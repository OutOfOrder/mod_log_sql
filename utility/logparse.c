#include "logparse.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_strings.h"

void find_log_files(config_t *cfg)
{
    apr_pool_t *tp;
    apr_dir_t *dir;
    apr_finfo_t finfo;
    char **newp;

    if (!cfg->input_dir)
        return;
    apr_pool_create(&tp, cfg->pool);
    if (apr_dir_open(&dir, cfg->input_dir, tp)==APR_SUCCESS) {
        while (apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE, dir)
                == APR_SUCCESS) {
            if (finfo.filetype == APR_DIR)
                continue;
            newp = (char **)apr_array_push(cfg->input_files);
            apr_filepath_merge(newp, cfg->input_dir, finfo.name,
                    APR_FILEPATH_TRUENAME, cfg->pool);
        }
        apr_dir_close(dir);
    }
    apr_pool_destroy(tp);
}

/*
 * Modified version of apr_tokenize_to_argv to add [] as quoting characters
 *
 *    token_context: Context from which pool allocations will occur.
 *    arg_str:       Input string for conversion to argv[].
 *    argv_out:      Output location. This is a pointer to an array
 *                   of pointers to strings (ie. &(char *argv[]).
 *                   This value will be allocated from the contexts
 *                   pool and filled in with copies of the tokens
 *                   found during parsing of the arg_str.
 *    keepquotes:    Keep the quotes instead of stripping them
 */
apr_status_t tokenize_logline(const char *arg_str, char ***argv_out,
        apr_pool_t *token_context, int keepquotes)
{
    const char *cp;
    const char *ct;
    char *cleaned, *dirty;
    int escaped;
    int isquoted, numargs = 0, argnum;

#define SKIP_WHITESPACE(cp) \
    for ( ; *cp == ' ' || *cp == '\t'; ) { \
        cp++; \
    };

#define CHECK_QUOTATION(cp,isquoted) \
    isquoted = 0; \
    if (*cp == '"') { \
        isquoted = 1; \
        cp++; \
    } \
    else if (*cp == '\'') { \
        isquoted = 2; \
        cp++; \
    } \
    else if (*cp == '[') { \
        isquoted = 3; \
        cp++; \
    }

    /* DETERMINE_NEXTSTRING:
     * At exit, cp will point to one of the following:  NULL, SPACE, TAB or QUOTE.
     * NULL implies the argument string has been fully traversed.
     */
#define DETERMINE_NEXTSTRING(cp,isquoted) \
    for ( ; *cp != '\0'; cp++) { \
        if (   (isquoted    && (*cp     == ' ' || *cp     == '\t')) \
            || (*cp == '\\' && (*(cp+1) == ' ' || *(cp+1) == '\t' || \
                                *(cp+1) == '"' || *(cp+1) == '\'' || \
                                *(cp+1) == '[' || *(cp+1) == ']'))) { \
            cp++; \
            continue; \
        } \
        if (   (!isquoted && (*cp == ' ' || *cp == '\t')) \
            || (isquoted == 1 && *cp == '"') \
            || (isquoted == 2 && *cp == '\'') \
            || (isquoted == 3 && *cp == ']') \
            ) { \
            break; \
        } \
    }

    /* REMOVE_ESCAPE_CHARS:
     * Compresses the arg string to remove all of the '\' escape chars.
     * The final argv strings should not have any extra escape chars in it.
     */
#define REMOVE_ESCAPE_CHARS(cleaned, dirty, escaped) \
    escaped = 0; \
    while(*dirty) { \
        if (!escaped && *dirty == '\\') { \
            escaped = 1; \
        } \
        else { \
            escaped = 0; \
            *cleaned++ = *dirty; \
        } \
        ++dirty; \
    } \
    *cleaned = 0;        /* last line of macro... */

    cp = arg_str;
    SKIP_WHITESPACE(cp);
    ct = cp;

    /* This is ugly and expensive, but if anyone wants to figure a
     * way to support any number of args without counting and
     * allocating, please go ahead and change the code.
     *
     * Must account for the trailing NULL arg.
     */
    numargs = 1;
    while (*ct != '\0') {
        CHECK_QUOTATION(ct, isquoted)
        ;
        DETERMINE_NEXTSTRING(ct, isquoted);
        if (*ct != '\0') {
            ct++;
        }
        numargs++;
        SKIP_WHITESPACE(ct);
    }
    *argv_out = apr_palloc(token_context, numargs * sizeof(char*));

    /*  determine first argument */
    for (argnum = 0; argnum < (numargs-1); argnum++) {
        SKIP_WHITESPACE(cp);
        CHECK_QUOTATION(cp, isquoted)
        ;
        ct = cp;
        DETERMINE_NEXTSTRING(cp, isquoted);
        cp++;
        if (isquoted && keepquotes) {
            (*argv_out)[argnum] = apr_palloc(token_context, cp - ct + 2);
            apr_cpystrn((*argv_out)[argnum], ct -1, cp - ct + 2);
        } else {
            (*argv_out)[argnum] = apr_palloc(token_context, cp - ct);
            apr_cpystrn((*argv_out)[argnum], ct, cp - ct);
        }
        cleaned = dirty = (*argv_out)[argnum];
        REMOVE_ESCAPE_CHARS(cleaned, dirty, escaped)
        ;
    }
    (*argv_out)[argnum] = NULL;

    return APR_SUCCESS;
}

apr_status_t parse_logfile(config_t *cfg, const char *filename)
{
    apr_pool_t *tp, *argp;
    apr_file_t *file;
    apr_status_t rv;
    char buff[2048];
    char **targv;
    int targc;
    int line;

    apr_pool_create(&tp, cfg->pool);
    apr_pool_create(&argp, tp);

    rv = apr_file_open(&file, filename, APR_FOPEN_READ | APR_BUFFERED,
            APR_OS_DEFAULT, tp);
    if (rv != APR_SUCCESS) {
        printf("Could not open %s\n", filename);
        return rv;
    }

    line = 0;
    do {
        rv = apr_file_gets(buff, 1024, file);
        if (rv == APR_SUCCESS) {
            line++;
            char *ptr;
            // chomp off newline
            for (ptr = buff + strlen(buff); *ptr != '\r' && *ptr != '\n'; ptr--)
                ;
            *ptr = '\0';
            apr_pool_clear(argp);
            tokenize_logline(buff, &targv, argp, 1);
            targc = 0;
            while (targv[targc]) targc++;
            if (targc != 9) {
                int i;
                printf("Line %d(%d): %s\n",line, targc, buff);
                for (i = 0; targv[i]; i++) {
                    printf("Arg (%d): '%s'\n", i, targv[i]);
                }
            }
        }
    } while (rv == APR_SUCCESS);
    printf("Total Lines: %d\n", line);
    apr_file_close(file);
    apr_pool_destroy(tp);
    return APR_SUCCESS;
}
