#include "logparse.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_strings.h"

#include "util.h"

apr_hash_t *g_parser_funcs;

static apr_status_t parser_func_regexmatch(config_t *cfg, const char *data,
        int argc, const char **argv)
{
    return APR_SUCCESS;
}
parser_func_t parser_get_func(const char *name)
{
    return apr_hash_get(g_parser_funcs, name, APR_HASH_KEY_STRING);
}

static void parser_add_func(apr_pool_t *p, const char *const name,
           parser_func_t func)
{
    if (!g_parser_funcs) {
        g_parser_funcs = apr_hash_make(p);
    }
    apr_hash_set(g_parser_funcs, lowerstr(p, name), APR_HASH_KEY_STRING, func);
}

void parser_init(apr_pool_t *p)
{
    parser_add_func(p, "regexmatch", parser_func_regexmatch);
}

void parser_find_logs(config_t *cfg)
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
static apr_status_t tokenize_logline(const char *arg_str, char ***argv_out,
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
    apr_pool_t *tp, *targp;
    apr_file_t *file;
    apr_status_t rv;
    char buff[2048];
    char **targv;
    int targc;
    int line;

    apr_pool_create(&tp, cfg->pool);
    apr_pool_create(&targp, tp);

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
            // chomp off newline
            line_chomp(buff);

            apr_pool_clear(targp);
            tokenize_logline(buff, &targv, targp, 1);
            targc = 0;
            while (targv[targc]) targc++;
            /** @todo Run Line Filters here */
            rv = parse_processline(targp, cfg, targv, targc);
            if (rv != APR_SUCCESS) {
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

apr_status_t parse_processline(apr_pool_t *ptemp, config_t *cfg, char **argv, int argc)
{
    config_logformat_t *fmt;
    config_logformat_field_t *ifields;
    config_output_field_t *ofields;
    apr_table_t *datain;
    apr_table_t *dataout;
    int i;

    fmt = apr_hash_get(cfg->log_formats, cfg->logformat, APR_HASH_KEY_STRING);
    if (!fmt) return APR_EINVAL;
    if (fmt->fields->nelts != argc) return APR_EINVAL;

    datain = apr_table_make(ptemp, fmt->fields->nelts);
    dataout = apr_table_make(ptemp, cfg->output_fields->nelts);

    ifields = (config_logformat_field_t *)fmt->fields->elts;
    for (i=0; i<fmt->fields->nelts; i++) {
        apr_table_setn(datain,ifields[i].name,argv[i]);
    }
    /** @todo Run Pre Filters here */

    // Convert input fields to output fields
    ofields = (config_output_field_t *)cfg->output_fields->elts;
    for (i=0; i<cfg->output_fields->nelts; i++) {
        const char *t;
        if (!ofields[i].func) {
            t = apr_table_get(datain, ofields[i].source);
            if (!t) {
                return APR_EINVAL;
            }
            apr_table_setn(dataout,ofields[i].field, t);
            printf("S: %s = %s\n",ofields[i].source, t);
        } else {
            printf("S: %s, F: %p\n",ofields[i].source, ofields[i].func);
        }
    }

    /** @todo Run Post Filters here */

    return APR_SUCCESS;
}
