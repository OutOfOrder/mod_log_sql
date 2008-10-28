#include "logparse.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "time.h"
#include "stdlib.h"

#include "util.h"
#include "ap_pcre.h"
#include "database.h"

apr_hash_t *g_parser_funcs;
void **g_parser_linedata;

static apr_status_t parser_func_wrap(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, const char **ret)
{
    if (field->args[0] && field->args[1]) {
        struct iovec vec[3];
        apr_size_t len;

        vec[0].iov_base = (void *)field->args[0];
        vec[0].iov_len = strlen(field->args[0]);
        vec[1].iov_base = (void *)value;
        vec[1].iov_len = strlen(value);
        vec[2].iov_base = (void *)field->args[1];
        vec[2].iov_len = strlen(field->args[1]);

        *ret = apr_pstrcatv(p, vec, 3, &len);
    } else {
        logging_log(cfg, LOGLEVEL_NOISE, "wrap requires before and after strings");
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}

static apr_status_t parser_func_regexmatch(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, const char **ret)
{
    struct {
        ap_regex_t *rx;
        const char *substr;
    }*_data;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    // Check if a regular expression configured
    if (!field->args[0])
        return APR_EINVAL;
    if (!field->data) {
        // pre compile the regex
        _data = apr_palloc(cfg->pool, sizeof(ap_regex_t)+sizeof(const char *));
        _data->rx = ap_pregcomp(cfg->pool, field->args[0],
                AP_REG_EXTENDED|AP_REG_ICASE);
        if (field->args[1]) {
            _data->substr = field->args[1];
        } else {
            _data->substr = "$1";
        }
        if (!_data->rx) {
            logging_log(cfg, LOGLEVEL_NOISE, "Failed to compile regular expression");
            return APR_EINVAL;
        }
        field->data = _data;
    } else
        _data = field->data;

    if (!ap_regexec(_data->rx, value, AP_MAX_REG_MATCH, regm, 0)) {
        *ret = ap_pregsub(p, _data->substr, value, AP_MAX_REG_MATCH, regm);
    }
    logging_log(cfg, LOGLEVEL_DEBUG, "REGEX: matched %s against %s to %s", value,
            field->args[0], *ret);
    return APR_SUCCESS;
}

static apr_status_t parser_func_totimestamp(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, const char **ret)
{
    time_t time;
    struct tm ts;

    //memset(&ts,0,sizeof(struct tm));

    strptime(value, "%d/%b/%Y:%H:%M:%S %z", &ts);
    time = mktime(&ts);

    *ret = apr_itoa(p, time);
    return APR_SUCCESS;
}

static apr_status_t parser_func_machineid(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, const char **ret)
{
    if (cfg->machineid) {
        *ret = apr_pstrdup(p, cfg->machineid);
    }
    return APR_SUCCESS;
}

static apr_status_t parser_func_queryarg(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, const char **ret)
{
    apr_table_t *query = parser_get_linedata(field->func);

    if (!field->args[0]) {
        logging_log(cfg, LOGLEVEL_NOISE, "queryarg requires name of query arg");
        return APR_EINVAL;
    }

    if (!query) {
        char *query_beg;

        query = apr_table_make(p,3);

        query_beg = strchr(value, '?');
        // if we have a query string, rip it apart
        if (query_beg) {
            char *key;
            char *value;
            char *query_string;
            char *strtok_state;
            char *query_end = strrchr(++query_beg,' ');

            query_string = apr_pstrndup(p, query_beg, query_end-query_beg);
            logging_log(cfg, LOGLEVEL_DEBUG, "QUERY: Found String %pp, %pp, %s",
                    query_beg, query_end, query_string);

            key = apr_strtok(query_string, "&", &strtok_state);
            while (key) {
                value = strchr(key, '=');
                if (value) {
                    *value = '\0';      /* Split the string in two */
                    value++;            /* Skip past the = */
                }
                else {
                    value = "1";
                }
                ap_unescape_url(key);
                ap_unescape_url(value);
                apr_table_set(query, key, value);

                logging_log(cfg, LOGLEVEL_DEBUG,
                    "QUERY: Found arg: %s = %s", key, value);

                key = apr_strtok(NULL, "&", &strtok_state);
            }
        }
        parser_set_linedata(field->func,query);
    }
    *ret = apr_table_get(query, field->args[0]);
    return APR_SUCCESS;
}

parser_func_t *parser_get_func(const char *name)
{
    return apr_hash_get(g_parser_funcs, name, APR_HASH_KEY_STRING);
}

static void parser_add_func(apr_pool_t *p, const char *const name,
        parser_func_f func, int id)
{
    parser_func_t *s;
    if (!g_parser_funcs) {
        g_parser_funcs = apr_hash_make(p);
    }
    s = apr_palloc(p, sizeof(parser_func_t));
    s->func = func;
    s->pos = id;
    s->data = NULL;
    s->linedata = &g_parser_linedata;
    apr_hash_set(g_parser_funcs, lowerstr(p, name), APR_HASH_KEY_STRING, s);
}

void parser_init(apr_pool_t *p)
{
    int i = 0;
    parser_add_func(p, "regexmatch", parser_func_regexmatch, ++i);
    parser_add_func(p, "totimestamp", parser_func_totimestamp, ++i);
    parser_add_func(p, "machineid", parser_func_machineid, ++i);
    parser_add_func(p, "queryarg", parser_func_queryarg, ++i);
    parser_add_func(p, "wrap", parser_func_wrap, ++i);
    g_parser_linedata = apr_pcalloc(p, sizeof(void *) * (i+1));
    g_parser_linedata[0] = (void *)i;
}

void parser_find_logs(config_t *cfg)
{
    apr_pool_t *tp;
    apr_dir_t *dir;
    apr_finfo_t finfo;
    config_filestat_t *newp;

    logging_log(cfg, LOGLEVEL_NOTICE, "Find Log files");
    if (!cfg->input_dir)
        return;
    apr_pool_create(&tp, cfg->pool);
    if (apr_dir_open(&dir, cfg->input_dir, tp)==APR_SUCCESS) {
        while (apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE, dir)
                == APR_SUCCESS) {
            if (finfo.filetype == APR_DIR)
                continue;
            newp = (config_filestat_t *)apr_array_push(cfg->input_files);
            newp->result = "Not Parsed";
            apr_filepath_merge(&(newp->fname), cfg->input_dir, finfo.name,
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

apr_status_t parser_parsefile(config_t *cfg, config_filestat_t *fstat)
{
    apr_pool_t *tp, *targp;
    apr_file_t *file;
    apr_status_t rv;
    char buff[2048];
    char **targv;
    int targc;

    apr_pool_create(&tp, cfg->pool);
    apr_pool_create(&targp, tp);

    logging_log(cfg, LOGLEVEL_NOTICE, "PARSER: Begin Parsing Log File '%s'", fstat->fname);

    rv = apr_file_open(&file, fstat->fname, APR_FOPEN_READ | APR_BUFFERED,
    APR_OS_DEFAULT, tp);
    if (rv != APR_SUCCESS) {
        logging_log(cfg, LOGLEVEL_NOISE, "PARSER: Could not open %s", fstat->fname);
        return rv;
    }

    fstat->linesparsed = 0;
    // Start Transaction
    fstat->start = apr_time_now();
    if (!cfg->dryrun && database_trans_start(cfg,tp)) {
        fstat->result = "Database Transaction Error";
        fstat->stop = apr_time_now();
        return rv;
    }

    do {
        rv = apr_file_gets(buff, 1024, file);
        if (rv == APR_SUCCESS) {
            int i,m, cont = 0;
            config_filter_t *filters;

            fstat->linesparsed++;
            // chomp off newline
            line_chomp(buff);
            // Run line filters
            for (i=0, m=cfg->linefilters->nelts,
                    filters = (config_filter_t *)cfg->linefilters->elts;
                    i<m; i++) {
                if (!filters[i].regex || ap_regexec(filters[i].regex, buff, 0, NULL,0)==0) {
                    if (filters[i].negative) {
                        logging_log(cfg, LOGLEVEL_DEBUG,
                                "PARSER: LINEFILTER: Skipping Line %d due to Filter (%d)%s",
                                fstat->linesparsed, i, filters[i].filter);
                        fstat->lineskipped++;
                        cont = 1;
                    } else {
                        logging_log(cfg, LOGLEVEL_DEBUG,
                                "PARSER: LINEFILTER: Force Parsing Line %d due to Filter (%d)%s",
                                fstat->linesparsed, i, filters[i].filter);
                    }
                    break;
                }
            }
            if (cont) continue;

            apr_pool_clear(targp);
            tokenize_logline(buff, &targv, targp, 0);
            targc = 0;
            while (targv[targc])
                targc++;
            rv = parser_processline(targp, cfg, fstat, targv, targc);
            if (rv != APR_SUCCESS) {
                int i;
                if (!cfg->dryrun) database_trans_abort(cfg);
                logging_log(cfg, LOGLEVEL_ERROR, "Line %d(%d): %s", fstat->linesparsed,
                        targc, buff);
                for (i = 0; targv[i]; i++) {
                    logging_log(cfg, LOGLEVEL_ERROR, "Arg (%d): '%s'", i,
                            targv[i]);
                }
            }
        } else {
            rv = APR_SUCCESS;
            break;
        }
    } while (rv == APR_SUCCESS);
    apr_file_close(file);
    // Finish Transaction
    if (!cfg->dryrun && database_trans_stop(cfg,tp)) {
        fstat->result = apr_psprintf(cfg->pool,
                "Input line %d, Database Transaction Error",
                fstat->linesparsed);
    }

    apr_pool_destroy(tp);
    logging_log(cfg, LOGLEVEL_NOTICE,
            "PARSER: Finish Parsing Log File '%s'. Lines: (%d/%d)",
            fstat->fname, fstat->linesparsed - fstat->lineskipped, fstat->linesparsed);
    if (!rv) {
        fstat->result = "File Parsed Succesfully";
    }
    fstat->stop = apr_time_now();
    return rv;
}

apr_status_t parser_processline(apr_pool_t *ptemp, config_t *cfg,
        config_filestat_t *fstat, char **argv, int argc)
{
    config_logformat_t *fmt;
    config_logformat_field_t *ifields;
    config_output_field_t *ofields;
    config_filter_t *filters;
    apr_table_t *datain;
    apr_table_t *dataout;
    apr_status_t rv= APR_SUCCESS;
    int i,m;

    fmt = apr_hash_get(cfg->log_formats, cfg->logformat, APR_HASH_KEY_STRING);
    if (!fmt) {
        logging_log(cfg, LOGLEVEL_NOISE, "PARSER: No Input Log format");
        return APR_EINVAL;
    }
    if (fmt->fields->nelts != argc) {
        logging_log(cfg, LOGLEVEL_NOISE,
                "PARSER: Input line field number differs from expected. Expected %d got %d.",
                fmt->fields->nelts, argc);
        fstat->result = apr_psprintf(cfg->pool,
                "Input line %d is badly formatted (wrong number of fields)",
                fstat->linesparsed);
        return APR_EINVAL;
    }

    datain = apr_table_make(ptemp, fmt->fields->nelts);
    dataout = apr_table_make(ptemp, cfg->output_fields->nelts);

    ifields = (config_logformat_field_t *)fmt->fields->elts;
    for (i=0; i<fmt->fields->nelts; i++) {
        apr_table_setn(datain, ifields[i].name, argv[i]);
    }
    // Run Pre Filters
    for (i=0, m=cfg->prefilters->nelts,
            filters = (config_filter_t *)cfg->prefilters->elts;
            i<m; i++) {
        const char *temp = apr_table_get(datain, filters[i].field);
        if (temp && (!filters[i].regex || ap_regexec(filters[i].regex, temp, 0, NULL,0)==0)) {
            if (filters[i].negative) {
                logging_log(cfg, LOGLEVEL_DEBUG,
                        "PARSER: PREFILTER: Skipping Line %d due to Filter (%d)%s",
                        fstat->linesparsed, i, filters[i].filter);
                fstat->lineskipped++;
                return APR_SUCCESS;
            } else {
                logging_log(cfg, LOGLEVEL_DEBUG,
                        "PARSER: PREFILTER: Force Parsing Line %d due to Filter (%d)%s",
                        fstat->linesparsed, i, filters[i].filter);
            }
            break;
        }
    }

    ofields = (config_output_field_t *)cfg->output_fields->elts;
    // clear out ofield function per-line data
    memset(&g_parser_linedata[1],0,sizeof(void *)*(int)g_parser_linedata[0]);
    // Convert input fields to output fields
    for (i=0,m=cfg->output_fields->nelts; i<m; i++) {
        const char *val;
        val = apr_table_get(datain, ofields[i].source);
        // If we can't find the source field just continue
        if (!val && !(ofields[i].source[0]=='\0' && ofields[i].func)) {
            apr_table_setn(dataout, ofields[i].field, ofields[i].def);
            continue;
        }
        if (!ofields[i].func) {
            apr_table_setn(dataout, ofields[i].field, val);
        } else {
            const char *ret= NULL;
            rv = ((parser_func_t *)ofields[i].func)->func(ptemp, cfg,
                    &ofields[i], val, &ret);
            if (rv) {
                fstat->result = apr_psprintf(cfg->pool,
                        "Input line %d, Parser function %s returned error (%d)%s",
                        fstat->linesparsed, ofields[i].fname, rv, logging_strerror(rv));
                return rv;
            }
            apr_table_setn(dataout, ofields[i].field, ret ? ret : ofields[i].def);
        }
    }

    // Run Post filters
    for (i=0, m=cfg->postfilters->nelts,
            filters = (config_filter_t *)cfg->postfilters->elts;
            i<m; i++) {
        const char *temp = apr_table_get(dataout, filters[i].field);
        if (temp && (!filters[i].regex || ap_regexec(filters[i].regex, temp, 0, NULL,0)==0)) {
            if (filters[i].negative) {
                logging_log(cfg, LOGLEVEL_DEBUG,
                        "PARSER: POSTFILTER: Skipping Line %d due to Filter (%d)%s",
                        fstat->linesparsed, i, filters[i].filter);
                fstat->lineskipped++;
                return APR_SUCCESS;
            } else {
                logging_log(cfg, LOGLEVEL_DEBUG,
                        "PARSER: POSTFILTER: Force Parsing Line %d due to Filter (%d)%s",
                        fstat->linesparsed, i, filters[i].filter);
            }
            break;
        }
    }

    // Process DB Query
    if (!cfg->dryrun) {
        rv = database_insert(cfg, ptemp, dataout);
        if (rv) {
            fstat->result = apr_psprintf(cfg->pool,
                    "Input line %d, Database Error",
                    fstat->linesparsed);
        }
    }
    return rv;
}
