#include "apr.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_uri.h"

#include "shell.h"
#include "config.h"
#include "util.h"
#include "logparse.h"

apr_hash_t *g_config_opts;

static apr_status_t config_set_string(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    int offset = (int)(long)opt->data;
    char **data = (char **)((void *)cfg + offset);
    if (argc != 2)
        return APR_EINVAL;
    *data = apr_pstrdup(cfg->pool, argv[1]);
    return APR_SUCCESS;
}

static apr_status_t config_set_int(config_t *cfg, config_opt_t *opt, int argc,
        const char **argv) __attribute__ ((__unused__));
static apr_status_t config_set_int(config_t *cfg, config_opt_t *opt, int argc,
        const char **argv)
{
    int offset = (int)(long)opt->data;
    int *data = (int *)((void *)cfg + offset);
    if (argc != 2)
        return APR_EINVAL;
    *data = apr_atoi64(argv[1]);
    return APR_SUCCESS;
}

static apr_status_t config_set_flag(config_t *cfg, config_opt_t *opt, int argc,
        const char **argv)
{
    int offset = (int)(long)opt->data;
    int *data = (int *)((void *)cfg + offset);
    if (argc != 2)
        return APR_EINVAL;
    *data = CHECK_YESNO(argv[1]);
    return APR_SUCCESS;
}

static apr_status_t config_set_loglevel(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    if (argc != 2)
        return APR_EINVAL;
    if (!strcasecmp(argv[1], "error")) {
        cfg->loglevel = LOGLEVEL_ERROR;
    } else if (!strcasecmp(argv[1], "warn")) {
        cfg->loglevel = LOGLEVEL_WARN;
    } else if (!strcasecmp(argv[1], "debug")) {
        cfg->loglevel = LOGLEVEL_DEBUG;
    } else if (!strcasecmp(argv[1], "quiet")) {
        cfg->loglevel = LOGLEVEL_QUIET;
    } else {
        cfg->loglevel = LOGLEVEL_ERROR;
    }
    return APR_SUCCESS;
}

static apr_status_t config_set_inputfile(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    char **newp;
    if (argc != 2)
        return APR_EINVAL;
    newp = (char **)apr_array_push(cfg->input_files);
    *newp = apr_pstrdup(cfg->pool, argv[1]);
    return APR_SUCCESS;
}

static apr_status_t config_set_dummy(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    return APR_SUCCESS;
}

static apr_status_t config_set_logformat(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    config_logformat_t *format;
    config_logformat_field_t *field;

    if (argc != 4)
        return APR_EINVAL;

    format = apr_hash_get(cfg->log_formats, argv[1], APR_HASH_KEY_STRING);
    if (!format) {
        format = apr_palloc(cfg->pool, sizeof(config_logformat_t));
        format->name = apr_pstrdup(cfg->pool, argv[1]);
        format->fields = apr_array_make(cfg->pool, 5,
                sizeof(config_logformat_field_t));
        apr_hash_set(cfg->log_formats, apr_pstrdup(cfg->pool,argv[1]), APR_HASH_KEY_STRING, format);
    }
    field = (config_logformat_field_t *)apr_array_push(format->fields);
    field->name = apr_pstrdup(cfg->pool, argv[2]);
    field->datatype = apr_pstrdup(cfg->pool, argv[3]);
    return APR_SUCCESS;
}

static apr_status_t config_set_output_field(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    config_output_field_t *field;
    char *type, *size, *temp;

    if (argc < 5)
        return APR_EINVAL;
    field = (config_output_field_t *)apr_array_push(cfg->output_fields);
    field->field = apr_pstrdup(cfg->pool, argv[1]);
    field->source = apr_pstrdup(cfg->pool, argv[4]);
    field->def = apr_pstrdup(cfg->pool, argv[3]);
    type = size = apr_pstrdup(cfg->pool, argv[2]);
    while (*size!='\0' && *size!='(')
        size++;
    if (*size == '(') {
        *size = '\0';
        size++;
        temp = size;
        while (*temp != '\0' && *temp != ')')
            temp++;
        *temp = '\0';
        field->size = apr_atoi64(size);
    }
    if (strcasecmp("VARCHAR", type)==0) {
        field->datatype = LOGSQL_DATATYPE_VARCHAR;
    } else if (strcasecmp("INT", type)==0) {
        field->datatype = LOGSQL_DATATYPE_INT;
    } else if (strcasecmp("CHAR", type)==0) {
        field->datatype = LOGSQL_DATATYPE_CHAR;
    } else if (strcasecmp("SMALLINT", type)==0) {
        field->datatype = LOGSQL_DATATYPE_SMALLINT;
    } else if (strcasecmp("BIGINT", type)==0) {
        field->datatype = LOGSQL_DATATYPE_BIGINT;
    } else {
        return APR_EINVAL;
    }

    // Has a function
    if (argc > 5) {
        int i;
        field->fname = apr_pstrdup(cfg->pool, argv[5]);
        field->func = parser_get_func(field->fname);
        field->args = apr_pcalloc(cfg->pool, sizeof(char *) * (argc-5+1));
        for (i=6; i<=argc; i++) {
            field->args[i-6] = apr_pstrdup(cfg->pool, argv[i]);
        }
    }

    return APR_SUCCESS;
}

static apr_status_t config_set_filter(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv)
{
    int argn = 1;
    config_filter_t *filter;
    filter = apr_pcalloc(cfg->pool, sizeof(config_filter_t));

    if (opt->name[0]!='L') { // Pre or post 2-3 args
        if (argc == 1)
            return APR_EINVAL;
        filter->field = apr_pstrdup(cfg->pool, argv[1]);
        argn++;
    } // Otherwise Line based only 1-2 args (no field)
    if (argc <= argn)
        return APR_EINVAL;
    if (argv[argn][0] == '+')
        argn++;
    if (argv[argn][0] == '-') {
        filter->negative = 1;
        argn++;
    }
    if (argc <= argn)
        return APR_EINVAL;
    filter->filter = apr_pstrdup(cfg->pool, argv[argn]);
    filter->regex = ap_pregcomp(cfg->pool, filter->filter, AP_REG_ICASE);
    return APR_SUCCESS;
}

void config_dump(config_t *cfg)
{
    apr_hash_index_t *hi;
    int i;
    config_output_field_t *fields;

    printf("ErrorLog: %s\n", cfg->errorlog);
    printf("LogLevel: %d\n", cfg->loglevel);

    printf("InputDir: %s\n", cfg->input_dir);

    printf("DB Driver: %s\n", cfg->dbdriver);
    printf("DB Params: %s\n", cfg->dbparams);

    printf("Table: %s\n", cfg->table);
    printf("Transactions: %d\n", cfg->transactions);
    printf("MachineID: %s\n", cfg->machineid);

    printf("Log formats:\n");
    for (hi = apr_hash_first(cfg->pool, cfg->log_formats); hi; hi
            = apr_hash_next(hi)) {
        config_logformat_t *format;
        config_logformat_field_t *fields;
        int i;

        apr_hash_this(hi, NULL, NULL, (void **)&format);
        printf(">> '%s'\n", format->name);
        fields = (config_logformat_field_t *)format->fields->elts;
        for (i=0; i<format->fields->nelts; i++) {
            printf(">>>> %s:%s\n", fields[i].name, fields[i].datatype);
        }
    }
    printf("Log Format: '%s'\n", cfg->logformat);

    printf("Output Fields:\n");
    fields = (config_output_field_t *)cfg->output_fields->elts;
    for (i=0; i<cfg->output_fields->nelts; i++) {
        printf(">> %s %s(%d) DEFAULT '%s': %s", fields[i].field,
                logsql_field_datatyeName(fields[i].datatype),
                fields[i].size, fields[i].def, fields[i].source);
        if (fields[i].func) {
            printf(" :: %s(", fields[i].fname);
            if (fields[i].args) {
                int a = 0;
                while (fields[i].args[a]) {
                    printf("%s,", fields[i].args[a]);
                    a++;
                }
            }
            printf(")");
        }
        printf("\n");
    }

    printf("DryRun: %d\n", cfg->dryrun);
    printf("Summary: %d\n", cfg->summary);
}

#define config_get_option(name) apr_hash_get(g_config_opts, name, APR_HASH_KEY_STRING)

static void config_add_option(apr_pool_t *p, const char *const name,
        const char *const help, config_func_t func, void *data)
{
    config_opt_t *opt;
    if (!g_config_opts) {
        g_config_opts = apr_hash_make(p);
    }
    opt = apr_palloc(p, sizeof(config_opt_t));
    opt->name = name;
    opt->help = help;
    opt->func = func;
    opt->data = data;
    apr_hash_set(g_config_opts, lowerstr(p, name), APR_HASH_KEY_STRING, opt);
}

void config_init(apr_pool_t *p)
{
    config_add_option(p, "ErrorLog", "File to log errors", config_set_string,
            (void *)APR_OFFSETOF(config_t, errorlog));
    config_add_option(p, "LogLevel",
            "Set Log Level (error, warn, debug, quiet)", config_set_loglevel,
            NULL);

    config_add_option(p, "InputDirectory", "Directory to scan for log files",
            config_set_string, (void *)APR_OFFSETOF(config_t, input_dir));
    config_add_option(p, "InputFile", "Parse only this file",
            config_set_inputfile, NULL);

    config_add_option(p, "DBDDriver", "DBD Driver to use",
            config_set_string, (void *)APR_OFFSETOF(config_t, dbdriver));
    config_add_option(p, "DBDParams", "DBD Connection Parameters",
            config_set_string, (void *)APR_OFFSETOF(config_t, dbparams));
    config_add_option(p, "Table", "Table to import the log to",
            config_set_string, (void *)APR_OFFSETOF(config_t, table));
    config_add_option(p, "UseTransactions", "Enable Transactions?",
            config_set_flag, (void *)APR_OFFSETOF(config_t, transactions));
    config_add_option(p, "MachineID", "Machine ID to set", config_set_string,
            (void *)APR_OFFSETOF(config_t, machineid));

    config_add_option(p, "LogFormatConfig", "Define input log formats",
            config_set_logformat, NULL);
    config_add_option(p, "LogFormat", "Use this logformat when parsing files",
            config_set_string, (void *)APR_OFFSETOF(config_t, logformat));

    config_add_option(p, "LineFilter",
            "A regular expression to apply to the input line",
            config_set_filter, (void *)APR_OFFSETOF(config_t, linefilters));
    config_add_option(p, "PreFilter",
            "A regular expression to apply to a specific input field",
            config_set_filter, (void *)APR_OFFSETOF(config_t, prefilters));
    config_add_option(p, "PostFilter",
            "A regular expression to apply to a specific SQL output field",
            config_set_filter, (void *)APR_OFFSETOF(config_t, postfilters));

    config_add_option(p, "OutputField",
            "Define output fields: field datatype source optfunc optarg...",
            config_set_output_field, NULL);

    config_add_option(p, "DryRun", "Don't perform any actual database changes",
            config_set_flag, (void *)APR_OFFSETOF(config_t, dryrun));
    config_add_option(p, "Config", "Dummy to handle config directive",
            config_set_dummy, NULL);
    config_add_option(p, "Summary", "Show the summary before exit?",
            config_set_flag, (void *)APR_OFFSETOF(config_t, summary));
}

config_t *config_create(apr_pool_t *p)
{
    config_t *cfg;
    apr_pool_t *sp;
    apr_pool_create(&sp, p);
    cfg = apr_pcalloc(sp, sizeof(config_t));
    cfg->pool = sp;
    cfg->loglevel = LOGLEVEL_WARN;
    cfg->summary = 1;
    cfg->transactions = 1;
    cfg->input_files = apr_array_make(cfg->pool, 10, sizeof(char *));
    cfg->log_formats = apr_hash_make(cfg->pool);
    cfg->output_fields = apr_array_make(cfg->pool, 10,
            sizeof(config_output_field_t));
    return cfg;
}

static int config_merge(void *rec, const char *key, const char *value)
{
    config_t *cfg = (config_t *)rec;

    config_opt_t *opt= config_get_option(key);
    if (opt) {
        const char *args[] = {
            key,
            value };
        opt->func(cfg, opt, 2, args);
    } else {
        printf("Unhandled: %s\n", key);
    }
    return 1;
}

apr_status_t config_read(config_t *cfg, const char *filename,
        apr_table_t *merge)
{
    apr_finfo_t finfo;
    apr_file_t *file;
    apr_status_t rv, ret= APR_SUCCESS;
    apr_pool_t *tp, *targp;
    config_opt_t *opt;
    char buff[1024];
    char *ptr;
    char **targv;
    int targc;
    int line;

    apr_pool_create(&tp, cfg->pool);
    apr_pool_create(&targp, tp);

    if (apr_stat(&finfo, filename, APR_FINFO_MIN, tp) != APR_SUCCESS) {
        return APR_ENOENT;
    }
    rv = apr_file_open(&file, filename, APR_FOPEN_READ | APR_BUFFERED,
    APR_OS_DEFAULT, tp);
    if (rv != APR_SUCCESS)
        return rv;

    line = 0;
    do {
        rv = apr_file_gets(buff, 1024, file);
        if (rv == APR_SUCCESS) { // we read data
            line++;

            // skip leading white space
            for (ptr = buff; *ptr == ' ' || *ptr == '\t'; ptr++)
                ;
            line_chomp(ptr);

            // skip comments
            if (*ptr == '#')
                continue;
            if (*ptr == '\0')
                continue;
            apr_pool_clear(targp);
            apr_tokenize_to_argv(ptr, &targv, targp);
            targc = 0;
            while (targv[targc])
                targc++;
            opt = config_get_option(lowerstr(targp,targv[0]));
            if (opt) {
                rv = opt->func(cfg, opt, targc, (const char **)targv);
                if (APR_STATUS_IS_EINVAL(rv)) {
                    printf("Config Error: Invalid Arguments for %s\n\t%s\n",
                            opt->name, opt->help);
                    ret = rv;
                }
            } else {
                printf("Unhandled: %s\n", targv[0]);
            }
        }
    } while (rv == APR_SUCCESS);

    // Apply merges
    apr_table_do(config_merge, (void *)cfg, merge, NULL);

    apr_file_close(file);
    apr_pool_destroy(tp);
    return ret;
}
