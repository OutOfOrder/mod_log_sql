#include "apr.h"
#include "apr_getopt.h"
#include "apr_tables.h"

#define APR_WANT_STDIO
#include "apr_want.h"
#include "stdlib.h"

#include "shell.h"
#include "config.h"
#include "logparse.h"
#include "database.h"
#include "util.h"

const apr_getopt_option_t _opt_config[]   = {
    {"machineid",   'm',    1,  "Machine ID for the log file"},
    {"transaction", 't',    1,  "Use a Transaction (yes,no)"},
    {"logformat",   'r',    1,  "Use this logformat to parse files"},
    {"file",        'f',    1,  "Parse this single log file (input dir is NOT scanned)"},
    {"inputdir",    'i',    1,  "Input Directory to look for log files"},
    {"config",      'c',    1,  "Configuration file to use (default mod_log_sql.conf)"},
    {"dryrun",      'n',    0,  "Perform a dry run (do not actually alter the databse)"},
    {"dump",        'd',    0,  "Dump the configuration after parsing and quit"},
    {"loglevel",    'l',    1,  "Log Level (deubg, warn, error)"},
    {"summary",     's',    1,  "Summary (yes,no)"},
    {"help",        'h',    0,  "Show Help"},
    {NULL}
};

void show_help(const char *prog, const apr_getopt_option_t *opts, FILE *output)
{
    int ptr = 0;
    fprintf(output, "Usage: %s [OPTIONS] [files...]\n\n", prog);
    while (opts[ptr].optch != 0) {
        if (opts[ptr].optch > 255) {
            if (opts[ptr].name) {
                fprintf(output, "    --%-10s", opts[ptr].name);
            } else {
                fprintf(output, "                ");
            }
        } else {
            if (opts[ptr].name) {
                fprintf(output, " -%c --%-10s", opts[ptr].optch, opts[ptr].name);
            } else {
                fprintf(output, " -%c             ", opts[ptr].optch);
            }
        }
        if (opts[ptr].has_arg) {
            fprintf(output, " (arg)");
        } else {
            fprintf(output, "      ");
        }
        fprintf(output, " %s\n", opts[ptr].description);
        ptr++;
    }
}

int main(int argc, const char *const argv[])
{
    apr_pool_t *pool, *ptemp;
    apr_getopt_t *opts;
    int opt;
    const char *opt_arg;
    apr_status_t rv;
    apr_table_t *args;
    config_t *cfg;

    apr_app_initialize(&argc, &argv, NULL);
    atexit(apr_terminate);

    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        fprintf(stderr, "Failed to create memory pool!\n");
        exit(1);
    }
    apr_pool_create(&ptemp, NULL);

    /** Iterate over command line arguments
     * shoving args in a apr_table for processing later*/
    args = apr_table_make(ptemp, 5);
    apr_table_setn(args, "config", "mod_log_sql.conf");
    apr_getopt_init(&opts, ptemp, argc, argv);
    while ((rv = apr_getopt_long(opts, _opt_config, &opt, &opt_arg)) == APR_SUCCESS) {
        switch (opt) {
        case 'c':
            apr_table_setn(args,"config",opt_arg);
            break;
        case 'd':
            apr_table_setn(args,"dump","yes");
            break;
        case 'f':
            apr_table_setn(args,"inputfile",opt_arg);
            break;
        case 'h':
            show_help(argv[0], _opt_config, stdout);
            exit(1);
            break;
        case 'i':
            apr_table_setn(args,"inputdirectory",opt_arg);
            break;
        case 'l':
            apr_table_setn(args,"loglevel",opt_arg);
            break;
        case 'm':
            apr_table_setn(args,"machineid",opt_arg);
            break;
        case 'n':
            apr_table_setn(args,"dryrun","yes");
            break;
        case 'r':
            apr_table_setn(args,"logformat",opt_arg);
            break;
        case 's':
            apr_table_setn(args,"summary",opt_arg);
            break;
        case 't':
            apr_table_setn(args,"usetransactions",opt_arg);
            break;
        }
    }
    if (rv != APR_EOF) {
        show_help(argv[0], _opt_config, stderr);
        exit(1);
    }
    // Check if no extra args were passed
    if (opts->ind != opts->argc) {
        show_help(argv[0], _opt_config, stderr);
        fprintf(stderr, "\n%s: Extra unknown arguments passed\n\n",argv[0]);
        exit(1);
    }

    // Initialize sub systems
    parser_init(pool);
    config_init(pool);
    database_init(pool);
    // Process configuration file
    cfg = config_create(pool);
    rv = config_read(cfg, apr_table_get(args,"Config"), args);
    apr_pool_destroy(ptemp);

    // Initialize Log system AFTER we parse the configuration
    logging_init(cfg);

    if (APR_STATUS_IS_ENOENT(rv)) {
        logging_log(cfg,LOGLEVEL_NOISE,"Could not load configuration file: %s",apr_table_get(args,"config"));
    } else if (rv) {
        exit(1);
    }
    if (cfg->dump) {
        config_dump(cfg);
        exit(0);
    }

    if (config_check(cfg)) {
        logging_log(cfg,LOGLEVEL_NOISE, "Please correct the configuration");
        exit(1);
    }

    // Find files and parse
    parser_find_logs(cfg);
    if (!cfg->dryrun) {
        if ((rv = database_connect(cfg))) {
            logging_log(cfg,LOGLEVEL_NOISE, "Error Connecting to Database");
            exit(1);
        }
    }
    if (!apr_is_empty_array(cfg->input_files)) {
        char **filelist;
        int f, l;
        filelist = (char **)cfg->input_files->elts;
        for (f=0, l=cfg->input_files->nelts; f < l; f++) {
            parse_logfile(cfg, filelist[f]);
        }
    } else {
        logging_log(cfg,LOGLEVEL_NOISE,"No log files found to parse");
    }
    if (!cfg->dryrun) {
        database_disconnect(cfg);
    }
    /** @todo summary goes here */
    return 0;
}
