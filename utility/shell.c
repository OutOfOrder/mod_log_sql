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

#if APR_HAS_THREADS
#include "apr_queue.h"
#include "apr_thread_pool.h"

static apr_queue_t *queue;

void run_multithreaded(config_t *cfg);
#endif

void run_singlethreaded(config_t *cfg);

const apr_getopt_option_t _opt_config[]   = {
    {"machineid",   'm',    1,  "Machine ID for the log file"},
    {"transaction", 't',    1,  "Use a Transaction (yes,no)"},
    {"logformat",   'r',    1,  "Use this logformat to parse files"},
    {"file",        'f',    1,  "Parse this single log file (input dir is NOT scanned)"},
    {"inputdir",    'i',    1,  "Input Directory to look for log files"},
    {"config",      'c',    1,  "Configuration file to use (default mod_log_sql.conf)"},
    {"dryrun",      'n',    0,  "Perform a dry run (do not actually alter the databse)"},
    {"dump",        'd',    0,  "Dump the configuration after parsing and quit"},
    {"loglevel",    'l',    1,  "Log Level (deubg, notice, error)"},
    {"summary",     's',    1,  "Summary (yes,no)"},
    {"threadcount", 'p',    1,  "Set thread count (a number greater than 0)"},
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

void print_summary(config_t *cfg) {
    config_filestat_t *fstat;
    int i,m;
    apr_time_t totaltime = 0;
    apr_size_t totalparsed = 0, totalskipped = 0, totalbad = 0;

    fstat = (config_filestat_t *)cfg->input_files->elts;

    printf("Execution Summary\nParsed %d files\n", cfg->input_files->nelts);
    for (i=0, m=cfg->input_files->nelts; i<m; i++) {
        totaltime += fstat[i].stop - fstat[i].start;
        totalparsed += fstat[i].linesparsed;
        totalskipped += fstat[i].lineskipped;
        totalbad += fstat[i].linesbad;
        printf(" File: %s\n"
                "  Lines Added %'d out of %'d (Skipped %'d, Bad %'d)\n"
                "  Status: %s\n"
                "  Duration: %02"APR_TIME_T_FMT":%02"APR_TIME_T_FMT".%"APR_TIME_T_FMT" (minutes, seconds, and miliseconds)\n"
                "\n",
               fstat[i].fname,
               fstat[i].linesparsed - fstat[i].lineskipped - fstat[i].linesbad,
               fstat[i].linesparsed,
               fstat[i].lineskipped,
               fstat[i].linesbad,
               fstat[i].result,
               apr_time_sec(fstat[i].stop - fstat[i].start)/60,
               apr_time_sec(fstat[i].stop - fstat[i].start) % 60,
               apr_time_msec(fstat[i].stop - fstat[i].start)
               );
    }
    printf("Totals\n"
            "  Lines Added %'d out of %'d (Skipped %'d, Bad %'d)\n"
            "  Duration: %02"APR_TIME_T_FMT":%02"APR_TIME_T_FMT".%"APR_TIME_T_FMT" (minutes, seconds, and miliseconds)\n"
            "\n",
            totalparsed - totalskipped - totalbad,
            totalparsed,
            totalskipped,
            totalbad,
            apr_time_sec(totaltime)/60,
            apr_time_sec(totaltime) % 60,
            apr_time_msec(totaltime)
            );
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
        case 'p':
            apr_table_setn(args,"threadcount",opt_arg);
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
    // initialize STD out error log
    logging_preinit(cfg);
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

    // Only Find files IF no filename was passed via the command line
    if (apr_is_empty_array(cfg->input_files)) {
        parser_find_logs(cfg);
    }
    if (!apr_is_empty_array(cfg->input_files)) {
        parser_split_logs(cfg);
#if APR_HAS_THREADS
        if (cfg->thread_count > 0) {
            run_multithreaded(cfg);
        } else {
#endif
           run_singlethreaded(cfg);
#if APR_HAS_THREADS
        }
#endif
    } else {
        logging_log(cfg,LOGLEVEL_NOISE,"No log files found to parse");
    }

    if (cfg->summary) {
        print_summary(cfg);
    }
    return 0;
}

void run_singlethreaded(config_t *cfg)
{
    config_filestat_t *filelist;
    config_dbd_t *dbconn = NULL;
    int f, l;
    apr_status_t rv;

    if (!cfg->dryrun) {
        if ((rv = database_connect(cfg, &dbconn))) {
            logging_log(cfg,LOGLEVEL_NOISE, "Error Connecting to Database");
            exit(1);
        }
    }

    filelist = (config_filestat_t *)cfg->input_files->elts;
    for (f=0, l=cfg->input_files->nelts; f < l; f++) {
        rv = parser_parsefile(cfg, dbconn, &filelist[f]);
        if (rv) {
            logging_log(cfg, LOGLEVEL_NOISE,
                    "Error occured parsing log files. Aborting");
            break;
        }
    }

    if (!cfg->dryrun) {
        database_disconnect(dbconn);
    }
}

#if APR_HAS_THREADS
void * APR_THREAD_FUNC run_filethread(apr_thread_t *thd, void *data)
{
    config_t *cfg = data;
    config_dbd_t *dbconn = NULL;
    config_filestat_t *fileentry;
    apr_status_t rv;

    if (!cfg->dryrun) {
        if ((rv = database_connect(cfg, &dbconn))) {
            logging_log(cfg,LOGLEVEL_NOISE, "Error Connecting to Database");
            return NULL;
        }
    }

    while (1) {
        rv = apr_queue_pop(queue, (void **)&fileentry);
        if (rv == APR_EINTR)
            continue;
        if (rv == APR_EOF)
            break;
        rv = parser_parsefile(cfg, dbconn, fileentry);
        if (rv) {
            logging_log(cfg, LOGLEVEL_NOISE,
                    "Error occured parsing log file %s", fileentry->fname);
        }
    }

    if (!cfg->dryrun) {
         database_disconnect(dbconn);
    }
    return NULL;
}

void run_multithreaded(config_t *cfg)
{
    logging_log(cfg, LOGLEVEL_NOISE, "Running Multithreaded");

    config_filestat_t *filelist;
    int f, l;
    apr_status_t rv;
    apr_pool_t *tp;
    apr_thread_pool_t *thrp;
    unsigned int count;

    apr_pool_create(&tp, cfg->pool);
    rv = apr_queue_create(&queue, cfg->input_files->nelts, tp);

    rv = apr_thread_pool_create(&thrp, 0, cfg->thread_count, tp);

    //populate queue
    filelist = (config_filestat_t *)cfg->input_files->elts;
    for (f=0, l=cfg->input_files->nelts; f < l; f++) {
        rv = apr_queue_push(queue, &filelist[f]);
    }
    // populate the worker threads
    for (f=0; f<cfg->thread_count; f++) {
        rv = apr_thread_pool_push(thrp, run_filethread, cfg, 0, NULL);
    }

    do {
        apr_sleep(apr_time_from_sec(1));
        count = apr_queue_size(queue);
    } while (count > 0);

    rv = apr_queue_term(queue);

    rv = apr_thread_pool_destroy(thrp);
}
#endif
