#ifndef CONFIG_H_
#define CONFIG_H_

#include "apr_tables.h"
#include "apr_hash.h"
#include "apr_file_io.h"
#include "ap_pcre.h"

typedef enum {
    LOGLEVEL_NOISE = 0,
    LOGLEVEL_NONE,
    LOGLEVEL_ERROR,
    LOGLEVEL_NOTICE,
    LOGLEVEL_DEBUG,
} loglevel_e;

typedef struct config_dbd_t config_dbd_t;
typedef struct config_t config_t;
struct config_t {
    /** the structures pool (to ease function arguments) */
    apr_pool_t *pool;

    /** error log file */
    const char *errorlog;
    /** log level */
    loglevel_e loglevel;
    /** error_log */
    apr_file_t *errorlog_fp;
    apr_file_t *errorlog_fperr;
    apr_pool_t *errorlog_p;

    const char *badlinefile;
    const char *badlastfile;
    apr_file_t *badline_fp;
    int badline_count;
    int badlinemax;


    /** input directory of log files */
    const char *input_dir;
    /** list of files to scan */
    apr_array_header_t *input_files;

    /** db connection configuration */
    const char *dbdriver;
    const char *dbparams;
    config_dbd_t *dbconn;

    /** Logging table */
    const char *table;
    /** Use transactons */
    int transactions;
    /** Machine ID */
    const char *machineid;

    /** Log file formats */
    apr_hash_t *log_formats;
    /** format to use to parse files */
    const char *logformat;

    /** output fields */
    apr_array_header_t *output_fields;

    /** filter configuration */
    apr_array_header_t *linefilters;
    apr_array_header_t *prefilters;
    apr_array_header_t *postfilters;

    /** Dry Run */
    int dryrun;
    /** dump configuration only */
    int dump;

    /* Show the summary */
    int summary;
};

typedef struct config_filestat_t config_filestat_t;
struct config_filestat_t {
    char *fname;
    apr_size_t linesparsed;
    apr_size_t lineskipped;
    apr_size_t linesbad;
    const char *result;
    apr_time_t start;
    apr_time_t stop;
};

typedef struct config_logformat_t config_logformat_t;
struct config_logformat_t {
    const char *name;
    apr_array_header_t *fields;
};

typedef struct config_logformat_field_t config_logformat_field_t;
struct config_logformat_field_t {
    const char *name;
    const char *datatype;
};

typedef struct config_opt_t config_opt_t;
typedef apr_status_t (*config_func_t)(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv);
struct config_opt_t {
    const char *name;
    const char *help;
    config_func_t func;
    void *data;
};

typedef struct config_filter_t config_filter_t;
struct config_filter_t {
    const char *field;
    const char *filter;
    int negative;
    ap_regex_t *regex;
};

typedef enum {
    LOGSQL_DATATYPE_INT = 0,
    LOGSQL_DATATYPE_SMALLINT,
    LOGSQL_DATATYPE_VARCHAR,
    LOGSQL_DATATYPE_CHAR,
    LOGSQL_DATATYPE_BIGINT
} logsql_field_datatype;
#define logsql_field_datatyeName(x) \
        (x == LOGSQL_DATATYPE_INT ? "INT" \
        : (x == LOGSQL_DATATYPE_SMALLINT ? "SMALLINT" \
        : (x == LOGSQL_DATATYPE_VARCHAR ? "VARCHAR" \
        : (x == LOGSQL_DATATYPE_CHAR ? "CHAR" \
        : (x == LOGSQL_DATATYPE_BIGINT ? "BIGINT" : "ERR")))))

typedef struct config_output_field_t config_output_field_t;

typedef struct parser_func_t parser_func_t;

struct config_output_field_t {
    const char *field;
    logsql_field_datatype datatype;
    apr_size_t size;
    const char *def;
    const char *source;
    const char *fname;
    parser_func_t *func;
    const char **args;
    void *data;
};

#define CHECK_YESNO(c) ((!strcasecmp(c,"on") || !strcasecmp(c,"yes")) ? 1 : 0)

/**
 * Initialize the config parser
 */
void config_init(apr_pool_t *p);

/**
 * Dump the configuration to stdout
 */
void config_dump(config_t *cfg);

/**
 * Checks the configuration to ensure all the required settings are set
 */
apr_status_t config_check(config_t *cfg);

/**
 * Creates the default configuration
 */
config_t *config_create(apr_pool_t *p);

/**
 * Read in a configuration file
 */
apr_status_t config_read(config_t *cfg, const char *filename,
        apr_table_t *merge);

#endif /*CONFIG_H_*/
