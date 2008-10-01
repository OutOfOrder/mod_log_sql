#ifndef CONFIG_H_
#define CONFIG_H_

#include "apr_tables.h"
#include "apr_hash.h"
#include "apr_file_io.h"

typedef enum {
    LOGLEVEL_QUIET = 0,
    LOGLEVEL_ERROR = 1,
    LOGLEVEL_WARN = 2,
    LOGLEVEL_DEBUG = 3,
} loglevel_e;

typedef struct {
    /** the structures pool (to ease function arguments) */
    apr_pool_t *pool;

    /** error log file */
    const char *errorlog;
    /** log level */
    loglevel_e loglevel;
    /** error_log */
    apr_file_t *errorlog_fp;

    /** input directory of log files */
    const char *input_dir;
    /** list of files to scan */
    apr_array_header_t *input_files;

    /** db connection configuration */
    apr_table_t *dbconfig;
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
    apr_array_header_t *filters;

    /** Dry Run */
    int dryrun;

    /* Show the summary */
    int summary;
} config_t;

typedef struct {
    const char *name;
    apr_array_header_t *fields;
} config_logformat_t;

typedef struct {
    const char *name;
    const char *datatype;
} config_logformat_field_t;

typedef struct config_opt_t config_opt_t;
typedef apr_status_t (*config_func_t)(config_t *cfg, config_opt_t *opt,
        int argc, const char **argv);

struct config_opt_t {
    const char *name;
    const char *help;
    config_func_t func;
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
 * Creates the default configuration
 */
config_t *config_create(apr_pool_t *p);

/**
 * Read in a configuration file
 */
apr_status_t config_read(config_t *cfg, const char *filename,
        apr_table_t *merge);

void config_generate(const char *filename);

#endif /*CONFIG_H_*/
