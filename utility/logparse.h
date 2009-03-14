#ifndef LOGPARSE_H_
#define LOGPARSE_H_

#include "config.h"

typedef apr_status_t (*parser_func_f)(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, const char **ret);

struct parser_func_t {
    parser_func_f func;
    int pos;
    void *data;
    void ***linedata;
};

#define parser_get_linedata(f) (*f->linedata)[f->pos]

#define parser_set_linedata(f, v) (*f->linedata)[f->pos] = v

parser_func_t *parser_get_func(const char *name);

void parser_init(apr_pool_t *p);

void parser_find_logs(config_t *cfg);

void parser_split_logs(config_t *cfg);

apr_status_t parser_tokenize_line(const char *arg_str, char ***argv_out,
        apr_pool_t *token_context);

apr_status_t parser_parsefile(config_t *cfg, config_dbd_t *dbconn,
        config_filestat_t *fstat);

apr_status_t parser_processline(apr_pool_t *ptemp, config_t *cfg,
        config_dbd_t *dbconn, config_filestat_t *line, char **argv, int argc);

#endif /*LOGPARSE_H_*/
