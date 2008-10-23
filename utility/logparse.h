#ifndef LOGPARSE_H_
#define LOGPARSE_H_

#include "config.h"

typedef apr_status_t (*parser_func_t)(apr_pool_t *p, config_t *cfg,
        config_output_field_t *field, const char *value, char **ret);

parser_func_t parser_get_func(const char *name);

void parser_init(apr_pool_t *p);

void parser_find_logs(config_t *cfg);

apr_status_t parse_logfile(config_t *cfg, const char *filename);

apr_status_t parse_processline(apr_pool_t *ptemp, config_t *cfg, char **argv,
        int argc);

#endif /*LOGPARSE_H_*/
