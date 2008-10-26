#ifndef UTIL_H_
#define UTIL_H_

#include "apr_pools.h"

#include "config.h"

char *lowerstr(apr_pool_t *pool, const char *input);

/**
 * Chomp new line characters off the end of the line
 */
void line_chomp(char *str);

int ap_unescape_url(char *url);

void logging_preinit(config_t *cfg);

void logging_init(config_t *cfg);

void logging_log(config_t *cfg, loglevel_e level, const char *fmt, ...)
            __attribute__((format(printf, 3, 4)));

const char *logging_strerror(apr_status_t rv);

#endif /*UTIL_H_*/
