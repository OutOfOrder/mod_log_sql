#ifndef UTIL_H_
#define UTIL_H_

#include "apr_pools.h"

#include "config.h"

char *lowerstr(apr_pool_t *pool, const char *input);

/**
 * Chomp new line characters off the end of the line
 */
void line_chomp(char *str);

void logging_init(config_t *cfg);

void logging_log(config_t *cfg, loglevel_e level, const char *fmt, ...)
            __attribute__((format(printf, 3, 4)));

#endif /*UTIL_H_*/
