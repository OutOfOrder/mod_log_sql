#ifndef UTIL_H_
#define UTIL_H_

#include "apr_pools.h"

char *lowerstr(apr_pool_t *pool, const char *input);

/**
 * Chomp new line characters off the end of the line
 */
void line_chomp(char *str);

#endif /*UTIL_H_*/
