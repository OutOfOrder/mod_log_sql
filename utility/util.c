#include "util.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_file_io.h"

#include "config.h"

#include <stdarg.h>

char *lowerstr(apr_pool_t *pool, const char *input)
{
    char *temp;
    char *itr;
    temp = apr_pstrdup(pool, input);
    for (itr=temp; *itr!='\0'; itr++) {
        *itr = apr_tolower(*itr);
    }
    return temp;
}

void line_chomp(char *str)
{
    int len;
    // chomp off newline
    len = strlen(str);
    if (len) {
        while (str[len-1] == '\r' || str[len-1] == '\n') {
            str[len-1] = '\0';
            len--;
        }
    }
}

void logging_init(config_t *cfg)
{
    if (cfg->errorlog) {
        apr_file_open(&cfg->errorlog_fp, cfg->errorlog,
                APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_BUFFERED,
                APR_OS_DEFAULT,
                cfg->pool);
        apr_pool_create(&cfg->errorlog_p, cfg->pool);
    }
}

/**
 * @todo implement logging
 */
void logging_log(config_t *cfg, loglevel_e level, const char *fmt, ...)
{
    va_list ap;
    struct iovec vec[2];
    apr_size_t blen;

    if (!cfg->errorlog_fp || cfg->loglevel < level) return;

    va_start(ap, fmt);
    apr_pool_clear(cfg->errorlog_p);

    vec[0].iov_base = apr_pvsprintf(cfg->errorlog_p, fmt, ap);
    vec[0].iov_len = strlen(vec[0].iov_base);
    vec[1].iov_base = "\n";
    vec[1].iov_len = 1;

    apr_file_writev(cfg->errorlog_fp,vec,2,&blen);

    va_end(ap);
}
