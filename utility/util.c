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

/*
 * *** Ripped from HTTPD util.c (why are so many PORTABLE things not in APR UTIL?)
 */
static char x2c(const char *what)
{
    register char digit;

    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
             : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
              : (what[1] - '0'));
    return (digit);
}

/*
 * *** Ripped from HTTPD util.c (why are so many PORTABLE things not in APR UTIL?)
 *
 * Unescapes a URL, leaving reserved characters intact.
 * Returns 0 on success, non-zero on error
 * Failure is due to
 *   bad % escape       returns HTTP_BAD_REQUEST
 *
 *   decoding %00 or a forbidden character returns HTTP_NOT_FOUND
 */
static int unescape_url(char *url, const char *forbid, const char *reserved)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return APR_SUCCESS;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                if ((decoded == '\0')
                    || (forbid && strchr(forbid, decoded))) {
                    badpath = 1;
                    *x = decoded;
                    y += 2;
                }
                else if (reserved && strchr(reserved, decoded)) {
                    *x++ = *y++;
                    *x++ = *y++;
                    *x = *y;
                }
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        return APR_EINVAL;
    }
    else if (badpath) {
        return APR_EINVAL;
    }
    else {
        return APR_SUCCESS;
    }
}

/*
 * *** Ripped from HTTPD util.c (why are so many PORTABLE things not in APR UTIL?)
 */
int ap_unescape_url(char *url)
{
    /* Traditional */
#ifdef CASE_BLIND_FILESYSTEM
    return unescape_url(url, "/\\", NULL);
#else
    return unescape_url(url, "/", NULL);
#endif
}

void logging_init(config_t *cfg)
{
    apr_status_t rv;
    apr_pool_create(&cfg->errorlog_p, cfg->pool);
    apr_file_open_stderr(&cfg->errorlog_fperr, cfg->pool);
    if (cfg->errorlog) {
        rv = apr_file_open(&cfg->errorlog_fp, cfg->errorlog,
                APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_APPEND,
                APR_OS_DEFAULT,
                cfg->pool);
        if (rv) {
            printf("Error opening %s\n",cfg->errorlog);
            cfg->loglevel = LOGLEVEL_NONE;
        }
        logging_log(cfg, LOGLEVEL_ERROR, "Log file Opened");
    } else {
        cfg->loglevel = LOGLEVEL_NONE;
        logging_log(cfg, LOGLEVEL_NOISE, "No Log file specified, disabled logging");
    }
}

const char *logging_strerror(apr_status_t rv)
{
    char buff[256];
    return apr_strerror(rv, buff, 256);
}

void logging_log(config_t *cfg, loglevel_e level, const char *fmt, ...)
{
    va_list ap;
    struct iovec vec[2];
    apr_size_t blen;

    if (cfg->loglevel < level) return;

    va_start(ap, fmt);
    apr_pool_clear(cfg->errorlog_p);

    vec[0].iov_base = apr_pvsprintf(cfg->errorlog_p, fmt, ap);
    vec[0].iov_len = strlen(vec[0].iov_base);
    vec[1].iov_base = "\n";
    vec[1].iov_len = 1;

    if (level == LOGLEVEL_NOISE) {
        apr_file_writev(cfg->errorlog_fperr,vec,2,&blen);
    }
    if (cfg->loglevel > LOGLEVEL_NONE) {
        apr_file_writev(cfg->errorlog_fp,vec,2,&blen);
    }

    va_end(ap);
}
