/* $Id$ */
#ifndef APACHE13_H
#define APACHE13_H

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"

/* Defines */
#define AP_MODULE_DECLARE_DATA
#define APR_OFF_T_FMT "ld"
#define APR_PID_T_FMT "d"
#define APR_SUCCESS 0
#define APR_OFFSETOF XtOffsetOf

/** method of declaring a directive with raw argument parsing */
# define AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, RAW_ARGS, help }
/** method of declaring a directive which takes 1 argument */
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE1, help }
/** method of declaring a directive which takes 2 argument */
# define AP_INIT_TAKE2(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE2, help }
/** method of declaring a directive which takes multiple arguments */
# define AP_INIT_ITERATE(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, ITERATE, help }
/** method of declaring a directive which takes 1 or 3 arguments */
# define AP_INIT_TAKE13(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE13, help }
/** method of declaring a directive which takes 3 arguments */
# define AP_INIT_TAKE3(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE3, help }
/** method of declaring a directive which takes a flag (on/off) as an argument */
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, FLAG, help }

/* Types */
#define apr_pool_t pool
#define apr_array_header_t array_header
#define apr_table_t table

#define apr_status_t int
#define apr_uri_t uri_components

/* Functions */
#define ap_get_remote_host(a,b,c,d) ap_get_remote_host(a,b,c)
#define ap_set_deprecated NULL
	
#define apr_uri_unparse ap_unparse_uri_components
#define apr_uri_parse ap_parse_uri_components
#define ap_add_version_component(p,s) ap_add_version_component(s)

#define apr_pool_create(a,b) *(a) = ap_make_sub_pool(b)
#define apr_pool_destroy ap_destroy_pool
#define apr_palloc ap_palloc
#define apr_pcalloc ap_pcalloc
#define apr_pstrdup ap_pstrdup
#define apr_pstrcat ap_pstrcat
#define apr_psprintf ap_psprintf
#define apr_snprintf ap_snprintf

#define apr_table_set ap_table_set
#define apr_table_get ap_table_get
#define apr_table_make ap_make_table

#define apr_array_push ap_push_array
#define apr_array_make ap_make_array
#define apr_array_cat ap_array_cat
#define apr_is_empty_array(t) (((t) == NULL)||((t)->nelts == 0))

#define apr_tolower ap_tolower

static void log_error(char *file, int line, int level, apr_status_t status, 
	const server_rec *s, const char *fmt, ...) __attribute__ ((format (printf, 6,7)));
static inline void log_error(char *file, int line, int level, 
	apr_status_t status, const server_rec *s, const char *fmt, ...)
{
	static char buff[MAX_STRING_LEN];
	va_list args;
	va_start(args, fmt);
	ap_vsnprintf(buff,MAX_STRING_LEN, fmt,args);
	ap_log_error(file,line,level | APLOG_NOERRNO ,s,"%s",buff);
	va_end(args);
}


#endif /* APACHE13_H */
