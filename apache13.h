/* $Header: /home/cvs/mod_log_sql/apache13.h,v 1.5 2004/02/29 23:36:17 urkle Exp $ */
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

/*AP_INIT_TAKE1("LogSQLTransferLogTable", set_server_nmv_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, transfer_table_name), RSRC_CONF, 
	 "The database table that holds the transfer log")

{"LogSQLTransferLogTable", set_log_sql_transfer_table, 			NULL, 	RSRC_CONF, 	TAKE1,
	 "The database table that holds the transfer log"}*/

/** method of declaring a directive which takes 1 argument */
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE1, help }
/** method of declaring a directive which takes multiple arguments */
# define AP_INIT_ITERATE(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, ITERATE, help }
/** method of declaring a directive which takes 3 arguments */
# define AP_INIT_TAKE3(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE3, help }
/** method of declaring a directive which takes a flag (on/off) as an argument */
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, FLAG, help }

/* Types */
#define apr_pool_t pool
#define apr_array_header_t array_header

/* Functions */
#define ap_get_remote_host(a,b,c,d) ap_get_remote_host(a,b,c)

#define apr_uri_unparse ap_unparse_uri_components

#define apr_pool_create(a,b) *(a) = ap_make_sub_pool(b)
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

#define log_error ap_log_error

#endif /* APACHE13_H */
