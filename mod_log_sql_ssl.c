/* $Id: mod_log_sql_ssl.c,v 1.7 2004/03/05 00:30:58 urkle Exp $ */
/* mod_log_sql_ssl */

#if defined(WITH_APACHE20)
#	include "apache20.h"
#elif defined(WITH_APACHE13)
#	include "apache13.h"
#else
#	error Unsupported Apache version
#endif

#ifdef HAVE_CONFIG_H
/* Undefine these to prevent conflicts between Apache ap_config_auto.h and 
 * my config.h. Only really needed for Apache < 2.0.48, but it can't hurt.
 */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"
#endif

#include "mod_log_sql.h"
#include "mod_ssl.h"

#if defined(WITH_APACHE20)
#	define TEST_SSL(r) myConnConfig(r->connection)
#elif defined(WITH_APACHE13)
#	define TEST_SSL(r) ap_ctx_get(r->connection->client->ctx, "ssl")
#endif

static const char *extract_ssl_keysize(request_rec *r, char *a)
{
	char *result = NULL;
	if (TEST_SSL(r) != NULL)
	{
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_USEKEYSIZE");
   	    log_error(APLOG_MARK,APLOG_DEBUG,r->server,"SSL_KEYSIZE: %s", result);
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "0";
	}
}

static const char *extract_ssl_maxkeysize(request_rec *r, char *a)
{
	char *result = NULL;
	if (TEST_SSL(r) != NULL) 
	{
		result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_ALGKEYSIZE");
   	    log_error(APLOG_MARK,APLOG_DEBUG,r->server,"SSL_ALGKEYSIZE: %s", result);
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "0";
	}
}

static const char *extract_ssl_cipher(request_rec *r, char *a)
{
	char *result = NULL;
	if (TEST_SSL(r) != NULL)
	{
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
   	    log_error(APLOG_MARK,APLOG_DEBUG,r->server,"SSL_CIPHER: %s", result);
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "-";
	}
}

#if defined(WITH_APACHE20)
static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
#elif defined(WITH_APACHE13)
static void module_init(server_rec *s, apr_pool_t *p)
#endif
{
	log_sql_register_item(s,p,'q', extract_ssl_keysize,       "ssl_keysize",      0, 1);
	log_sql_register_item(s,p,'Q', extract_ssl_maxkeysize,    "ssl_maxkeysize",   0, 1);
	log_sql_register_item(s,p,'z', extract_ssl_cipher,        "ssl_cipher",       0, 1);
#if defined(WITH_APACHE20)
	return OK;
#endif
}

/* The configuration array that sets up the hooks into the module. */
#if defined(WITH_APACHE20)
static void register_hooks(apr_pool_t *p) {
	ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA log_sql_ssl_module = {
	STANDARD20_MODULE_STUFF,
	NULL,		/* create per-directory config structures */
    NULL,		/* merge per-directory config structures */
    NULL,		/* create per-server config structures */
    NULL,		/* merge per-server config structures     */
    NULL,		/* command handlers */
    register_hooks	/* register hooks */
};
#elif defined(WITH_APACHE13)
module log_sql_ssl_module = {
	STANDARD_MODULE_STUFF,
	module_init,			/* module initializer 				*/
	NULL,					/* create per-dir config 			*/
	NULL,					/* merge per-dir config 			*/
	NULL,		 			/* create server config 			*/
	NULL,	 				/* merge server config 			*/
	NULL,			/* config directive table 			*/
	NULL,					/* [9] content handlers 			*/
	NULL,					/* [2] URI-to-filename translation */
	NULL,					/* [5] check/validate user_id 		*/
	NULL,					/* [6] check authorization 		*/
	NULL,					/* [4] check access by host		*/
	NULL,					/* [7] MIME type checker/setter 	*/
	NULL,					/* [8] fixups 						*/
	NULL,	/* [10] logger 					*/
	NULL					/* [3] header parser 				*/
#if MODULE_MAGIC_NUMBER >= 19970728 /* 1.3-dev or later support these additionals... */
	,NULL,   /* child process initializer 		*/
	NULL,    /* process exit/cleanup 			*/
	NULL					 /* [1] post read-request 			*/
#endif

};
#endif
