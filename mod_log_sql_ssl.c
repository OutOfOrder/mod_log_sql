/* $Header: /home/cvs/mod_log_sql/mod_log_sql_ssl.c,v 1.3 2004/01/21 04:34:21 urkle Exp $ */
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

#include "mod_ssl.h"

static const char *extract_ssl_keysize(request_rec *r, char *a)
{
	char *result = NULL;
#if defined(APACHE20)
	SSLConnRec *scc = myConnConfig(r->connection);
	SSLSrvConfigRec *ssc = mySrvConfig(r->server);
	if (myCtxConfig(scc,ssc) != NULL
#elif defined(APACHE13)
	if (ap_ctx_get(r->connection->client->ctx, "ssl") != NULL) 
#endif
	{
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_USEKEYSIZE");
		#ifdef DEBUG
    	    log_error(APLOG_MARK,APLOG_DEBUG,0,r->server,"SSL_KEYSIZE: %s", result);
		#endif
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
#if defined(APACHE20)
	SSLConnRec *scc = myConnConfig(r->connection);
	SSLSrvConfigRec *ssc = mySrvConfig(r->server);
	if (myCtxConfig(scc,ssc) != NULL
#elif defined(APACHE13)
	if (ap_ctx_get(r->connection->client->ctx, "ssl") != NULL) 
#endif
	{
		result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_ALGKEYSIZE");
		#ifdef DEBUG
    	    log_error(APLOG_MARK,APLOG_DEBUG,0,r->server,"SSL_ALGKEYSIZE: %s", result);
		#endif
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
#if defined(APACHE20)
	SSLConnRec *scc = myConnConfig(r->connection);
	SSLSrvConfigRec *ssc = mySrvConfig(r->server);
	if (myCtxConfig(scc,ssc) != NULL
#elif defined(APACHE13)
	if (ap_ctx_get(r->connection->client->ctx, "ssl") != NULL) 
#endif
	{
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
		#ifdef DEBUG
    	    log_error(APLOG_MARK,APLOG_DEBUG,0,r->server,"SSL_CIPHER: %s", result);
		#endif
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "-";
	}
}

#if defined(WITH_APACHE20)
static int pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
#elif defined(WITH_APACHE13)
static void module_init(server_rec *s, apr_pool_t *p)
#endif
{
	log_sql_register_item(p,'q', extract_ssl_keysize,       "ssl_keysize",      0, 1);
	log_sql_register_item(p,'Q', extract_ssl_maxkeysize,    "ssl_maxkeysize",   0, 1);
	log_sql_register_item(p,'z', extract_ssl_cipher,        "ssl_cipher",       0, 1);
}

/* The configuration array that sets up the hooks into the module. */
#if defined(WITH_APACHE20)
static void register_hooks(apr_pool_t *p) {
	ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA log_sql_module = {
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
	log_sql_cmds,			/* config directive table 			*/
	NULL,					/* [9] content handlers 			*/
	NULL,					/* [2] URI-to-filename translation */
	NULL,					/* [5] check/validate user_id 		*/
	NULL,					/* [6] check authorization 		*/
	NULL,					/* [4] check access by host		*/
	NULL,					/* [7] MIME type checker/setter 	*/
	NULL,					/* [8] fixups 						*/
	log_sql_transaction,	/* [10] logger 					*/
	NULL					/* [3] header parser 				*/
#if MODULE_MAGIC_NUMBER >= 19970728 /* 1.3-dev or later support these additionals... */
	,log_sql_child_init,   /* child process initializer 		*/
	log_sql_child_exit,    /* process exit/cleanup 			*/
	NULL					 /* [1] post read-request 			*/
#endif

};
#endif
