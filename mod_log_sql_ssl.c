/* $Header: /home/cvs/mod_log_sql/mod_log_sql_ssl.c,v 1.1 2004/01/20 19:38:08 urkle Exp $ */
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

#ifdef WANT_SSL_LOGGING
	{   'q', extract_ssl_keysize,       "ssl_keysize",      0, 1    },
	{   'Q', extract_ssl_maxkeysize,    "ssl_maxkeysize",   0, 1    },
	{   'z', extract_ssl_cipher,        "ssl_cipher",       0, 1    },
#endif
