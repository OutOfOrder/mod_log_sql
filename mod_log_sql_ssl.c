/* $Id$ */

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
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *header_ssl_lookup = NULL;
#	define TEST_SSL(r) header_ssl_lookup
#elif defined(WITH_APACHE13)
#	define TEST_SSL(r) ap_ctx_get(r->connection->client->ctx, "ssl")
#   define header_ssl_lookup ssl_var_lookup
#endif

static const char *extract_ssl_keysize(request_rec *r, char *a)
{
	char *result = NULL;
	if (TEST_SSL(r) != NULL)
	{
	    result = header_ssl_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_USEKEYSIZE");
   	    log_error(APLOG_MARK,APLOG_DEBUG,0, r->server,"SSL_KEYSIZE: %s", result);
		if (result && result[0])
		    return result;
        else
            return "0";
	} else {
		return "0";
	}
}

static const char *extract_ssl_maxkeysize(request_rec *r, char *a)
{
	char *result = NULL;
	if (TEST_SSL(r) != NULL) 
	{
		result = header_ssl_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_ALGKEYSIZE");
   	    log_error(APLOG_MARK,APLOG_DEBUG,0, r->server,"SSL_ALGKEYSIZE: %s", result);
		if (result && result[0])
		    return result;
        else
            return "0";
    } else {
		return "0";
	}
}

static const char *extract_ssl_cipher(request_rec *r, char *a)
{
	char *result = NULL;
	if (TEST_SSL(r) != NULL)
	{
	    result = header_ssl_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
   	    log_error(APLOG_MARK,APLOG_DEBUG,0, r->server,"SSL_CIPHER: %s", result);
		if (result && result[0])
		    return result;
        else
            return "0";
	} else {
		return "-";
	}
}


LOGSQL_REGISTER(ssl)
{
	log_sql_register_item(s,p,'q', extract_ssl_keysize,       "ssl_keysize",      0, 1);
	log_sql_register_item(s,p,'Q', extract_ssl_maxkeysize,    "ssl_maxkeysize",   0, 1);
	log_sql_register_item(s,p,'z', extract_ssl_cipher,        "ssl_cipher",       0, 1);
#if defined(WITH_APACHE20)
    header_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
#endif
	LOGSQL_REGISTER_RETURN;
}
