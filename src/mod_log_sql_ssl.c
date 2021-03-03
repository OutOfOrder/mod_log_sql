/* $Id:mod_log_sql_ssl.c 180 2008-09-21 15:54:12Z urkle@drip.ws $ */

#if defined(WITH_APACHE20)
#	include "apache20.h"
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

#include "autoconfig.h"
#endif

#include "mod_log_sql.h"

#include "mod_ssl.h"

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) * header_ssl_lookup = NULL;
#define TEST_SSL(r) header_ssl_lookup

static const char *extract_ssl_keysize(request_rec * r, char *a)
{
    if (TEST_SSL(r) != NULL) {
	char *result = header_ssl_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_USEKEYSIZE");
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "SSL_KEYSIZE: %s", result);
	if (result && result[0])
	    return result;
    }
    return NULL;
}

static const char *extract_ssl_maxkeysize(request_rec * r, char *a)
{
    if (TEST_SSL(r) != NULL) {
	char *result = header_ssl_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_ALGKEYSIZE");
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "SSL_ALGKEYSIZE: %s", result);
	if (result && result[0])
	    return result;
    }
    return NULL;
}

static const char *extract_ssl_cipher(request_rec * r, char *a)
{
    if (TEST_SSL(r) != NULL) {
	char *result = header_ssl_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
	log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "SSL_CIPHER: %s", result);
	if (result && result[0])
	    return result;
    }
    return NULL;
}


LOGSQL_REGISTER(ssl)
{
    log_sql_register_function(p, "ssl_keysize", extract_ssl_keysize, LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "ssl_maxkeysize", extract_ssl_maxkeysize, LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "ssl_cipher", extract_ssl_cipher, LOGSQL_FUNCTION_REQ_FINAL);

    log_sql_register_alias(s, p, 'q', "ssl_keysize");
    log_sql_register_alias(s, p, 'Q', "ssl_maxkeysize");
    log_sql_register_alias(s, p, 'z', "ssl_cipher");

    log_sql_register_field(p, "ssl_keysize",	"ssl_keysize",		NULL, "ssl_keysize",	LOGSQL_DATATYPE_INT, 20);
    log_sql_register_field(p, "ssl_maxkeysize", "ssl_maxkeysize",	NULL, "ssl_maxkeysize", LOGSQL_DATATYPE_INT, 20);
    log_sql_register_field(p, "ssl_cipher",	"ssl_cipher",		NULL, "ssl_cipher",	LOGSQL_DATATYPE_VARCHAR, 25);

    header_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    LOGSQL_REGISTER_RETURN;
}
