/* $Id: mod_log_sql_dbi.c 120 2004-04-17 15:14:12Z urkle@drip.ws $ */

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

#include "config.h"
#endif

#include "mod_log_sql.h"

#include "apr_dbd.h"
#include "mod_dbd.h"

typedef struct {
	ap_dbd_t *dbd;
} request_config_t;

LOGSQL_MODULE_FORWARD(dbd);

static ap_dbd_t *(*dbd_acquire_fn)(request_rec*) = NULL;

static ap_dbd_t *log_sql_dbd_getconnection(request_rec *r)
{
	request_config_t *rconf = ap_get_module_config(r->request_config, &LOGSQL_MODULE(dbd));
	if (!rconf) {
		rconf = apr_pcalloc(r->pool, sizeof(request_config_t));
		ap_set_module_config(r->request_config, &LOGSQL_MODULE(dbd), (void *)rconf);
		rconf->dbd = dbd_acquire_fn(r);
	}
	return rconf->dbd;
}

/* Connect to the database */
static logsql_opendb_ret log_sql_dbd_connect(server_rec *s, logsql_dbconnection *db)
{
	// We are using mod_dbd so we don't do anything here
	if (!dbd_acquire_fn) {
		// no mod_dbd return failure
		log_error(APLOG_MARK,APLOG_ERR,0, s,"mod_log_sql_dbd: mod_dbd is not loaded or available");
		return LOGSQL_OPENDB_FAIL;
	} else {
		return LOGSQL_OPENDB_SUCCESS;
	}
}

/* Close the DB link */
static void log_sql_dbd_close(logsql_dbconnection *db)
{
	// mod_dbd handles this, so do nothing
}

/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 */
static const char *log_sql_dbd_escape(request_rec *r, const char *from_str, apr_pool_t *p, 
								logsql_dbconnection *db)
{
	// Acquire a DBD connection from mod_dbd
	ap_dbd_t *dbd = log_sql_dbd_getconnection(r);
	if (!dbd) return NULL;

	if (!from_str)
		return NULL;

	return apr_pstrcat(p, "'",apr_dbd_escape(dbd->driver, p, from_str, dbd->handle),"'",NULL);
}

/* Run an insert query and return a categorized error or success */
static logsql_query_ret log_sql_dbd_query(request_rec *r,logsql_dbconnection *db,
								const char *query)
{
	int ret;
	const char *err;
	int affected;
	// Acquire a DBD connection from mod_dbd
	ap_dbd_t *dbd = log_sql_dbd_getconnection(r);
	if (!dbd) return LOGSQL_QUERY_NOLINK;

	// Run the query 
	ret = apr_dbd_query(dbd->driver, dbd->handle, &affected, query);
	if (ret == 0) {
		return LOGSQL_QUERY_SUCCESS;
	} else {
		// attempt to detect error message
		err = apr_dbd_error(dbd->driver, dbd->handle, ret);
		log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "DB Returned error: (%d) %s", ret, err);
		// Unable to check if "NO SUCH TABLE" due to apr_dbd not mapping error codes to a standard set.
		return LOGSQL_QUERY_FAIL;
	}
}

/* Create table table_name of type table_type. */
static logsql_table_ret log_sql_dbd_create(request_rec *r, logsql_dbconnection *db,
						logsql_tabletype table_type, const char *table_name)
{
	return LOGSQL_TABLE_FAIL;
}

static const char *supported_drivers[] = {"dbd",NULL};
static logsql_dbdriver log_sql_dbd_driver = {
    "dbd",
	supported_drivers,
	log_sql_dbd_connect,/* open DB connection */
	log_sql_dbd_close,	/* close DB connection */
	log_sql_dbd_escape,	/* escape query */
	log_sql_dbd_query,	/* insert query */
	log_sql_dbd_create	/* create table */
};

LOGSQL_REGISTER(dbd) {
	dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
	if (dbd_acquire_fn == NULL) {
		log_error(APLOG_MARK,APLOG_ERR,0,s,"You must load mod_dbd to enable AuthDBD functions");
    }

	log_sql_register_driver(p,&log_sql_dbd_driver);
	LOGSQL_REGISTER_RETURN;
}
