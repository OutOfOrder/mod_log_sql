/* $Id: mod_log_sql.h,v 1.4 2004/02/29 23:36:18 urkle Exp $ */

#ifndef MOD_LOG_SQL_H
#define MOD_LOG_SQL_H

/* Create a set of LOGSQL_DECLARE(type), LOGSQL_DECLARE_NONSTD(type) and
 * LOGSQL_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define LOGSQL_DECLARE(type)            type
#define LOGSQL_DECLARE_NONSTD(type)     type
#define LOGSQL_DECLARE_DATA
#elif defined(LOGSQL_DECLARE_STATIC)
#define LOGSQL_DECLARE(type)            type __stdcall
#define LOGSQL_DECLARE_NONSTD(type)     type
#define LOGSQL_DECLARE_DATA
#elif defined(LOGSQL_DECLARE_EXPORT)
#define LOGSQL_DECLARE(type)            __declspec(dllexport) type __stdcall
#define LOGSQL_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define LOGSQL_DECLARE_DATA             __declspec(dllexport)
#else
#define LOGSQL_DECLARE(type)            __declspec(dllimport) type __stdcall
#define LOGSQL_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define LOGSQL_DECLARE_DATA             __declspec(dllimport)
#endif

typedef const char *logsql_item_func(request_rec *r, char *a);

/* Registration Function for extract functions */
LOGSQL_DECLARE(void) log_sql_register_item(server_rec *s, apr_pool_t *p,
		char key, logsql_item_func *func, const char *sql_field_name,
		int want_orig_default, int string_contents);

/* DB Connection structure holds connection status information
 * and connection handle
 */
typedef struct {
	int connected; /* Are we connected to the DB */
	void *handle; /* DB specific connection pointer */
} logsql_dbconnection;

/* open db handle return values*/
typedef enum {
	LOGSQL_OPENDB_FAIL = 0,
	LOGSQL_OPENDB_SUCCESS,
	LOGSQL_OPENDB_ALREADY,
	LOGSQL_OPENDB_PRESERVE
} logsql_opendb;

/* For passing to create_tables handler */
typedef enum {
	LOGSQL_TABLE_ACCESS = 0,
	LOGSQL_TABLE_NOTES,
	LOGSQL_TABLE_HEADERSOUT,
	LOGSQL_TABLE_HEADERSIN,
	LOGSQL_TABLE_COOKIES,
} logsql_tabletype;

/* All Tables */
#define LOGSQL_TABLE_ALL LOGSQL_TABLE_ACCESS | LOGSQL_TABLE_NOTES | \
	LOGSQL_TABLE_HEADERSIN | LOGSQL_TABLE_HEADERSOUT | LOGSQL_TABLE_COOKIES


#endif /* MOD_LOG_SQL_H */
