/* $Id: mod_log_sql.h,v 1.5 2004/03/02 05:34:50 urkle Exp $ */

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

/* DB Connection structure holds connection handle */
typedef struct {
	int connected; /* Are we connected to the DB */
	void *handle; /* DB specific connection pointer */
	apr_table_t *parms; /* DB connection parameters */
} logsql_dbconnection;

/* open db handle return values*/
typedef enum {
	LOGSQL_OPENDB_FAIL = 0,
	LOGSQL_OPENDB_SUCCESS,
	LOGSQL_OPENDB_ALREADY,
	LOGSQL_OPENDB_PRESERVE
} logsql_opendb_ret;

typedef enum {
	LOGSQL_QUERY_SUCCESS = 0,
	LOGSQL_QUERY_FAIL,
	LOGSQL_QUERY_NOLINK,
	LOGSQL_QUERY_NOTABLE,
	LOGSQL_QUERY_PRESERVED,
} logsql_query_ret;

typedef enum {
	LOGSQL_TABLE_SUCCESS = 0,
	LOGSQL_TABLE_FAIL,
} logsql_table_ret;

/* Table type to create/log to */
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

/* MySQL module calls */
logsql_opendb_ret log_sql_mysql_connect(server_rec *s, logsql_dbconnection *db);
void log_sql_mysql_close(logsql_dbconnection *db);
const char *log_sql_mysql_escape(const char *from_str, apr_pool_t *p, 
								logsql_dbconnection *db);
logsql_query_ret log_sql_mysql_query(request_rec *r,logsql_dbconnection *db,
								const char *query);
logsql_table_ret log_sql_mysql_create(request_rec *r, logsql_dbconnection *db,
						logsql_tabletype table_type, const char *table_name);


#endif /* MOD_LOG_SQL_H */
