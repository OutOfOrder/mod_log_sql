/* $Id$ */

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

/* Registration function for extract functions */

typedef const char *logsql_item_func(request_rec *r, char *a);

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
	LOGSQL_QUERY_PRESERVED
} logsql_query_ret;

typedef enum {
	LOGSQL_TABLE_SUCCESS = 0,
	LOGSQL_TABLE_FAIL
} logsql_table_ret;

/* Table type to create/log to */
typedef enum {
	LOGSQL_TABLE_ACCESS = 0,
	LOGSQL_TABLE_NOTES,
	LOGSQL_TABLE_HEADERSOUT,
	LOGSQL_TABLE_HEADERSIN,
	LOGSQL_TABLE_COOKIES
} logsql_tabletype;

/* All Tables */
#define LOGSQL_TABLE_ALL LOGSQL_TABLE_ACCESS | LOGSQL_TABLE_NOTES | \
	LOGSQL_TABLE_HEADERSIN | LOGSQL_TABLE_HEADERSOUT | LOGSQL_TABLE_COOKIES

/* MySQL module calls */

/* Registration function for database drivers */

typedef struct {
	/* NULL terminated list of drivers strings */
	char **provided_drivers;
	/* create a connection to the underlying database layer */
	logsql_opendb_ret (*connect)(server_rec *s, logsql_dbconnection *db);
	/* disconnect from the underlying database layer */
	void (*disconnect)(logsql_dbconnection *db);
	/* escape the SQL statement according to database rules */
	const char *(*escape)(const char *from_str, apr_pool_t *p, 
		logsql_dbconnection *db);
	/* insert a SQL query statement */
	logsql_query_ret (*insert)(request_rec *r,logsql_dbconnection *db,
		const char *query);
	/* create a SQL table named table_name of table_type */
	logsql_table_ret (*create_table)(request_rec *r, logsql_dbconnection *db,
		logsql_tabletype table_type, const char *table_name);
} logsql_dbdriver;

LOGSQL_DECLARE(void) log_sql_register_driver(apr_pool_t *p,
		logsql_dbdriver *driver);

/* Module initialization Macros */
#if defined(WITH_APACHE20)
#	define LOGSQL_REGISTER(driver) \
	static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s); \
	static void register_hooks(apr_pool_t *p) { \
		ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_FIRST); \
	} \
	\
	module AP_MODULE_DECLARE_DATA log_sql_##driver##_module = { \
		STANDARD20_MODULE_STUFF, \
		NULL, NULL,  NULL, NULL,  NULL, register_hooks }; \
	static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
#elif defined(WITH_APACHE13)
#	define LOGSQL_REGISTER(driver) \
	static void module_init(server_rec *s, apr_pool_t *p); \
	module log_sql_##driver##_module = { \
		STANDARD_MODULE_STUFF, module_init }; \
	static void module_init(server_rec *s, apr_pool_t *p)
#endif

#if defined(WITH_APACHE20)
#define LOGSQL_REGISTER_RETURN return OK;
#elif defined(WITH_APACHE13)
#define LOGSQL_REGISTER_RETURN
#endif

#endif /* MOD_LOG_SQL_H */
