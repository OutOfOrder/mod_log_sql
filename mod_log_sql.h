/* $Header: /home/cvs/mod_log_sql/mod_log_sql.h,v 1.3 2004/01/22 05:26:56 urkle Exp $ */
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

typedef const char *log_sql_item_func(request_rec *r, char *a);

/* Registration Function for extract functions */
LOGSQL_DECLARE(void) log_sql_register_item(server_rec *s, apr_pool_t *p,
		char key, log_sql_item_func *func, const char *sql_field_name,
		int want_orig_default, int string_contents);
#endif /* MOD_LOG_SQL_H */
