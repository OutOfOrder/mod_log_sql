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

#include "mysql.h"
#include "mysqld_error.h"

/* The enduser won't modify these */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")

/* Connect to the MYSQL database */
static logsql_opendb_ret log_sql_mysql_connect(server_rec *s, logsql_dbconnection *db)
{
	const char *host = apr_table_get(db->parms,"hostname");
	const char *user = apr_table_get(db->parms,"username");
	const char *passwd = apr_table_get(db->parms,"password");
	const char *database = apr_table_get(db->parms,"database");
	const char *s_tcpport = apr_table_get(db->parms,"port");
	unsigned int tcpport = (s_tcpport)?atoi(s_tcpport):3306;
	const char *socketfile = apr_table_get(db->parms,"socketfile");
	MYSQL *dblink = db->handle;

	dblink = mysql_init(dblink);
	db->handle = (void *)dblink;


	if (!socketfile) {
		socketfile = "/var/lib/mysql/mysql.sock";
	}

	if (mysql_real_connect(dblink, host, user, passwd, database, tcpport,
						socketfile, 0)) {
		log_error(APLOG_MARK,APLOG_DEBUG,0, s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
				host, tcpport, database, user, socketfile);
		return LOGSQL_OPENDB_SUCCESS;
	} else {
		log_error(APLOG_MARK,APLOG_ERR,0, s,"mod_log_sql_mysql: database connection error: mysql error: %s",
				MYSQL_ERROR(dblink));
		log_error(APLOG_MARK,APLOG_DEBUG, 0, s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
				host, tcpport, database, user, socketfile);
		return LOGSQL_OPENDB_FAIL;
	}
}

/* Close the DB link */
static void log_sql_mysql_close(logsql_dbconnection *db)
{
	mysql_close((MYSQL *)db->handle);
        /* mysql_close frees this data so NULL it out incase we reconnect later */
        db->handle=NULL;
}

/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 */
static const char *log_sql_mysql_escape(const char *from_str, apr_pool_t *p,
								logsql_dbconnection *db)
{
        /* Return "NULL" for empty strings */
	if (!from_str || strlen(from_str) == 0)
		return "NULL";
	else {
	  	char *to_str;
		unsigned long length = strlen(from_str);
		unsigned long retval;

		/* Pre-allocate a new string that could hold twice the original, which would only
		 * happen if the whole original string was 'dangerous' characters.
		 */
		to_str = (char *) apr_palloc(p, length * 2 + 3);
		if (!to_str) {
			return from_str;
		}
        strcpy(to_str, "'");
		if (!db->connected) {
			/* Well, I would have liked to use the current database charset.  mysql is
			 * unavailable, however, so I fall back to the slightly less respectful
			 * mysql_escape_string() function that uses the default charset.
			 */
			retval = mysql_escape_string(to_str+1, from_str, length);
		} else {
			/* MySQL is available, so I'll go ahead and respect the current charset when
			 * I perform the escape.
			 */
			retval = mysql_real_escape_string((MYSQL *)db->handle, to_str+1, from_str, length);
		}
        strcat(to_str,"'");

		if (retval)
		  return to_str;
		else
		  return from_str;
	}
}

#if defined(WIN32)
#define SIGNAL_GRAB
#define SIGNAL_RELEASE
#define SIGNAL_VAR
#else
#define SIGNAL_VAR void (*handler) (int);
#define SIGNAL_GRAB handler = signal(SIGPIPE, SIG_IGN);
#define SIGNAL_RELEASE signal(SIGPIPE, handler);
#endif
/* Run a mysql insert query and return a categorized error or success */
static logsql_query_ret log_sql_mysql_query(request_rec *r,logsql_dbconnection *db,
								const char *query)
{
	int retval;
    SIGNAL_VAR

	unsigned int real_error = 0;
	/*const char *real_error_str = NULL;*/

	MYSQL *dblink = (MYSQL *)db->handle;

	if (!dblink) {
		return LOGSQL_QUERY_NOLINK;
	}

	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	SIGNAL_GRAB

	/* Run the query */
	if (!(retval = mysql_query(dblink, query))) {
	        SIGNAL_RELEASE
		return LOGSQL_QUERY_SUCCESS;
	}
        log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
            "mysql_query returned (%d)", retval);
	/* Check to see if the error is "nonexistent table" */
	real_error = mysql_errno(dblink);

	if (real_error == ER_NO_SUCH_TABLE) {
		log_error(APLOG_MARK,APLOG_ERR,0, r->server,"table does not exist, preserving query");
		/* Restore SIGPIPE to its original handler function */
	    SIGNAL_RELEASE
		return LOGSQL_QUERY_NOTABLE;
	}

	/* Restore SIGPIPE to its original handler function */
	SIGNAL_RELEASE
	return LOGSQL_QUERY_FAIL;
}

/* Create table table_name of type table_type. */
static logsql_table_ret log_sql_mysql_create(request_rec *r, logsql_dbconnection *db,
						logsql_tabletype table_type, const char *table_name)
{
	int retval;
	const char *tabletype = apr_table_get(db->parms,"tabletype");
	SIGNAL_VAR
	char *type_suffix = NULL;

	char *create_prefix = "create table if not exists `";
	char *create_suffix = NULL;
	char *create_sql;

	MYSQL *dblink = (MYSQL *)db->handle;

/*	if (!global_config.createtables) {
		return APR_SUCCESS;
	}*/

	switch (table_type) {
	case LOGSQL_TABLE_ACCESS:
		create_suffix =
	"` (id char(19),\
       agent varchar(255),\
       bytes_sent int unsigned,\
       child_pid smallint unsigned,\
       cookie varchar(255),\
       machine_id varchar(25),\
       request_file varchar(255),\
       referer varchar(255),\
       remote_host varchar(50),\
       remote_logname varchar(50),\
       remote_user varchar(50),\
       request_duration smallint unsigned,\
       request_line varchar(255),\
       request_method varchar(10),\
       request_protocol varchar(10),\
       request_time char(28),\
       request_uri varchar(255),\
       request_args varchar(255),\
       server_port smallint unsigned,\
       ssl_cipher varchar(25),\
       ssl_keysize smallint unsigned,\
       ssl_maxkeysize smallint unsigned,\
       status smallint unsigned,\
       time_stamp int unsigned,\
       virtual_host varchar(255),\
       bytes_in int unsigned,\
       bytes_out int unsigned)";
		break;
	case LOGSQL_TABLE_COOKIES:
	case LOGSQL_TABLE_HEADERSIN:
	case LOGSQL_TABLE_HEADERSOUT:
	case LOGSQL_TABLE_NOTES:
		create_suffix =
	"` (id char(19),\
	   item varchar(80),\
	   val varchar(80))";
		break;
	}

	if (tabletype) {
		type_suffix = apr_pstrcat(r->pool, " TYPE=",
							tabletype, NULL);
	}
	/* Find memory long enough to hold the whole CREATE string + \0 */
	create_sql = apr_pstrcat(r->pool, create_prefix, table_name, create_suffix,
						type_suffix, NULL);

	log_error(APLOG_MARK,APLOG_DEBUG,0, r->server,"create string: %s", create_sql);

	if (!dblink) {
		return LOGSQL_QUERY_NOLINK;
	}
	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	SIGNAL_GRAB

	/* Run the create query */
  	if ((retval = mysql_query(dblink, create_sql))) {
		log_error(APLOG_MARK,APLOG_ERR,0, r->server,"failed to create table: %s",
			table_name);
		SIGNAL_RELEASE
		return LOGSQL_TABLE_FAIL;
	}
	SIGNAL_RELEASE
	return LOGSQL_TABLE_SUCCESS;
}

static const char *supported_drivers[] = {"mysql",NULL};
static logsql_dbdriver mysql_driver = {
    "mysql",
	supported_drivers,
	log_sql_mysql_connect,	/* open DB connection */
	log_sql_mysql_close,	/* close DB connection */
	log_sql_mysql_escape,	/* escape query */
	log_sql_mysql_query,	/* insert query */
	log_sql_mysql_create	/* create table */
};

LOGSQL_REGISTER(mysql) {
	log_sql_register_driver(p,&mysql_driver);
	LOGSQL_REGISTER_RETURN;
}
