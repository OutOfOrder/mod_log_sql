/* $Id: mod_log_sql_mysql.c,v 1.1 2004/02/29 23:36:18 urkle Exp $ */
#include "mysql.h"
#include "mysqld_error.h"

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

/* The enduser won't modify these */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")

logsql_opendb log_sql_mysql_connect(server_rec *s, logsql_dbconnection *db, 
								apr_table_t *dbparms)
{
	MYSQL *dblink;
	char *host = apr_table_get(dbparms,"host");
	char *user = apr_table_get(dbparms,"user");
	char *passwd = apr_table_get(dbparms,"passwd");
	char *database = apr_table_get(dbparms,"database");
	char *tcpport = apr_table_get(dbparms,"tcpport");
	char *socketfile = apr_table_get(dbparms,"socketfile");
	mysql_init(&dblink);
	if (mysql_real_connect(&dblink, host, user, passwd, database, tcpport,
						socketfile, 0) {
		log_error(APLOG_MARK,APLOG_DEBUG,s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
				host, tcpport, database, user, socketfile);
		return LOGSQL_OPENDB_SUCCESS;
	} else {
		log_error(APLOG_MARK,APLOG_DEBUG,s,"mod_log_sql: database connection error: %s",
				MYSQL_ERROR(&dblink));
		log_error(APLOG_MARK,APLOG_DEBUG,s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
				host, tcpport, database, user, socketfile);
		return LOGSQL_OPENDB_FAIL;
	}
}

/*-----------------------------------------------------*
 * safe_sql_query: perform a database query with       *
 * a degree of safety and error checking.              *
 *                                                     *
 * Parms:   request record, SQL insert statement       *
 * Returns: 0 (OK) on success                          *
 *          1 if have no log handle                    *
 *          2 if insert delayed failed (kluge)         *
 *          the actual MySQL return code on error      *
 *-----------------------------------------------------*/
unsigned int log_sql_mysql_query(request_rec *r, const char *query)
{
	int retval;
	struct timespec delay, remainder;
	int ret;
	void (*handler) (int);
	logsql_state *cls;
	unsigned int real_error = 0;
	const char *real_error_str = NULL;

	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	handler = signal(SIGPIPE, SIG_IGN);

	/* First attempt for the query */
	if (!global_config.server_p) {
		signal(SIGPIPE, handler);
		return 1;
	} else if (!(retval = mysql_query(global_config.server_p, query))) {
		signal(SIGPIPE, handler);
		return 0;
	}

	/* If we ran the query and it returned an error, try to be robust.
	* (After all, the module thought it had a valid mysql_log connection but the query
	* could have failed for a number of reasons, so we have to be extra-safe and check.) */

	/* Check to see if the error is "nonexistent table" */
	if (global_config.insertdelayed) {
		real_error_str = MYSQL_ERROR(global_config.server_p);
		retval = (strstr(real_error_str, "Table")) && (strstr(real_error_str,"doesn't exist"));
	} else {
		real_error = mysql_errno(global_config.server_p);
		retval = (real_error == ER_NO_SUCH_TABLE);
	}
	if (retval) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"table does not exist, preserving query");
		preserve_entry(r, query);
		/* Restore SIGPIPE to its original handler function */
		signal(SIGPIPE, handler);
		return ER_NO_SUCH_TABLE;
	}

	/* Handle all other types of errors */

	cls = ap_get_module_config(r->server->module_config, &log_sql_module);

	/* Something went wrong, so start by trying to restart the db link. */
	if (global_config.insertdelayed) {
	 real_error = 2;
	} /*else {
	 real_error = mysql_errno(global_config.server_p);
	}*/

	log_error(APLOG_MARK,APLOG_ERR,r->server,"first attempt failed, API said: error %d, \"%s\"", real_error, MYSQL_ERROR(global_config.server_p));
	mysql_close(global_config.server_p);
	global_config.server_p = NULL;
	open_logdb_link(r->server);

	if (global_config.server_p == NULL) {	 /* still unable to link */
		signal(SIGPIPE, handler);
		log_error(APLOG_MARK,APLOG_ERR,r->server,"reconnect failed, unable to reach database. SQL logging stopped until child regains a db connection.");
		log_error(APLOG_MARK,APLOG_ERR,r->server,"log entries are being preserved in %s", cls->preserve_file);
		return 1;
	} else
		log_error(APLOG_MARK,APLOG_ERR,r->server,"db reconnect successful");

	/* First sleep for a tiny amount of time. */
	delay.tv_sec = 0;
	delay.tv_nsec = 250000000;  /* max is 999999999 (nine nines) */
	ret = nanosleep(&delay, &remainder);
	if (ret && errno != EINTR)
		log_error(APLOG_MARK,APLOG_ERR,r->server,"nanosleep unsuccessful");

	/* Then make our second attempt */
	retval = mysql_query(global_config.server_p,query);

	/* If this one also failed, log that and append to our local offline file */
	if (retval)	{
		if (global_config.insertdelayed) {
		 real_error = 2;
		} else {
		 real_error = mysql_errno(global_config.server_p);
		}

		log_error(APLOG_MARK,APLOG_ERR,r->server,"second attempt failed, API said: error %d, \"%s\" -- preserving", real_error, MYSQL_ERROR(global_config.server_p));
		preserve_entry(r, query);
		retval = real_error;
	} else {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"second attempt successful");
		retval = 0;
	}
	/* Restore SIGPIPE to its original handler function */
	signal(SIGPIPE, handler);
	return retval;
}

/*-----------------------------------------------------*
 * safe_create_tables: create SQL table set for the    *
 * virtual server represented by cls.                  *
 *                                                     *
 * Parms:   virtserver structure, request record,	   *
 * tables to create									   *
 * Returns: 0 on no errors							   *
 *          mysql error code on failure				   *
 *-----------------------------------------------------*/
int mod_log_mysql_create_tables(request_rec *r, logsql_tabletype table_type, 
								const char *table_name)
{
	int retval;

	char *type_suffix = NULL;

	char *create_prefix = "create table if not exists `";
	char *create_suffix = NULL;
	char *create_sql;

	if (!global_config.createtables) {
		return APR_SUCCESS;
	}

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
       virtual_host varchar(255))";
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
	
	if (global_config.tabletype) {
		type_suffix = apr_pstrcat(r->pool, " TYPE=", 
							global_config.tabletype, NULL);
	}
	/* Find memory long enough to hold the whole CREATE string + \0 */
	create_sql = apr_pstrcat(r->pool, create_prefix, table_name, create_suffix,
						type_suffix, NULL);

	log_error(APLOG_MARK,APLOG_DEBUG,r->server,"create string: %s", create_sql);

  	if ((retval = safe_sql_query(r, create_sql))) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"failed to create table: %s",
			table_name);
	}
	return retval;
}
