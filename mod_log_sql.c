/* $Header: /home/cvs/mod_log_sql/mod_log_sql.c,v 1.11 2004/01/21 04:34:21 urkle Exp $ */
/* --------*
 * DEFINES *
 * --------*/

/* The enduser may wish to modify this */
#define DEBUG

/* The enduser won't modify these */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")

/* ---------*
 * INCLUDES *
 * ---------*/
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

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "mod_log_sql.h"

/* Configuratino Defaults */
#define DEFAULT_TRANSFER_LOG_FMT	"AbHhmRSsTUuv"
#define DEFAULT_NOTES_TABLE_NAME	"notes"
#define DEFAULT_HIN_TABLE_NAME		"headers_in"
#define DEFAULT_HOUT_TABLE_NAME		"headers_out"
#define DEFAULT_COOKIE_TABLE_NAME	"cookies"
#define DEFAULT_PRESERVE_FILE		"/tmp/sql-preserve"

/* -------------*
 * DECLARATIONS *
 * -------------*/

/* Declare ourselves so the configuration routines can find and know us. */
module AP_MODULE_DECLARE_DATA log_sql_module;

/* The contents of these are known 'Apache wide' and are not variable
 * on a per-virtual-server basis.  Every virtual server 'knows' the
 * same versions of these variables.
 */

typedef struct {
	int massvirtual;
	int createtables;
	int forcepreserve;
	char *tabletype;
	char *dbname;
	char *dbhost;
	char *dbuser;
	char *dbpwd;
	char *machid;
	char *socketfile;
	unsigned int tcpport;
	int insertdelayed;
	MYSQL server;
	MYSQL *server_p;
} global_config_t;

static global_config_t global_config;

/* But the contents of this structure will vary by virtual server.
 * This permits each virtual server to vary its configuration slightly
 * for per-server customization.
 *
 * Each child process has its own segregated copy of this structure.
 */
typedef struct {
	apr_array_header_t *transfer_ignore_list;
	apr_array_header_t *transfer_accept_list;
	apr_array_header_t *remhost_ignore_list;
	apr_array_header_t *notes_list;
	apr_array_header_t *hout_list;
	apr_array_header_t *hin_list;
	apr_array_header_t *cookie_list;
	char *notes_table_name;
	char *hout_table_name;
	char *hin_table_name;
	char *cookie_table_name;
	char *transfer_table_name;
	char *transfer_log_format;
	char *preserve_file;
	char *cookie_name;
} logsql_state;


/* -----------------*
 * HELPER FUNCTIONS *
 * -----------------*/

static int safe_create_tables(logsql_state *cls, request_rec *r);

typedef struct {
	char key;					/* item letter character */
	log_sql_item_func *func;	/* its extraction function */
	const char *sql_field_name;	/* its column in SQL */
	int want_orig_default;		/* if it requires the original request prior to internal redirection */
	int string_contents;		/* if it returns a string */
} log_sql_item;

static apr_array_header_t *log_sql_item_list;

/* Registration Function for extract functions */
LOGSQL_DECLARE(void) log_sql_register_item(apr_pool_t *p, char key,
		log_sql_item_func *func, const char *sql_field_name,
		int want_orig_default, int string_contents)
{
	log_sql_item *item = apr_array_push(log_sql_item_list);
	item->key = key;
	item->func = func;
	item->sql_field_name = sql_field_name;
	item->want_orig_default = want_orig_default;
	item->string_contents = string_contents;
}

/* Search through item array */
static inline log_sql_item *log_sql_get_item(char key)
{
	int itr;
	for(itr=0; itr<log_sql_item_list->nelts; itr++) {
		if (((log_sql_item *)log_sql_item_list->elts)[itr].key == key) {
			return &((log_sql_item *)log_sql_item_list->elts)[itr];
		}
	}
	return NULL;
}

/* Include all the extract functions */
#include "functions.h"
#if defined(WITH_APACHE13)
#	include "functions13.h"
#elif defined(WITH_APACHE20)
#	include "functions20.h"
#endif

/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 */
static const char *escape_query(const char *from_str, apr_pool_t *p)
{
	if (!from_str)
		return NULL;
	else {
	  	char *to_str;
		unsigned long length = strlen(from_str);
		unsigned long retval;

		/* Pre-allocate a new string that could hold twice the original, which would only
		 * happen if the whole original string was 'dangerous' characters.
		 */
		to_str = (char *) apr_palloc(p, length * 2 + 1);
		if (!to_str) {
			return from_str;
		}

		if (!global_config.server_p) {
			/* Well, I would have liked to use the current database charset.  mysql is
			 * unavailable, however, so I fall back to the slightly less respectful
			 * mysql_escape_string() function that uses the default charset.
			 */
			retval = mysql_escape_string(to_str, from_str, length);
		} else {
			/* MySQL is available, so I'll go ahead and respect the current charset when
			 * I perform the escape.
			 */
			retval = mysql_real_escape_string(global_config.server_p, to_str, from_str, length);
		}

		if (retval)
		  return to_str;
		else
		  return from_str;
	}
}

static int open_logdb_link(server_rec* s)
{
	/* Returns:
	   3 if preserve forced
	   2 if already connected
	   1 if successful
	   0 if unsuccessful
	*/

	if (global_config.forcepreserve)
		return 3;

	if (global_config.server_p)
		return 2;

	if ((global_config.dbname) && (global_config.dbhost) && (global_config.dbuser) && (global_config.dbpwd)) {
		mysql_init(&global_config.server);
		global_config.server_p = mysql_real_connect(&global_config.server, global_config.dbhost, global_config.dbuser, global_config.dbpwd, global_config.dbname, global_config.tcpport, global_config.socketfile, 0);

		if (global_config.server_p) {
			#ifdef DEBUG
			  log_error(APLOG_MARK,APLOG_DEBUG,s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
			  										global_config.dbhost, global_config.tcpport, global_config.dbname, global_config.dbuser, global_config.socketfile);
			#endif
			return 1;
		} else {
			#ifdef DEBUG
			  log_error(APLOG_MARK,APLOG_DEBUG,s,"mod_log_sql: database connection error: %s",MYSQL_ERROR(&global_config.server));
			  log_error(APLOG_MARK,APLOG_DEBUG,s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
			  										global_config.dbhost, global_config.tcpport, global_config.dbname, global_config.dbuser, global_config.socketfile);
		 	#endif
			return 0;
		}
	} else {
		log_error(APLOG_MARK,APLOG_ERR,s,"mod_log_sql: insufficient configuration info to establish database link");
		return 0;
	}
}

/*static const char *extract_table(void *data, const char *key, const char *val)
{
    request_rec *r = (request_rec *)data;

	return apr_pstrcat(r->pool, key, " = ", val, " ", NULL);
}*/

static void preserve_entry(request_rec *r, const char *query)
{
	logsql_state *cls = ap_get_module_config(r->server->module_config, 
											&log_sql_module);
	#if defined(WITH_APACHE20)
		apr_file_t *fp;
		apr_status_t result;
		result = apr_file_open(&fp, cls->preserve_file,APR_APPEND, APR_OS_DEFAULT, r->pool);
	#elif defined(WITH_APACHE13)
		FILE *fp;
		int result;
		fp = ap_pfopen(r->pool, cls->preserve_file, "a");
		result = (fp)?0:1;
	#endif
	if (result != APR_SUCCESS) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: attempted append of local preserve file but failed.");
	} else {
		#if defined(WITH_APACHE20)
			apr_file_printf(fp,"%s;\n", query);
			apr_file_close(fp);
		#elif defined(WITH_APACHE13)
			fprintf(fp,"%s;\n", query);
			ap_pfclose(r->pool, fp);
		#endif
		#ifdef DEBUG
		  log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: entry preserved in %s", cls->preserve_file);
		#endif
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
static unsigned int safe_sql_query(request_rec *r, const char *query)
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
	if (global_config.insertdelayed) {
	 real_error_str = MYSQL_ERROR(global_config.server_p);
	} else {
	 real_error = mysql_errno(global_config.server_p);
	}

	/* Check to see if the error is "nonexistent table" */
	if (global_config.insertdelayed) {
		retval = (strstr(real_error_str, "Table")) && (strstr(real_error_str,"doesn't exist"));
	} else {
		retval = (real_error == ER_NO_SUCH_TABLE);
	}
	if (retval) {
		if (global_config.createtables) {
			log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: table doesn't exist...creating now");
			cls = ap_get_module_config(r->server->module_config, &log_sql_module);
			if (safe_create_tables(cls, r)) {
				log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: child attempted but failed to create one or more tables for %s, preserving query", ap_get_server_name(r));
				preserve_entry(r, query);
				retval = mysql_errno(global_config.server_p);
			} else {
				log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: tables successfully created - retrying query");
				if (mysql_query(global_config.server_p, query)) {
					log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: giving up, preserving query");
					preserve_entry(r, query);
					retval = mysql_errno(global_config.server_p);
				} else
					log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: query successful after table creation");
					retval = 0;
			}
		} else {
			log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql, table doesn't exist, creation denied by configuration, preserving query");
			preserve_entry(r, query);
			retval = ER_NO_SUCH_TABLE;
		}
		/* Restore SIGPIPE to its original handler function */
		signal(SIGPIPE, handler);
		return retval;
	}

	/* Handle all other types of errors */

	cls = ap_get_module_config(r->server->module_config, &log_sql_module);

	/* Something went wrong, so start by trying to restart the db link. */
	if (global_config.insertdelayed) {
	 real_error = 2;
	} else {
	 real_error = mysql_errno(global_config.server_p);
	}

	log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: first attempt failed, API said: error %d, \"%s\"", real_error, MYSQL_ERROR(global_config.server_p));
	mysql_close(global_config.server_p);
	global_config.server_p = NULL;
	open_logdb_link(r->server);

	if (global_config.server_p == NULL) {	 /* still unable to link */
		signal(SIGPIPE, handler);
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: reconnect failed, unable to reach database. SQL logging stopped until child regains a db connection.");
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: log entries are being preserved in %s", cls->preserve_file);
		return 1;
	} else
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: db reconnect successful");

	/* First sleep for a tiny amount of time. */
	delay.tv_sec = 0;
	delay.tv_nsec = 250000000;  /* max is 999999999 (nine nines) */
	ret = nanosleep(&delay, &remainder);
	if (ret && errno != EINTR)
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: nanosleep unsuccessful");

	/* Then make our second attempt */
	retval = mysql_query(global_config.server_p,query);

	/* If this one also failed, log that and append to our local offline file */
	if (retval)	{
		if (global_config.insertdelayed) {
		 real_error = 2;
		} else {
		 real_error = mysql_errno(global_config.server_p);
		}

		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: second attempt failed, API said: error %d, \"%s\" -- preserving", real_error, MYSQL_ERROR(global_config.server_p));
		preserve_entry(r, query);
		retval = real_error;
	} else
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: second attempt successful");

	/* Restore SIGPIPE to its original handler function */
	signal(SIGPIPE, handler);
	return retval;
}

/*-----------------------------------------------------*
 * safe_create_tables: create SQL table set for the    *
 * virtual server represented by cls.                  *
 *                                                     *
 * Parms:   virtserver structure, request record       *
 * Returns: 0 on no errors							   *
 *          mysql error code on failure				   *
 *-----------------------------------------------------*/
static int safe_create_tables(logsql_state *cls, request_rec *r)
{
	int retval;
	unsigned int create_results;
	char *create_access = NULL;
	char *create_notes = NULL;
	char *create_hout = NULL;
	char *create_hin = NULL;
	char *create_cookies = NULL;

	char *type_suffix = NULL;

	char *createprefix = "create table if not exists `";
	char *access_suffix =
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

	char *notes_suffix =
	 "` (id char(19),\
	   item varchar(80),\
	   val varchar(80))";

	char *headers_suffix =
	 "` (id char(19),\
	   item varchar(80),\
       val varchar(80))";

   	char *cookies_suffix =
	 "` (id char(19),\
	   item varchar(80),\
       val varchar(80))";
	if (global_config.tabletype) {
		type_suffix = apr_pstrcat(r->pool, " TYPE=", global_config.tabletype, NULL);
	}
	/* Find memory long enough to hold the whole CREATE string + \0 */
	create_access = apr_pstrcat(r->pool, createprefix, cls->transfer_table_name, access_suffix, type_suffix, NULL);
	create_notes  = apr_pstrcat(r->pool, createprefix, cls->notes_table_name, notes_suffix, type_suffix, NULL);
	create_hout   = apr_pstrcat(r->pool, createprefix, cls->hout_table_name, headers_suffix, type_suffix, NULL);
	create_hin    = apr_pstrcat(r->pool, createprefix, cls->hin_table_name, headers_suffix, type_suffix, NULL);
	create_cookies= apr_pstrcat(r->pool, createprefix, cls->cookie_table_name, cookies_suffix, type_suffix, NULL);

	#ifdef DEBUG
		log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: create string: %s", create_access);
		log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: create string: %s", create_notes);
		log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: create string: %s", create_hout);
		log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: create string: %s", create_hin);
		log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: create string: %s", create_cookies);
	#endif

	/* Assume that things worked unless told otherwise */
	retval = 0;

  	if ((create_results = safe_sql_query(r, create_access))) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: failed to create access table");
		retval = create_results;
	}

	if ((create_results = safe_sql_query(r, create_notes))) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: failed to create notes table");
		retval = create_results;
	}

	if ((create_results = safe_sql_query(r, create_hin))) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: failed to create header_in table");
		retval = create_results;
	}

	if ((create_results = safe_sql_query(r, create_hout))) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: failed to create header_out table");
		retval = create_results;
	}

	if ((create_results = safe_sql_query(r, create_cookies))) {
		log_error(APLOG_MARK,APLOG_ERR,r->server,"mod_log_sql: failed to create cookies table");
		retval = create_results;
	}

	return retval;
}

/* ------------------------------------------------*
 * Command handlers that are called according      *
 * to the directives found at Apache runtime.      *
 * ------------------------------------------------*/


static const char *set_global_flag_slot(cmd_parms *cmd, 
										void *struct_ptr, 
										int flag)
{
	void *ptr = &global_config;
	int offset = (int)(long)cmd->info;

	*(int *)((char *)ptr + offset) = flag ? 1 : 0;

    return NULL;
}

static const char *set_global_nmv_flag_slot(cmd_parms *cmd,
											void *struct_ptr,
											int flag)
{
	if (global_config.massvirtual) {
		return apr_psprintf(cmd->pool,
			"mod_log_sql: do not set %s when LogSQLMassVirtualHosting(%d) is On.%d:%d",
			cmd->cmd->name, global_config.massvirtual,
				(int)(long)&global_config, (int)(long)struct_ptr);
	} else {
		return set_global_flag_slot(cmd,struct_ptr,flag);
	}
}

static const char *set_global_string_slot(cmd_parms *cmd,
                                    	  void *struct_ptr,
                                     	  const char *arg)
{
	void *ptr = &global_config;
	int offset = (int)(long)cmd->info;

    *(const char **)((char *)ptr + offset) = apr_pstrdup(cmd->pool,arg);
    return NULL;
}

static const char *set_server_string_slot(cmd_parms *cmd,
                                     		 void *struct_ptr,
                                     		 const char *arg)
{
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&log_sql_module);
	int offset = (int)(long)cmd->info;

	*(const char **)((char *)ptr + offset) = arg;
    
    return NULL;
}


static const char *set_server_nmv_string_slot(cmd_parms *parms,
											void *struct_ptr,
											const char *arg)
{
	if (global_config.massvirtual)
		return apr_psprintf(parms->pool,
			"mod_log_sql: do not set %s when LogSQLMassVirtualHosting is On.",
			parms->cmd->name);
	else
		return set_server_string_slot(parms,struct_ptr,arg);
}

static const char *set_log_sql_info(cmd_parms *cmd, void *dummy, const char *host, const char *user, const char *pwd)
{
	if (*host != '.') {
		global_config.dbhost = apr_pstrdup(cmd->pool,host);
	}
	if (*user != '.') {
		global_config.dbuser = apr_pstrdup(cmd->pool,user);
	}
	if (*pwd != '.') {
		global_config.dbpwd = apr_pstrdup(cmd->pool,pwd);
	}
	return NULL;
}

static const char *add_server_string_slot(cmd_parms *cmd,
                                     		 void *struct_ptr,
                                     		 const char *arg)
{
	char **addme;
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&log_sql_module);
	int offset = (int)(long)cmd->info;
	apr_array_header_t *ary = *(apr_array_header_t **)((apr_array_header_t *)ptr + offset);

	addme = apr_array_push(ary);
	*addme = apr_pstrdup(ary->pool, arg);
	    
    return NULL;
}

static const char *set_log_sql_tcp_port(cmd_parms *parms, void *dummy, const char *arg)
{
	global_config.tcpport = (unsigned int)atoi(arg);

	return NULL;
}

/*------------------------------------------------------------*
 * Apache-specific hooks into the module code                 *
 * that are defined in the array 'mysql_lgog_module' (at EOF) *
 *------------------------------------------------------------*/
/* Closing mysql link: child_exit(1.3), pool registration(2.0) */
#if defined(WITH_APACHE20)
static apr_status_t log_sql_close_link(void *data)
{
	mysql_close(global_config.server_p);
	return APR_SUCCESS;
}
#elif defined(WITH_APACHE13)
static void log_sql_child_exit(server_rec *s, apr_pool_t *p)
{
	mysql_close(global_config.server_p);
}
#endif

/* Child Init */
#if defined(WITH_APACHE20)
static void log_sql_child_init(apr_pool_t *p, server_rec *s)
{
	apr_pool_cleanup_register(p, NULL, log_sql_close_link, log_sql_close_link);
}

static int log_sql_open(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt, server_rec *s)
#elif defined(WITH_APACHE13)
static void log_sql_child_init(server_rec *s, apr_pool_t *p)
#endif
{
	int retval;
		/* Open a link to the database */
	retval = open_logdb_link(s);
	if (!retval)
		log_error(APLOG_MARK,APLOG_ERR,s,"mod_log_sql: child spawned but unable to open database link");

	#ifdef DEBUG
	if ( (retval == 1) || (retval == 2) )
		log_error(APLOG_MARK,APLOG_DEBUG,s,"mod_log_sql: open_logdb_link successful");
	if (retval == 3)
 		log_error(APLOG_MARK,APLOG_DEBUG,s,"mod_log_sql: open_logdb_link said that preservation is forced");
	#endif
#if defined(WITH_APACHE20)
	return OK;
#endif
}
/*
void *log_sql_initializer(server_rec *main_server, apr_pool_t *p)
{
	server_rec *s;

    logsql_state main_conf = ap_get_module_config(main_server->module_config, &log_sql_module);

	for (server_rec *s = main_server; s; s = s->next) {
	    conf = ap_get_module_config(s->module_config, &log_sql_module);
	    if (conf->transfer_log_format == NULL && s != main_server) {
	        *conf = *main_conf;
		}

}
 */

#if defined(WITH_APACHE20)
static int log_sql_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
#elif defined(WITH_APACHE13)
static void log_sql_module_init(server_rec *s, apr_pool_t *p)
#endif
{
	/* Initialize Global configuration */
	if (!global_config.socketfile)
		global_config.socketfile = "/tmp/mysql.sock";
	if (!global_config.tcpport)
		global_config.tcpport = 3306;
	if (!log_sql_item_list)
		log_sql_item_list = apr_array_make(p,10,sizeof(log_sql_item));

	/* Register handlers */
	log_sql_register_item(p,'A', extract_agent,             "agent",            1, 1);
	log_sql_register_item(p,'a', extract_request_args,      "request_args",     1, 1);
	log_sql_register_item(p,'b', extract_bytes_sent,        "bytes_sent",       0, 0);
    log_sql_register_item(p,'c', extract_cookie,            "cookie",           0, 1);
    log_sql_register_item(p,'e', extract_env_var,           "env_var",          0, 1);
    log_sql_register_item(p,'f', extract_request_file,      "request_file",     0, 1);
	log_sql_register_item(p,'H', extract_request_protocol,  "request_protocol", 0, 1);
	log_sql_register_item(p,'h', extract_remote_host,       "remote_host",      0, 1);
	log_sql_register_item(p,'I', extract_unique_id,         "id",               0, 1);
	log_sql_register_item(p,'l', extract_remote_logname,    "remote_logname",   0, 1);
	log_sql_register_item(p,'m', extract_request_method,    "request_method",   0, 1);
	log_sql_register_item(p,'M', extract_machine_id,        "machine_id",       0, 1);
	log_sql_register_item(p,'P', extract_child_pid,         "child_pid",        0, 0);
	log_sql_register_item(p,'p', extract_server_port,       "server_port",      0, 0);
	log_sql_register_item(p,'R', extract_referer,           "referer",          1, 1);
	log_sql_register_item(p,'r', extract_request_line,      "request_line",     1, 1);
	log_sql_register_item(p,'S', extract_request_timestamp, "time_stamp",       0, 0);
	log_sql_register_item(p,'s', extract_status,            "status",           1, 0);
	log_sql_register_item(p,'T', extract_request_duration,  "request_duration", 1, 0);
	log_sql_register_item(p,'t', extract_request_time,      "request_time",     0, 1);
	log_sql_register_item(p,'u', extract_remote_user,       "remote_user",      0, 1);
	log_sql_register_item(p,'U', extract_request_uri,       "request_uri",      1, 1);
	log_sql_register_item(p,'v', extract_virtual_host,      "virtual_host",     0, 1);

#if defined(WITH_APACHE20)
	return OK;
#endif
}

/*
 * This function gets called to create a per-server configuration
 * record.  It will always be called for the main server and
 * for each virtual server that is established.  Each server maintains
 * its own state that is separate from the others' states.
 *
 * The return value is a pointer to the created module-specific
 * structure.
 */
static void *log_sql_make_state(apr_pool_t *p, server_rec *s)
{
	logsql_state *cls = (logsql_state *) apr_pcalloc(p, sizeof(logsql_state));

	/* These defaults are overridable in the httpd.conf file. */
	cls->transfer_log_format = DEFAULT_TRANSFER_LOG_FMT;
	cls->notes_table_name = DEFAULT_NOTES_TABLE_NAME;
	cls->hin_table_name = DEFAULT_HIN_TABLE_NAME;
	cls->hout_table_name = DEFAULT_HOUT_TABLE_NAME;
	cls->cookie_table_name = DEFAULT_COOKIE_TABLE_NAME;
	cls->preserve_file = DEFAULT_PRESERVE_FILE;

	cls->transfer_ignore_list = apr_array_make(p, 1, sizeof(char *));
	cls->transfer_accept_list = apr_array_make(p, 1, sizeof(char *));
	cls->remhost_ignore_list  = apr_array_make(p, 1, sizeof(char *));
	cls->notes_list           = apr_array_make(p, 1, sizeof(char *));
	cls->hin_list             = apr_array_make(p, 1, sizeof(char *));
	cls->hout_list            = apr_array_make(p, 1, sizeof(char *));
	cls->cookie_list          = apr_array_make(p, 1, sizeof(char *));

	return (void *) cls;
}

static void *log_sql_merge_state(apr_pool_t *p, void *basev, void *addv)
{
	/* Fetch the two states to merge */
	logsql_state *parent = (logsql_state *) basev;
	logsql_state *child = (logsql_state *) addv;

	/* Child can override these, otherwise they default to parent's choice.
	 * If the parent didn't set them, create reasonable defaults for the
	 * ones that should have such default settings.  Leave the others null. */

	child->transfer_table_name = child->transfer_table_name ?
				child->transfer_table_name : parent->transfer_table_name;
	/* No default for transfer_table_name because we want its absence
	 * to disable logging. */

	if (child->transfer_log_format == DEFAULT_TRANSFER_LOG_FMT)
		child->transfer_log_format = parent->transfer_log_format;

	if (child->preserve_file == DEFAULT_PRESERVE_FILE)
		child->preserve_file = parent->preserve_file;

	if (child->notes_table_name == DEFAULT_NOTES_TABLE_NAME)
		child->notes_table_name = parent->notes_table_name;

	if (child->hin_table_name == DEFAULT_HIN_TABLE_NAME)
		child->hin_table_name = parent->hin_table_name;

	if (child->hout_table_name == DEFAULT_HOUT_TABLE_NAME)
		child->hout_table_name = parent->hout_table_name;

	if (child->cookie_table_name == DEFAULT_COOKIE_TABLE_NAME)
		child->cookie_table_name = parent->cookie_table_name;

	if (apr_is_empty_array(child->transfer_ignore_list))
		apr_array_cat(child->transfer_ignore_list, parent->transfer_ignore_list);

	if (apr_is_empty_array(child->transfer_accept_list))
		apr_array_cat(child->transfer_accept_list, parent->transfer_accept_list);

	if (apr_is_empty_array(child->remhost_ignore_list))
		apr_array_cat(child->remhost_ignore_list, parent->remhost_ignore_list);

	if (apr_is_empty_array(child->notes_list))
		apr_array_cat(child->notes_list, parent->notes_list);

	if (apr_is_empty_array(child->hin_list))
		apr_array_cat(child->hin_list, parent->hin_list);

	if (apr_is_empty_array(child->hout_list))
		apr_array_cat(child->hout_list, parent->hout_list);

	if (apr_is_empty_array(child->cookie_list))
		apr_array_cat(child->cookie_list, parent->cookie_list);

	if (!child->cookie_name)
		child->cookie_name = parent->cookie_name;

	return (void*) child;
}

/* Routine to perform the actual construction and execution of the relevant
 * INSERT statements.
 */
static int log_sql_transaction(request_rec *orig)
{
	char **ptrptr, **ptrptr2;
	logsql_state *cls = ap_get_module_config(orig->server->module_config, &log_sql_module);
	const char *access_query;
	request_rec *r;
	char *transfer_tablename = cls->transfer_table_name;
	char *notes_tablename = cls->notes_table_name;
	char *hout_tablename = cls->hout_table_name;
	char *hin_tablename = cls->hin_table_name;
	char *cookie_tablename = cls->cookie_table_name;

	/* We handle mass virtual hosting differently.  Dynamically determine the name
	 * of the table from the virtual server's name, and flag it for creation.
	 */
	if (global_config.massvirtual) {
		/* TODO: Make these configurable? */
		char *access_base = "access_";
		char *notes_base  = "notes_";
		char *hout_base   = "headout_";
		char *hin_base    = "headin_";
		char *cookie_base = "cookies_";


		/* Determint the hostname and convert it to all lower-case; */
		char *servername = apr_pstrdup(orig->pool,(char *)ap_get_server_name(orig));
		char *p=servername;
		while (*p) {
			*p = apr_tolower(*p);
			if (*p == '.') *p = '_';
			++p;
		}
		
		/* Find memory long enough to hold the table name + \0. */
		transfer_tablename = apr_pstrcat(orig->pool, access_base, servername, NULL);
		notes_tablename = apr_pstrcat(orig->pool, notes_base,  servername, NULL);
		hin_tablename = apr_pstrcat(orig->pool, hin_base,    servername, NULL);
		hout_tablename = apr_pstrcat(orig->pool, hout_base,   servername, NULL);
		cookie_tablename = apr_pstrcat(orig->pool, cookie_base, servername, NULL);

		/* Tell this virtual server its transfer table name, and
		 * turn on create_tables, which is implied by massvirtual.
		 */
		
		global_config.createtables = 1;
	}

	/* Do we have enough info to log? */
	if (!transfer_tablename) {
		return DECLINED;
	} else {
		const char *thehost;
		const char *theitem;
		char *fields = "", *values = "";
		char *itemsets = "";
		char *note_query = NULL;
		char *hin_query = NULL;
		char *hout_query = NULL;
		char *cookie_query = NULL;
		const char *unique_id;
		const char *formatted_item;
		char *s;
		int i;
		int proceed;

		for (r = orig; r->next; r = r->next) {
			continue;
		}

		/* The following is a stolen upsetting mess of pointers, I'm sorry.
		 * Anyone with the motiviation and/or the time should feel free
		 * to make this cleaner. :) */
		ptrptr2 = (char **) (cls->transfer_accept_list->elts + (cls->transfer_accept_list->nelts * cls->transfer_accept_list->elt_size));

		/* Go through each element of the accept list and compare it to the
		 * request_uri.  If we don't get a match, return without logging */
		if ((r->uri) && (cls->transfer_accept_list->nelts)) {
			proceed = 0;
			for (ptrptr = (char **) cls->transfer_accept_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->transfer_accept_list->elt_size))
				if (strstr(r->uri, *ptrptr)) {
					proceed = 1;
					break;
				}
			if (!proceed)
				return OK;
		}

		/* Go through each element of the ignore list and compare it to the
		 * request_uri.  If we get a match, return without logging */
		ptrptr2 = (char **) (cls->transfer_ignore_list->elts + (cls->transfer_ignore_list->nelts * cls->transfer_ignore_list->elt_size));
		if (r->uri) {
			for (ptrptr = (char **) cls->transfer_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->transfer_ignore_list->elt_size))
				if (strstr(r->uri, *ptrptr)) {
					return OK;
				}
		}

		/* Go through each element of the ignore list and compare it to the
		 * remote host.  If we get a match, return without logging */
		ptrptr2 = (char **) (cls->remhost_ignore_list->elts + (cls->remhost_ignore_list->nelts * cls->remhost_ignore_list->elt_size));
		thehost = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
		if (thehost) {
			for (ptrptr = (char **) cls->remhost_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->remhost_ignore_list->elt_size))
				if (strstr(thehost, *ptrptr)) {
					return OK;
				}
		}


		/* Iterate through the format characters and set up the INSERT string according to
		 * what the user has configured. */
		i = 0;
		for (s = cls->transfer_log_format; *s != '\0' ; s++) {
			log_sql_item *item = log_sql_get_item(*s);

			/* Yes, this key is one of the configured keys.
			 * Call the key's function and put the returned value into 'formatted_item' */
			formatted_item = item->func(item->want_orig_default ? orig : r, "");

			/* Massage 'formatted_item' for proper SQL eligibility... */
			if (!formatted_item) {
				formatted_item = "";
			} else if (formatted_item[0] == '-' && formatted_item[1] == '\0' && !item->string_contents) {
				/* If apache tried to log a '-' character for a numeric field, convert that to a zero
				 * because the database expects a numeral and will reject the '-' character. */
				formatted_item = "0";
			}

		     /* Append the fieldname and value-to-insert to the appropriate strings, quoting stringvals with ' as appropriate */
			fields = apr_pstrcat(r->pool, fields, (i ? "," : ""),
						 item->sql_field_name, NULL);
			values = apr_pstrcat(r->pool, values, (i ? "," : ""),
						 (item->string_contents ? "'" : ""),
					     escape_query(formatted_item, r->pool),
						 (item->string_contents ? "'" : ""), NULL);
			i = 1;
		}

		/* Work through the list of notes defined by LogSQLWhichNotes */
		i = 0;
		unique_id = extract_unique_id(r, "");

		ptrptr2 = (char **) (cls->notes_list->elts + (cls->notes_list->nelts * cls->notes_list->elt_size));
		for (ptrptr = (char **) cls->notes_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->notes_list->elt_size)) {
			/* If the specified note (*ptrptr) exists for the current request... */
		    if ((theitem = apr_table_get(r->notes, *ptrptr))) {
				itemsets = apr_pstrcat(r->pool, itemsets,
									  (i > 0 ? "," : ""),
									  "('",
									  unique_id,
									  "','",
									  escape_query(*ptrptr, r->pool),
									  "','",
									  escape_query(theitem, r->pool),
									  "')",
									  NULL);
				i++;
			}
		}
		if ( itemsets != "" ) {
			note_query = apr_psprintf(r->pool, "insert %s into `%s` (id, item, val) values %s",
				global_config.insertdelayed?"delayed":"", notes_tablename, itemsets);

			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,orig->server,"mod_log_sql: note string: %s", note_query);
		   	#endif
		}

		/* Work through the list of headers-out defined by LogSQLWhichHeadersOut*/
		i = 0;
		itemsets = "";

		ptrptr2 = (char **) (cls->hout_list->elts + (cls->hout_list->nelts * cls->hout_list->elt_size));
		for (ptrptr = (char **) cls->hout_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->hout_list->elt_size)) {
			/* If the specified header (*ptrptr) exists for the current request... */
		    if ((theitem = apr_table_get(r->headers_out, *ptrptr))) {
				itemsets = apr_pstrcat(r->pool, itemsets,
									  (i > 0 ? "," : ""),
									  "('",
									  unique_id,
									  "','",
									  escape_query(*ptrptr, r->pool),
									  "','",
									  escape_query(theitem, r->pool),
									  "')",
									  NULL);
				i++;
			}
		}
		if ( itemsets != "" ) {
			hout_query = apr_psprintf(r->pool, "insert %s into `%s` (id, item, val) values %s",
				global_config.insertdelayed?"delayed":"", hout_tablename, itemsets);

			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,orig->server,"mod_log_sql: header_out string: %s", hout_query);
		   	#endif
		}


		/* Work through the list of headers-in defined by LogSQLWhichHeadersIn */
		i = 0;
		itemsets = "";

		ptrptr2 = (char **) (cls->hin_list->elts + (cls->hin_list->nelts * cls->hin_list->elt_size));
		for (ptrptr = (char **) cls->hin_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->hin_list->elt_size)) {
			/* If the specified header (*ptrptr) exists for the current request... */
		    if ((theitem = apr_table_get(r->headers_in, *ptrptr))) {
				itemsets = apr_pstrcat(r->pool, itemsets,
									  (i > 0 ? "," : ""),
									  "('",
									  unique_id,
									  "','",
									  escape_query(*ptrptr, r->pool),
									  "','",
									  escape_query(theitem, r->pool),
									  "')",
									  NULL);
				i++;
			}
		}
		if ( itemsets != "" ) {
			hin_query = apr_psprintf(r->pool, "insert %s into `%s` (id, item, val) values %s",
				global_config.insertdelayed?"delayed":"", hin_tablename, itemsets);

			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,orig->server,"mod_log_sql: header_in string: %s", hin_query);
		   	#endif
		}


		/* Work through the list of cookies defined by LogSQLWhichCookies */
		i = 0;
		itemsets = "";

		ptrptr2 = (char **) (cls->cookie_list->elts + (cls->cookie_list->nelts * cls->cookie_list->elt_size));
		for (ptrptr = (char **) cls->cookie_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->cookie_list->elt_size)) {
			/* If the specified cookie (*ptrptr) exists for the current request... */
		    if ( strncmp((theitem = extract_specific_cookie(r, *ptrptr)), "-", 1) ) {
				itemsets = apr_pstrcat(r->pool, itemsets,
									  (i > 0 ? "," : ""),
									  "('",
									  unique_id,
									  "','",
									  escape_query(*ptrptr, r->pool),
									  "','",
									  escape_query(theitem, r->pool),
									  "')",
									  NULL);
				i++;
			}

		}
		if ( itemsets != "" ) {
			cookie_query = apr_psprintf(r->pool, "insert %s into `%s` (id, item, val) values %s",
				global_config.insertdelayed?"delayed":"", cookie_tablename, itemsets);

			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,orig->server,"mod_log_sql: cookie string: %s", cookie_query);
		   	#endif
		}


		/* Set up the actual INSERT statement */
		access_query = apr_psprintf(r->pool, "insert %s into `%s` (%s) values (%s)",
			global_config.insertdelayed?"delayed":"", transfer_tablename, fields, values);

		#ifdef DEBUG
	        log_error(APLOG_MARK,APLOG_DEBUG,r->server,"mod_log_sql: access string: %s", access_query);
	    #endif

		/* If the person activated force-preserve, go ahead and push all the entries
		 * into the preserve file, then return.
		 */
		if (global_config.forcepreserve) {
			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,orig->server,"mod_log_sql: preservation forced");
		   	#endif
			preserve_entry(orig, access_query);
			if ( note_query != NULL )
				preserve_entry(orig, note_query);
			if ( hin_query != NULL )
			  	preserve_entry(orig, hin_query);
			if ( hout_query != NULL )
			  	preserve_entry(orig, hout_query);
			if ( cookie_query != NULL )
			  	preserve_entry(orig, cookie_query);
			return OK;
		}

		/* How's our mysql link integrity? */
		if (global_config.server_p == NULL) {

			/* Make a try to establish the link */
			open_logdb_link(r->server);

			if (global_config.server_p == NULL) {
				/* Unable to re-establish a DB link, so assume that it's really
				 * gone and send the entry to the preserve file instead.
				 * This short-circuits safe_sql_query() during a db outage and therefore
				 * we don't keep logging the db error over and over.
				 */
				preserve_entry(orig, access_query);
				if ( note_query != NULL )
					preserve_entry(orig, note_query);
				if ( hin_query != NULL )
				  	preserve_entry(orig, hin_query);
				if ( hout_query != NULL )
				  	preserve_entry(orig, hout_query);
				if ( cookie_query != NULL )
				  	preserve_entry(orig, cookie_query);

				return OK;
			} else {
				/* Whew, we got the DB link back */
				log_error(APLOG_MARK,APLOG_NOTICE,orig->server,"mod_log_sql: child established database connection");
			}
		}


		/* ---> So as of here we have a non-null value of mysql_log. <--- */
		/* ---> i.e. we have a good MySQL connection.                <--- */

  	    /* Make the access-table insert */
		safe_sql_query(orig, access_query);

		/* Log the optional notes, headers, etc. */
		if (note_query)
			safe_sql_query(orig, note_query);

		if (hout_query)
		  	safe_sql_query(orig, hout_query);

		if (hin_query)
		  	safe_sql_query(orig, hin_query);

		if (cookie_query)
		  	safe_sql_query(orig, cookie_query);

		return OK;
	}
}


/* Setup of the available httpd.conf configuration commands.
 * Structure: command, function called, NULL, where available, how many arguments, verbose description
 */
static const command_rec log_sql_cmds[] = {
	AP_INIT_TAKE1("LogSQLTransferLogTable", set_server_nmv_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, transfer_table_name), RSRC_CONF, 
	 "The database table that holds the transfer log")
	,
	AP_INIT_TAKE1("LogSQLNotesLogTable", set_server_nmv_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, notes_table_name), RSRC_CONF,
	 "The database table that holds the notes")
	,
	AP_INIT_TAKE1("LogSQLHeadersOutLogTable", set_server_nmv_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, hout_table_name), RSRC_CONF,
	 "The database table that holds the outbound headers")
	,
	AP_INIT_TAKE1("LogSQLHeadersInLogTable", set_server_nmv_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, hin_table_name), RSRC_CONF,
	 "The database table that holds the inbound headers")
	,
	AP_INIT_TAKE1("LogSQLCookieLogTable", set_server_nmv_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, cookie_table_name), RSRC_CONF,
	 "The database table that holds the cookie info")
	,
	AP_INIT_TAKE1("LogSQLTransferLogFormat", set_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state,transfer_log_format), RSRC_CONF,
	 "Instruct the module what information to log to the database transfer log")
	,
	AP_INIT_TAKE1("LogSQLMachineID", set_global_string_slot,
	 (void *)APR_OFFSETOF(global_config_t, machid), RSRC_CONF,
	 "Machine ID that the module will log, useful in web clusters to differentiate machines")
	,
	AP_INIT_ITERATE("LogSQLRequestAccept", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, transfer_accept_list), RSRC_CONF,
	 "List of URIs to accept for logging. Accesses that don't match will not be logged")
	,
	AP_INIT_ITERATE("LogSQLRequestIgnore", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, transfer_ignore_list), RSRC_CONF,
	 "List of URIs to ignore. Accesses that match will not be logged to database")
	,
	AP_INIT_ITERATE("LogSQLRemhostIgnore", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, remhost_ignore_list), RSRC_CONF,
	 "List of remote hosts to ignore. Accesses that match will not be logged to database")
	,
	AP_INIT_TAKE1("LogSQLDatabase", set_global_string_slot, 
	 (void *)APR_OFFSETOF(global_config_t, dbname), RSRC_CONF,
	 "The name of the database database for logging")
	,
	AP_INIT_TAKE1("LogSQLWhichCookie", set_server_string_slot, 
	 (void *)APR_OFFSETOF(logsql_state, cookie_name), RSRC_CONF,
	 "The single cookie that you want logged in the access_log when using the 'c' config directive")
	,
	AP_INIT_TAKE3("LogSQLLoginInfo", set_log_sql_info, NULL, RSRC_CONF,
	 "The database host, user-id and password for logging")
	,
	AP_INIT_FLAG("LogSQLCreateTables", set_global_nmv_flag_slot, 
	 (void *)APR_OFFSETOF(global_config_t, createtables), RSRC_CONF,
	 "Turn on module's capability to create its SQL tables on the fly")
	,
	AP_INIT_FLAG("LogSQLMassVirtualHosting", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, massvirtual), RSRC_CONF,
	 "Activates option(s) useful for ISPs performing mass virutal hosting")
	,
	AP_INIT_FLAG("LogSQLDelayedInserts", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, insertdelayed), RSRC_CONF,
	 "Whether to use delayed inserts")
	,
	AP_INIT_FLAG("LogSQLForcePreserve", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, forcepreserve), RSRC_CONF,
	 "Forces logging to preserve file and bypasses database")
	,
	AP_INIT_TAKE1("LogSQLPreserveFile", set_global_string_slot,
	 (void *)APR_OFFSETOF(logsql_state,preserve_file), RSRC_CONF,
	 "Name of the file to use for data preservation during database downtime")
	,
	AP_INIT_TAKE1("LogSQLSocketFile", set_global_string_slot,
	 (void *)APR_OFFSETOF(global_config_t, socketfile), RSRC_CONF,
	 "Name of the file to employ for socket connections to database")
	,
	AP_INIT_TAKE1("LogSQLTableType", set_global_string_slot,
	 (void *)APR_OFFSETOF(global_config_t, tabletype), RSRC_CONF,
	 "What kind of table to create (MyISAM, InnoDB,...) when creating tables")
	,
	AP_INIT_TAKE1("LogSQLTCPPort", set_log_sql_tcp_port, NULL, RSRC_CONF,
	 "Port number to use for TCP connections to database, defaults to 3306 if not set")
	,
	AP_INIT_ITERATE("LogSQLWhichNotes", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, notes_list), RSRC_CONF,
	 "Notes that you would like to log in a separate table")
	,
	AP_INIT_ITERATE("LogSQLWhichHeadersOut", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, hout_list), RSRC_CONF,
	 "Outbound headers that you would like to log in a separate table")
	,
	AP_INIT_ITERATE("LogSQLWhichHeadersIn", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, hin_list), RSRC_CONF,
	 "Inbound headers that you would like to log in a separate table")
	,
	AP_INIT_ITERATE("LogSQLWhichCookies", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, cookie_list), RSRC_CONF,
	 "The cookie(s) that you would like to log in a separate table")
	,
	{NULL}
};
/* The configuration array that sets up the hooks into the module. */
#if defined(WITH_APACHE20)
static void register_hooks(apr_pool_t *p) {
	ap_hook_pre_config(log_sql_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
	ap_hook_child_init(log_sql_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_open_logs(log_sql_open, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_log_transaction(log_sql_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA log_sql_module = {
	STANDARD20_MODULE_STUFF,
	NULL,		/* create per-directory config structures */
    NULL,		/* merge per-directory config structures */
    log_sql_make_state,		/* create per-server config structures */
    log_sql_merge_state,		/* merge per-server config structures     */
    log_sql_cmds,	/* command handlers */
    register_hooks	/* register hooks */
};
#elif defined(WITH_APACHE13)
module log_sql_module = {
	STANDARD_MODULE_STUFF,
	log_sql_module_init,	 /* module initializer 				*/
	NULL,					 /* create per-dir config 			*/
	NULL,					 /* merge per-dir config 			*/
	log_sql_make_state,		 /* create server config 			*/
	log_sql_merge_state,	 /* merge server config 			*/
	log_sql_cmds,			 /* config directive table 			*/
	NULL,					 /* [9] content handlers 			*/
	NULL,					 /* [2] URI-to-filename translation */
	NULL,					 /* [5] check/validate user_id 		*/
	NULL,					 /* [6] check authorization 		*/
	NULL,					 /* [4] check access by host		*/
	NULL,					 /* [7] MIME type checker/setter 	*/
	NULL,					 /* [8] fixups 						*/
	log_sql_transaction,	 /* [10] logger 					*/
	NULL					 /* [3] header parser 				*/
#if MODULE_MAGIC_NUMBER >= 19970728 /* 1.3-dev or later support these additionals... */
	,log_sql_child_init,   /* child process initializer 		*/
	log_sql_child_exit,    /* process exit/cleanup 			*/
	NULL					 /* [1] post read-request 			*/
#endif

};
#endif
