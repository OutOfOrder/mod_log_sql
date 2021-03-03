/* $Id:mod_log_sql.c 180 2008-09-21 15:54:12Z urkle@drip.ws $ */

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

#include "autoconfig.h"
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
#define DEFAULT_PRESERVE_FILE		"logs/mod_log_sql-preserve"

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
	int disablepreserve;
	char *machid;
	int announce;
	logsql_dbconnection db;
	logsql_dbdriver *driver;
	/** Show config support */
	char *showconfig;
	apr_file_t *showconfig_fp;
} global_config_t;

static global_config_t global_config;

/* structure to hold helper function info */
typedef struct {
	const char *alias;			/* The function alias */
	logsql_item_func *func;		/* The extraction function pointer */
	int want_orig_req;			/* if it requires the original request prior to internal redirection */
} logsql_function;

/* list of logsql_functions's for log types */
static apr_array_header_t *logsql_function_list;

/* structure to hold sqlfield mappings */
typedef struct {
    const char *alias;			/* long name for item */
    const char *funcalias;		/* The function alias */
	logsql_function *func;		/* its extraction function */
	char *param;				/* Parameter for function */
	const char *sql_field_name;	/* its column in SQL */
	char string_contents;		/* Whether this is a string field or not */
	logsql_field_datatype datatype; /* the field data type */
	apr_size_t size;			/* The size of the data type */
} logsql_field;

/* list of logsql_item's for log types */
static apr_array_header_t *logsql_field_list;

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
	const char *notes_table_name;
	const char *hout_table_name;
	const char *hin_table_name;
	const char *cookie_table_name;
	const char *transfer_table_name;
	apr_array_header_t *transfer_log_format;
	apr_pool_t *parsed_pool;
	logsql_field **parsed_log_format;
	const char *preserve_file;
	const char *cookie_name;
} logsql_state;

/** Registration function for extract functions
 *
 * This functions registers an alias for a function
 *
 * @note This is exported from the module
 */
LOGSQL_DECLARE(void) log_sql_register_function(apr_pool_t *p,
		const char *alias, logsql_item_func *func,
		logsql_function_req want_orig_req)
{
	logsql_function *item;
	if (!logsql_function_list)
		logsql_function_list = apr_array_make(p,10, sizeof(logsql_function));

	item = apr_array_push(logsql_function_list);
	item->alias = alias;
	item->func = func;
	item->want_orig_req = want_orig_req;
	if (global_config.showconfig_fp) {
		apr_file_printf(global_config.showconfig_fp," Function : %s\n",alias);
	}
}
/** Register a old style sql mapping to the new style
 *
 * @note This is exported from the module
 */
LOGSQL_DECLARE(void) log_sql_register_alias(server_rec *s, apr_pool_t *p,
		char key, const char *alias)
{
	server_rec *ts;
	for (ts = s; ts; ts = ts->next) {
		logsql_state *cfg = ap_get_module_config(ts->module_config,
								&log_sql_module);
		int itr;
		for (itr = 0; itr < cfg->transfer_log_format->nelts; itr++) {
			const char *logformat = ((const char **)cfg->transfer_log_format->elts)[itr];
			//log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "Testing Logformat %s against %c for %s",logformat,key,alias);
			// Check if it is only one character AND it is our key
			if (logformat[1]=='\0' && logformat[0]==key) {
				((const char **)cfg->transfer_log_format->elts)[itr] = alias;
			}
		}
	}
}


/** Registration sqlfield aliases to functions
 *
 * And update parse cache for transfer_log_format
 *
 * @note This is exported from the module
 */
LOGSQL_DECLARE(void) log_sql_register_field(apr_pool_t *p,
		const char *alias,
		const char *funcalias, const char *param,
		const char *sql_field_name,
		logsql_field_datatype datatype, apr_size_t size)
{
	logsql_field *item;

	if (!logsql_field_list)
		logsql_field_list = apr_array_make(p,10, sizeof(logsql_field));

	item = apr_array_push(logsql_field_list);
	item->func = NULL;
	item->alias = apr_pstrdup(p, alias);
	item->funcalias = apr_pstrdup(p, funcalias);
	item->param = apr_pstrdup(p, param);
	item->sql_field_name = apr_pstrdup(p,sql_field_name);
	item->datatype = datatype;
	item->string_contents = 0;
	if (datatype == LOGSQL_DATATYPE_CHAR || datatype == LOGSQL_DATATYPE_VARCHAR) {
		item->string_contents = 1;
	}
	item->size = size;
}

/**
 * Links sql field items with their functions
 */
LOGSQL_DECLARE(void) log_sql_register_finish(server_rec *s)
{
	server_rec *ts;
	int itr, f;
	logsql_field *item;
	logsql_function *func;
	for (itr = 0; itr < logsql_field_list->nelts; itr++) {
		item = &((logsql_field *)logsql_field_list->elts)[itr];
		if (item->func) continue;
		/* Find function alias in function list */
		for (f = 0; f < logsql_function_list->nelts; f++) {
			func = &((logsql_function *)logsql_function_list->elts)[f];
			if (strcmp(func->alias,item->funcalias)==0) {
				item->func = func;
				if (global_config.showconfig_fp) {
					apr_file_printf(global_config.showconfig_fp," Item : %s using function %s(%s)\n"
							"\tStoring in field %s of type %s(%"APR_SIZE_T_FMT")\n",
							item->alias, item->funcalias, item->param,
							item->sql_field_name, item->string_contents ? "TEXT":"NUMERIC", item->size);
				}
				break;
			}
		}
		if (!item->func) {
			log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
					"Could not find function %s for item %s",item->funcalias, item->alias);
		}
	}
	/* some voodoo here to post parse logitems in all servers *
	 * so a "cached" list is used in the main logging loop for speed */
	for (ts = s; ts; ts = ts->next) {
		logsql_state *cfg = ap_get_module_config(ts->module_config,
								&log_sql_module);

		if (!cfg->parsed_log_format) {
			cfg->parsed_log_format = apr_pcalloc(cfg->parsed_pool,
					cfg->transfer_log_format->nelts * sizeof(logsql_field *));
		}

		for (itr = 0; itr < cfg->transfer_log_format->nelts; itr++) {
			const char *logformat = ((char **)cfg->transfer_log_format->elts)[itr];
			for (f = 0; f < logsql_field_list->nelts; f++) {
				item = &((logsql_field *)logsql_field_list->elts)[f];
				if (item->func && strcmp(logformat,item->alias)==0) {
					cfg->parsed_log_format[itr] = item;
					break;
				}
			}
		}
	}
}

/* Registration function for database drivers */
LOGSQL_DECLARE(void) log_sql_register_driver(apr_pool_t *p,
		logsql_dbdriver *driver)
{
	global_config.driver = driver;
}

/* Include all the core extract functions */
#include "functions.h"
#if defined(WITH_APACHE13)
#	include "functions13.h"
#elif defined(WITH_APACHE20)
#	include "functions20.h"
#endif

static logsql_opendb_ret log_sql_opendb_link(server_rec* s)
{
	logsql_opendb_ret result;
    if (global_config.driver == NULL) {
        return LOGSQL_OPENDB_FAIL;
    }
	if (global_config.forcepreserve) {
		/*global_config.db.connected = 1;*/
		return LOGSQL_OPENDB_PRESERVE;
	}
	if (global_config.db.connected) {
		return LOGSQL_OPENDB_ALREADY;
	}
	/* database
		host
		user
		passwd
	*/
	if (global_config.db.parms) {
		result = global_config.driver->connect(s, &global_config.db);
		if (result==LOGSQL_OPENDB_FAIL) {
			global_config.db.connected = 0;
		} else {
			global_config.db.connected = 1;
		}
		return result;
	} else {
		log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"mod_log_sql: insufficient configuration info to establish database link");
		return LOGSQL_OPENDB_FAIL;
	}
}

static void preserve_entry(request_rec *r, const char *query)
{
	logsql_state *cls = ap_get_module_config(r->server->module_config,
											&log_sql_module);
	apr_status_t result;
	apr_file_t *fp;

	/* If preserve file is disabled bail out */
	if (global_config.disablepreserve)
       return;
    #if defined(WITH_APACHE20)
		result = apr_file_open(&fp, cls->preserve_file,APR_APPEND | APR_WRITE | APR_CREATE, APR_OS_DEFAULT, r->pool);
    #elif defined(WITH_APACHE13)
		fp = ap_pfopen(r->pool, cls->preserve_file, "a");
		result = (fp)?0:errno;
    #endif
    if (result != APR_SUCCESS) {
		log_error(APLOG_MARK, APLOG_ERR, result, r->server,
			"attempted append of local preserve file '%s' but failed.",cls->preserve_file);
	} else {
		apr_file_printf(fp,"%s;\n", query);
		#if defined(WITH_APACHE20)
			apr_file_close(fp);
		#elif defined(WITH_APACHE13)
			ap_pfclose(r->pool, fp);
		#endif
		log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
			"mod_log_sql: entry preserved in %s", cls->preserve_file);
	}
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

static const char *set_server_file_slot(cmd_parms *cmd,
                                     		 void *struct_ptr,
                                     		 const char *arg)
{
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&log_sql_module);
	int offset = (int)(long)cmd->info;
    const char *path;

    path = ap_server_root_relative(cmd->pool, (char *)arg);

    if (!path) {
        return apr_pstrcat(cmd->pool, "Invalid file path ",
                           arg, NULL);
    }

    *(const char **)((char*)ptr + offset) = path;

    return NULL;
}

static apr_array_header_t *create_logformat_default(apr_pool_t *p)
{
	apr_array_header_t *logformat;
	char **addme;

	logformat = apr_array_make(p, 12, sizeof(char *));
	addme = apr_array_push(logformat); *addme = "useragent";
	addme = apr_array_push(logformat); *addme = "bytes_sent";
	addme = apr_array_push(logformat); *addme = "request_protocol";
	addme = apr_array_push(logformat); *addme = "remote_host";
	addme = apr_array_push(logformat); *addme = "request_method";
	addme = apr_array_push(logformat); *addme = "referer";
	addme = apr_array_push(logformat); *addme = "timestamp";
	addme = apr_array_push(logformat); *addme = "status";
	addme = apr_array_push(logformat); *addme = "request_duration";
	addme = apr_array_push(logformat); *addme = "request_uri";
	addme = apr_array_push(logformat); *addme = "remote_user";
	addme = apr_array_push(logformat); *addme = "virtual_host";
	return logformat;
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

/* Set a DB connection parameter */
static const char *set_dbparam(cmd_parms *cmd,
								void *struct_ptr,
								const char *key,
								const char *val)
{
	if (!global_config.db.parms) {
		global_config.db.parms = apr_table_make(cmd->pool,5);
	}
	apr_table_set(global_config.db.parms,key,val);
	return NULL;
}

static const char *set_dbparam_slot(cmd_parms *cmd,
								void *struct_ptr,
								const char *arg)
{
	const char *param = (char *)cmd->info;
	set_dbparam(cmd,NULL,param,arg);
	return NULL;
}

/* Sets basic connection info */
static const char *set_log_sql_info(cmd_parms *cmd, void *dummy,
						const char *host, const char *user, const char *pwd)
{
	if (!user) { /* user is null, so only one arg passed */
	    /* TODO: to more error checking/force all params to be set */
		apr_uri_t uri;
		apr_uri_parse(cmd->pool, host, &uri);
		if (uri.scheme) {
			set_dbparam(cmd, NULL, "driver", uri.scheme);
		}
		if (uri.hostname) {
			set_dbparam(cmd, NULL, "hostname", uri.hostname);
		}
		if (uri.user) {
			set_dbparam(cmd, NULL, "username", uri.user);
		}
		if (uri.password) {
			set_dbparam(cmd, NULL, "password", uri.password);
		}
		if (uri.port_str) {
			set_dbparam(cmd, NULL, "port", uri.port_str);
		}
		if (uri.path) {
			/* extract Database name */
			char *off = ap_strchr(++uri.path,'/');
			if (off)
				*off='\0';
			set_dbparam(cmd, NULL, "database", uri.path);

		}
	} else {
		if (*host != '.') {
			set_dbparam(cmd, NULL, "hostname", host);
		}
		if (*user != '.') {
			set_dbparam(cmd, NULL, "username", user);
		}
		if (*pwd != '.') {
			set_dbparam(cmd, NULL, "password", pwd);
		}
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
	apr_array_header_t *ary = *(apr_array_header_t **)((char *)ptr + offset);
	addme = apr_array_push(ary);
	*addme = apr_pstrdup(ary->pool, arg);

    return NULL;
}

static const char *set_logformat_slot(cmd_parms *cmd,
                                     		 void *struct_ptr,
                                     		 const char *arg)
{
	const char *t;
	char t2[2] = {'\0','\0'};
	for (t = arg; *t != '\0'; t++) {
		t2[0] = *t;
		add_server_string_slot(cmd, NULL, t2);
	}
    return NULL;
}

static const char *set_register_field(cmd_parms *cmd,
											void *struct_ptr,
											const char *arg)
{
	char *alias, *funcalias, *param, *field, *datatype_s, *size_s;
	logsql_field_datatype datatype;
	apr_size_t size;

	alias = ap_getword_white(cmd->pool, &arg);
	funcalias = ap_getword_white(cmd->pool, &arg);
	param = ap_getword_conf(cmd->pool, &arg);
	field = ap_getword_white(cmd->pool, &arg);
	datatype_s = ap_getword_white(cmd->pool, &arg);
	size_s = ap_getword_white(cmd->pool, &arg);

	if (strcasecmp("VARCHAR",datatype_s)==0) {
		datatype = LOGSQL_DATATYPE_VARCHAR;
	} else if (strcasecmp("INT",datatype_s)==0) {
		datatype = LOGSQL_DATATYPE_INT;
	} else if (strcasecmp("CHAR",datatype_s)==0) {
		datatype = LOGSQL_DATATYPE_CHAR;
	} else if (strcasecmp("SMALLINT",datatype_s)==0) {
		datatype = LOGSQL_DATATYPE_SMALLINT;
	} else if (strcasecmp("BIGINT",datatype_s)==0) {
		datatype = LOGSQL_DATATYPE_BIGINT;
	} else {
		return apr_psprintf(cmd->pool, "Unknown data type %s",datatype_s);
	}

	size = atoi(size_s);

	log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
				"%s, %s, %s, %s, %s(%d), %s(%"APR_SIZE_T_FMT")",
				alias, funcalias, param, field, datatype_s, datatype, size_s, size);

	log_sql_register_field(cmd->pool, alias, funcalias, param,
				field, datatype, size);

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
	if (global_config.driver)
        global_config.driver->disconnect(&global_config.db);
	return APR_SUCCESS;
}
#elif defined(WITH_APACHE13)
static void log_sql_child_exit(server_rec *s, apr_pool_t *p)
{
	if (global_config.driver)
        global_config.driver->disconnect(&global_config.db);
}
#endif

/* Child Init */
#if defined(WITH_APACHE20)
static void log_sql_child_init(apr_pool_t *p, server_rec *s)
#elif defined(WITH_APACHE13)
static void log_sql_child_init(server_rec *s, apr_pool_t *p)
#endif
{
	logsql_opendb_ret retval;
#	if defined(WITH_APACHE20)
	/* Register cleanup hook to close DDB connection (apache 2 doesn't have child_exit) */
	apr_pool_cleanup_register(p, NULL, log_sql_close_link, log_sql_close_link);
#	endif
	/* Open a link to the database */
	retval = log_sql_opendb_link(s);
	switch (retval) {
	case LOGSQL_OPENDB_FAIL:
        if (global_config.driver==NULL) {
            log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "mod_log_sql: Driver module not loaded");
        } else {
            log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "mod_log_sql: child spawned but unable to open database link");
        }
		break;
	case LOGSQL_OPENDB_SUCCESS:
	case LOGSQL_OPENDB_ALREADY:
		log_error(APLOG_MARK,APLOG_DEBUG,0, s,
			"mod_log_sql: open_logdb_link successful");
		break;
	case LOGSQL_OPENDB_PRESERVE:
 		log_error(APLOG_MARK,APLOG_DEBUG, 0, s,
			"mod_log_sql: open_logdb_link said that preservation is forced");
		break;
	}
}

static apr_array_header_t *do_merge_array(apr_array_header_t *parent, apr_array_header_t *child, apr_pool_t *p);

/* post_config / module_init */
#if defined(WITH_APACHE20)
static int log_sql_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
#elif defined(WITH_APACHE13)
static void log_sql_module_init(server_rec *s, apr_pool_t *p)
#endif
{
    server_rec *cur_s;
    const char *default_p = ap_server_root_relative(p, DEFAULT_PRESERVE_FILE);
    apr_array_header_t *parent = NULL;

    if (global_config.showconfig != NULL) {
    	const char *tempfile = ap_server_root_relative(p, global_config.showconfig);
		apr_status_t result;
		#if defined(WITH_APACHE20)
			result = apr_file_open(&global_config.showconfig_fp, tempfile,APR_TRUNCATE | APR_WRITE | APR_CREATE, APR_OS_DEFAULT, p);
		#elif defined(WITH_APACHE13)
			global_config.showconfig_fp = ap_pfopen(p, tempfile, "w");
			result = (fp)?0:errno;
		#endif
	    if (result != APR_SUCCESS) {
			log_error(APLOG_MARK, APLOG_ERR, result, s,
				"attempted open of showconfig file '%s' failed.",tempfile);
			global_config.showconfig_fp = NULL;
		} else {
			#if defined(WITH_APACHE20)
				char temp_time[APR_RFC822_DATE_LEN];
				apr_rfc822_date(temp_time,apr_time_now());
			#elif defined(WITH_APACHE13)
				char *temp_time = ap_get_time());
			#endif
			apr_file_printf(global_config.showconfig_fp,"Mod_log_sql Config dump created on %s\n", temp_time);
		}
    }

    for (cur_s = s; cur_s != NULL; cur_s= cur_s->next) {
	     logsql_state *cls = ap_get_module_config(cur_s->module_config,
								&log_sql_module);
	     /* ap_server_root_relative any default preserve file locations */
         if (cls->preserve_file == DEFAULT_PRESERVE_FILE)
             cls->preserve_file = default_p;

         /* Post-process logformats */
         if (!cur_s->is_virtual) {
	    	 parent = create_logformat_default(p);
	    	 cls->transfer_log_format = do_merge_array(parent, cls->transfer_log_format, p);
	    	 parent = cls->transfer_log_format;
	     } else {
	    	 cls->transfer_log_format = do_merge_array(parent, cls->transfer_log_format, p);
	     }
    }

    /* TODO: Add local_address, remote_address, connection_status */
	/** Register functions */
	/** 	register_function(p, funcname,			func_ptr,				which request_rec); */
	log_sql_register_function(p, "useragent",		extract_agent,			LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "request_args",	extract_request_query,	LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "bytes_sent",		extract_bytes_sent,		LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "cookie",			extract_specific_cookie,LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "request_file",	extract_request_file,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "request_protocol",extract_request_protocol,LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "remote_host",		extract_remote_host,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "unique_id",		extract_unique_id,		LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "remote_logname",	extract_remote_logname,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "request_method",	extract_request_method,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "machine_id",		extract_machine_id,		LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "child_pid",		extract_child_pid,		LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "server_port",		extract_server_port,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "referrer",		extract_referer,		LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "request_line",	extract_request_line,	LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "timestamp",		extract_request_timestamp,LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "status",			extract_status,			LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "request_duration",extract_request_duration,LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "request_time",	extract_request_time,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "remote_user",		extract_remote_user,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "request_uri",		extract_request_uri,	LOGSQL_FUNCTION_REQ_ORIG);
    log_sql_register_function(p, "virtual_host",	extract_virtual_host,	LOGSQL_FUNCTION_REQ_FINAL);
    log_sql_register_function(p, "server_name",		extract_server_name,	LOGSQL_FUNCTION_REQ_FINAL);

    /** Old style aliases */
    /**  	register_alias(s, shortname, longname) */
    log_sql_register_alias(s,p,'A',"useragent");
    log_sql_register_alias(s,p,'a',"request_args");
    log_sql_register_alias(s,p,'b',"bytes_sent");
    log_sql_register_alias(s,p,'c',"cookie");
    log_sql_register_alias(s,p,'f',"request_file");
    log_sql_register_alias(s,p,'H',"request_protocol");
    log_sql_register_alias(s,p,'h',"remote_host");
    log_sql_register_alias(s,p,'I',"unique_id");
    log_sql_register_alias(s,p,'l',"remote_logname");
    log_sql_register_alias(s,p,'m',"request_method");
    log_sql_register_alias(s,p,'M',"machine_id");
    log_sql_register_alias(s,p,'P',"child_pid");
    log_sql_register_alias(s,p,'p',"server_port");
    log_sql_register_alias(s,p,'R',"referrer");
    log_sql_register_alias(s,p,'r',"request_line");
    log_sql_register_alias(s,p,'S',"timestamp");
    log_sql_register_alias(s,p,'s',"status");
    log_sql_register_alias(s,p,'T',"request_duration");
    log_sql_register_alias(s,p,'t',"request_time");
    log_sql_register_alias(s,p,'u',"remote_user");
    log_sql_register_alias(s,p,'U',"request_uri");
    log_sql_register_alias(s,p,'v',"virtual_host");
    log_sql_register_alias(s,p,'V',"server_name");

    /* Register handlers */
    /**     register_field(p, longname, funcalias, arg, sqlfieldname, DATATYPE, DATA LENGTH); */
    log_sql_register_field(p, "useragent",              "useragent",            NULL,   "agent",                LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "request_args",           "request_args",         NULL,   "request_args",         LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "bytes_sent",             "bytes_sent",           NULL,   "bytes_sent",           LOGSQL_DATATYPE_INT,            20);
    log_sql_register_field(p, "connection_status",      "connection_status",    NULL,   "connection_status",    LOGSQL_DATATYPE_CHAR,           1);
    log_sql_register_field(p, "cookie",                 "cookie",               NULL,   "cookie",               LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "local_address",          "local_address",        NULL,   "local_address",        LOGSQL_DATATYPE_CHAR,           15);
    log_sql_register_field(p, "remote_address",         "remote_address",       NULL,   "remote_address",       LOGSQL_DATATYPE_CHAR,           15);
    log_sql_register_field(p, "request_file",           "request_file",         NULL,   "request_file",         LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "request_protocol",       "request_protocol",     NULL,   "request_protocol",     LOGSQL_DATATYPE_VARCHAR,        10);
    log_sql_register_field(p, "remote_host",            "remote_host",          NULL,   "remote_host",          LOGSQL_DATATYPE_VARCHAR,        50);
    log_sql_register_field(p, "unique_id",              "unique_id",            NULL,   "id",                   LOGSQL_DATATYPE_CHAR,           28);
    log_sql_register_field(p, "child_tid",              "child_tid",            "tid",  "child_tid",            LOGSQL_DATATYPE_BIGINT,         20);
    log_sql_register_field(p, "remote_logname",         "remote_logname",       NULL,   "remote_logname",       LOGSQL_DATATYPE_VARCHAR,        50);
    log_sql_register_field(p, "request_method",         "request_method",       NULL,   "request_method",       LOGSQL_DATATYPE_VARCHAR,        16);
    log_sql_register_field(p, "machine_id",             "machine_id",           NULL,   "machine_id",           LOGSQL_DATATYPE_VARCHAR,        25);
    log_sql_register_field(p, "child_pid",              "child_pid",            "pid",  "child_pid",            LOGSQL_DATATYPE_INT,            20);
    log_sql_register_field(p, "server_port",            "server_port",          NULL,   "server_port",          LOGSQL_DATATYPE_INT,            20);
    log_sql_register_field(p, "referer",                "referer",              NULL,   "referer",              LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "request_line",           "request_line",         NULL,   "request_line",         LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "timestamp",              "timestamp",            NULL,   "time_stamp",           LOGSQL_DATATYPE_INT,            20);
    log_sql_register_field(p, "status",                 "status",               NULL,   "status",               LOGSQL_DATATYPE_INT,            20);
    log_sql_register_field(p, "request_duration",       "request_duration",     NULL,   "request_duration",     LOGSQL_DATATYPE_INT,            20);
    log_sql_register_field(p, "request_time",           "request_time",         NULL,   "request_time",         LOGSQL_DATATYPE_TIMESTAMP,      19);
    log_sql_register_field(p, "remote_user",            "remote_user",          NULL,   "remote_user",          LOGSQL_DATATYPE_VARCHAR,        50);
    log_sql_register_field(p, "request_uri",            "request_uri",          NULL,   "request_uri",          LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "virtual_host",           "virtual_host",         NULL,   "virtual_host",         LOGSQL_DATATYPE_VARCHAR,        255);
    log_sql_register_field(p, "server_name",            "server_name",          NULL,   "server_name",          LOGSQL_DATATYPE_VARCHAR,        255);

    log_sql_register_finish(s);

    if (global_config.announce) {
        ap_add_version_component(p, PACKAGE_NAME"/"PACKAGE_VERSION);
    }
    global_config.db.p = p;

#if defined(WITH_APACHE20)
	return OK;
#endif
}

/* This function handles calling the DB module,  handling errors
 * of missing tables and lost DB connections, and falling back to
 * preserving the DB query.
 *
 * Parms: request record, table type, table name, and the full SQL command
 */

static logsql_query_ret safe_sql_insert(request_rec *r, logsql_tabletype table_type,
		const char *table_name, const char *query) {

	logsql_query_ret result;
	logsql_state *cls = ap_get_module_config(r->server->module_config,
									&log_sql_module);

	if (!global_config.db.connected || global_config.driver == NULL) {
		/* preserve query */
		return LOGSQL_QUERY_NOLINK;
	}

	result = global_config.driver->insert(r,&global_config.db,query);

	/* If we ran the query and it returned an error, try to be robust.
	* (After all, the module thought it had a valid mysql_log connection but the query
	* could have failed for a number of reasons, so we have to be extra-safe and check.) */
	switch (result) {
	case LOGSQL_QUERY_SUCCESS:
		return LOGSQL_QUERY_SUCCESS;
	case LOGSQL_QUERY_NOLINK:
		return LOGSQL_QUERY_FAIL;
		/* TODO: What do we do here */
	case LOGSQL_QUERY_FAIL:
		global_config.driver->disconnect(&global_config.db);
		global_config.db.connected = 0;
		/* re-open the connection and try again */
		if (log_sql_opendb_link(r->server) != LOGSQL_OPENDB_FAIL) {
			log_error(APLOG_MARK,APLOG_NOTICE,0, r->server,"db reconnect successful");
#			if defined(WITH_APACHE20)
			apr_sleep(apr_time_from_sec(0.25)); /* pause for a quarter second */
#			elif defined(WITH_APACHE13)
#            if defined(WIN32)
            Sleep((DWORD)0.25);
#            else
			{
				struct timespec delay, remainder;
				int nanoret;
				delay.tv_sec = 0;
				delay.tv_nsec = 250000000; /* pause for a quarter second */
				nanoret = nanosleep(&delay, &remainder);
				if (nanoret && errno != EINTR) {
					log_error(APLOG_MARK,APLOG_ERR, errno, r->server,"nanosleep unsuccessful");
				}
			}
#			 endif /* win32 */
#			endif
			result = global_config.driver->insert(r,&global_config.db,query);
			if (result == LOGSQL_QUERY_SUCCESS) {
				return LOGSQL_QUERY_SUCCESS;
			} else {
				log_error(APLOG_MARK,APLOG_ERR,0,r->server,"second attempt failed");
				preserve_entry(r, query);
				return LOGSQL_QUERY_PRESERVED;
			}
		} else {
			log_error(APLOG_MARK,APLOG_ERR,0,r->server,
				"reconnect failed, unable to reach database. SQL logging stopped until child regains a db connection.");
			log_error(APLOG_MARK,APLOG_ERR,0,r->server,
				"log entries are being preserved in %s",cls->preserve_file);
			preserve_entry(r, query);
			return LOGSQL_QUERY_PRESERVED;
		}
		break;
	case LOGSQL_QUERY_NOTABLE:
		if (global_config.createtables) {
			log_error(APLOG_MARK,APLOG_ERR,0,r->server,
					"table doesn't exist...creating now");
			if ((result = global_config.driver->create_table(r, &global_config.db, table_type,
				table_name))!=LOGSQL_TABLE_SUCCESS) {
				log_error(APLOG_MARK,APLOG_ERR,result,r->server,
					"child attempted but failed to create one or more tables for %s, preserving query", ap_get_server_name(r));
				preserve_entry(r, query);
				return LOGSQL_QUERY_PRESERVED;
			} else {
				log_error(APLOG_MARK,APLOG_ERR,result, r->server,
					"tables successfully created - retrying query");
				if ((result = global_config.driver->insert(r,&global_config.db,query))!=LOGSQL_QUERY_SUCCESS) {
					log_error(APLOG_MARK,APLOG_ERR,result, r->server,
						"giving up, preserving query");
					preserve_entry(r, query);
					return LOGSQL_QUERY_PRESERVED;
				} else {
					log_error(APLOG_MARK,APLOG_NOTICE,0, r->server,
						"query successful after table creation");
					return LOGSQL_QUERY_SUCCESS;
				}
			}
		} else {
			log_error(APLOG_MARK,APLOG_ERR,0,r->server,
				"table doesn't exist, creation denied by configuration, preserving query");
			preserve_entry(r, query);
			return LOGSQL_QUERY_PRESERVED;
		}
		break;
	default:
		log_error(APLOG_MARK,APLOG_ERR,0, r->server,
				"Invalid return code from mog_log_query");
		return LOGSQL_QUERY_FAIL;
		break;
	}
	return LOGSQL_QUERY_FAIL;
}

/* This function gets called to create a per-server configuration
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
	cls->transfer_log_format  = apr_array_make(p, 1, sizeof(char *));
	cls->parsed_pool = p;

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


/* Iterates through an array of char* and searches for a matching element
 * Returns 0 if not found, 1 if found */
static int in_array(apr_array_header_t *ary, const char *elem)
{
	int itr;
	for (itr = 0; itr < ary->nelts; itr++) {
		if (!strcmp(elem,((char **)ary->elts)[itr])) {
			return 1;
		}
	}
	return 0;
}


/* Parse through lists and merge based on +/- prefixes */
static apr_array_header_t *do_merge_array(apr_array_header_t *parent, apr_array_header_t *child, apr_pool_t *p)
{
	apr_array_header_t *ret;
	ret = apr_array_make(p, 1, sizeof(char *));
	if (apr_is_empty_array(child)) {
		apr_array_cat(ret, parent);
	} else {
		apr_array_header_t *addlist, *dellist;
		apr_pool_t *subp;
		char **elem, **ptr = (char **)(child->elts);
		int itr, overwrite = 0;

		apr_pool_create(&subp,p);

		addlist = apr_array_make(subp,5,sizeof(char *));
		dellist = apr_array_make(subp,5,sizeof(char *));

		for (itr=0; itr<child->nelts; itr++) {
			if (*ptr[itr] == '+') {
				elem = (char **)apr_array_push(addlist);
				*elem = (ptr[itr]+1);
			} else if (*ptr[itr] == '-') {
				elem = (char **)apr_array_push(dellist);
				*elem = (ptr[itr]+1);
			} else {
				overwrite = 1;
				elem = (char **)apr_array_push(addlist);
				*elem = ptr[itr];
			}
		}
		child = apr_array_make(p,1,sizeof(char *));
		ptr = (char **)(parent->elts);
		if (overwrite==0) {
			/* if we are not overwriting the existing then prepare for merge */
			for (itr=0; itr<parent->nelts; itr++) {
				if (!in_array(addlist, ptr[itr]) && !in_array(dellist,ptr[itr])) {
					elem = apr_array_push(ret);
					*elem = apr_pstrdup(p, ptr[itr]);
				}
			}
		}
		apr_array_cat(ret, addlist);
		apr_pool_destroy(subp);
	}
	return ret;
}

static void *log_sql_merge_state(apr_pool_t *p, void *basev, void *addv)
{
	/* Fetch the two states to merge */
	logsql_state *parent = (logsql_state *) basev;
	logsql_state *child = (logsql_state *) addv;

	/* Child can override these, otherwise they default to parent's choice.
	 * If the parent didn't set them, create reasonable defaults for the
	 * ones that should have such default settings.  Leave the others null. */

	/* No default for transfer_table_name because we want its absence
	 * to disable logging. */
	if (!child->transfer_table_name) {
		child->transfer_table_name = parent->transfer_table_name;
	}

	if (child->preserve_file == DEFAULT_PRESERVE_FILE)
		child->preserve_file = parent->preserve_file;
	/* server_root_relative the preserve file location */
	if (child->preserve_file == DEFAULT_PRESERVE_FILE)
        child->preserve_file = ap_server_root_relative(p, DEFAULT_PRESERVE_FILE);

	if (child->notes_table_name == DEFAULT_NOTES_TABLE_NAME)
		child->notes_table_name = parent->notes_table_name;

	if (child->hin_table_name == DEFAULT_HIN_TABLE_NAME)
		child->hin_table_name = parent->hin_table_name;

	if (child->hout_table_name == DEFAULT_HOUT_TABLE_NAME)
		child->hout_table_name = parent->hout_table_name;

	if (child->cookie_table_name == DEFAULT_COOKIE_TABLE_NAME)
		child->cookie_table_name = parent->cookie_table_name;

	child->transfer_ignore_list = do_merge_array(parent->transfer_ignore_list, child->transfer_ignore_list, p);
	child->transfer_accept_list = do_merge_array(parent->transfer_accept_list, child->transfer_accept_list, p);
	child->remhost_ignore_list = do_merge_array(parent->remhost_ignore_list, child->remhost_ignore_list, p);
	child->notes_list = do_merge_array(parent->notes_list, child->notes_list, p);
	child->hin_list = do_merge_array(parent->hin_list, child->hin_list, p);
	child->hout_list = do_merge_array(parent->hout_list, child->hout_list, p);
	child->cookie_list = do_merge_array(parent->cookie_list,child->cookie_list, p);

	if (!child->cookie_name)
		child->cookie_name = parent->cookie_name;


	return (void*) child;
}

static void str_trunc(char *src, int len, int show_ellipses) {

    if(src && len < strlen(src)) {

        src[len--] = '\0';

        if(show_ellipses) {
            if(len+1) src[len--] = '.';
            if(len+1) src[len--] = '.';
            if(len+1) src[len--] = '.';
        }
    }
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
	const char *transfer_tablename = cls->transfer_table_name;
	const char *notes_tablename = cls->notes_table_name;
	const char *hout_tablename = cls->hout_table_name;
	const char *hin_tablename = cls->hin_table_name;
	const char *cookie_tablename = cls->cookie_table_name;
    if (global_config.driver == NULL) {
        return OK;
    }
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


		/* Determine the hostname and convert it to all lower-case; */
		char *servername = apr_pstrdup(orig->pool,(char *)ap_get_server_name(orig));

		char *p=servername;
		while (*p) {
			*p = apr_tolower(*p);
			if (*p == '.') *p = '_';
			if (*p == '-') *p = '_';
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
		int i, showcomma;
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
				if (ap_strstr(r->uri, *ptrptr)) {
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
				if (ap_strstr(r->uri, *ptrptr)) {
					return OK;
				}
		}

		/* Go through each element of the ignore list and compare it to the
		 * remote host.  If we get a match, return without logging */
		ptrptr2 = (char **) (cls->remhost_ignore_list->elts + (cls->remhost_ignore_list->nelts * cls->remhost_ignore_list->elt_size));
		thehost = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
		if (thehost) {
			for (ptrptr = (char **) cls->remhost_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->remhost_ignore_list->elt_size))
				if (ap_strstr_c(thehost, *ptrptr)) {
					return OK;
				}
		}


		/* Iterate through the format characters and set up the INSERT string according to
		 * what the user has configured. */
		showcomma = 0;
		for (i = 0; i<cls->transfer_log_format->nelts; i++) {
			logsql_field *item = cls->parsed_log_format[i];
			if (item==NULL || item->func==NULL) {
				log_error(APLOG_MARK, APLOG_ERR, 0, orig->server,
					"Log Format '%s' unknown or incomplete",((char **)cls->transfer_log_format->elts)[i]);
				continue;
			}

			/* Yes, this key is one of the configured keys.
			 * Call the key's function and put the returned value into 'formatted_item' */
			formatted_item = item->func->func(item->func->want_orig_req ? orig : r,
						item->param ? item->param : NULL);

			/* If apache tried to log a '-' character, an empty string, or NULL, skip this field and value */
			if ( formatted_item && !(formatted_item[0] == '-' && formatted_item[1] == '\0') && !(formatted_item[0] == '\0') ) {

				/* TODO: Make show_ellipses configurable */
				str_trunc((char *) formatted_item, item->size, 1);

				/* Append the fieldname and value-to-insert to the appropriate strings, quoting stringvals with ' as appropriate */
				fields = apr_pstrcat(r->pool, fields, (showcomma ? "," : ""),
					 item->sql_field_name, NULL);
				values = apr_pstrcat(r->pool, values, (showcomma ? "," : ""),
					 global_config.driver->escape(r, formatted_item, r->pool,&global_config.db), NULL);
				showcomma = 1;
			}
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
									  "(",
									  global_config.driver->escape(r, unique_id, r->pool, &global_config.db),
									  ",",
									  global_config.driver->escape(r, *ptrptr, r->pool,&global_config.db),
									  ",",
									  global_config.driver->escape(r, theitem, r->pool,&global_config.db),
									  ")",
									  NULL);
				i++;
			}
		}
		if ( *itemsets != '\0' ) {
			note_query = apr_psprintf(r->pool, "insert %s into %s (id, item, val) values %s",
				/*global_config.insertdelayed?"delayed":*/"", notes_tablename, itemsets);

			log_error(APLOG_MARK,APLOG_DEBUG,0, orig->server,"mod_log_sql: note string: %s", note_query);
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
									  "(",
									  global_config.driver->escape(r,unique_id, r->pool, &global_config.db),
									  ",",
									  global_config.driver->escape(r,*ptrptr, r->pool,&global_config.db),
									  ",",
									  global_config.driver->escape(r,theitem, r->pool,&global_config.db),
									  ")",
									  NULL);
				i++;
			}
		}
		if ( *itemsets != '\0' ) {
			hout_query = apr_psprintf(r->pool, "insert %s into %s (id, item, val) values %s",
				/*global_config.insertdelayed?"delayed":*/"", hout_tablename, itemsets);

			log_error(APLOG_MARK,APLOG_DEBUG,0, orig->server,"mod_log_sql: header_out string: %s", hout_query);
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
									  "(",
									  global_config.driver->escape(r,unique_id, r->pool, &global_config.db),
									  ",",
									  global_config.driver->escape(r,*ptrptr, r->pool,&global_config.db),
									  ",",
									  global_config.driver->escape(r,theitem, r->pool,&global_config.db),
									  ")",
									  NULL);
				i++;
			}
		}
		if ( *itemsets != '\0' ) {
			hin_query = apr_psprintf(r->pool, "insert %s into %s (id, item, val) values %s",
				/*global_config.insertdelayed?"delayed":*/"", hin_tablename, itemsets);

			log_error(APLOG_MARK,APLOG_DEBUG,0, orig->server,"mod_log_sql: header_in string: %s", hin_query);
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
									  "(",
									  global_config.driver->escape(r,unique_id, r->pool, &global_config.db),
									  ",",
									  global_config.driver->escape(r,*ptrptr, r->pool,&global_config.db),
									  ",",
									  global_config.driver->escape(r,theitem, r->pool,&global_config.db),
									  ")",
									  NULL);
				i++;
			}

		}
		if ( *itemsets != '\0' ) {
			cookie_query = apr_psprintf(r->pool, "insert %s into %s (id, item, val) values %s",
				/*global_config.insertdelayed?"delayed":*/"", cookie_tablename, itemsets);

			log_error(APLOG_MARK,APLOG_DEBUG,0, orig->server,"mod_log_sql: cookie string: %s", cookie_query);
		}


		/* Set up the actual INSERT statement */
		access_query = apr_psprintf(r->pool, "insert %s into %s (%s) values (%s)",
			/*global_config.insertdelayed?"delayed":*/"", transfer_tablename, fields, values);

        log_error(APLOG_MARK,APLOG_DEBUG,0, r->server,"mod_log_sql: access string: %s", access_query);

		/* If the person activated force-preserve, go ahead and push all the entries
		 * into the preserve file, then return.
		 */
		if (global_config.forcepreserve) {
			log_error(APLOG_MARK,APLOG_DEBUG,0, orig->server,"mod_log_sql: preservation forced");
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
		if (!global_config.db.connected) {
            if (!global_config.forcepreserve) {
			    /* Make a try to establish the link */
			    log_sql_opendb_link(r->server);
            }
			if (!global_config.db.connected) {
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
				log_error(APLOG_MARK,APLOG_NOTICE,0, orig->server,"mod_log_sql: child established database connection");
			}
		}


		/* ---> So as of here we have a non-null value of mysql_log. <--- */
		/* ---> i.e. we have a good MySQL connection.                <--- */

  	    /* Make the access-table insert */
		safe_sql_insert(orig,LOGSQL_TABLE_ACCESS,transfer_tablename,access_query);

		/* Log the optional notes, headers, etc. */
		if (note_query)
			safe_sql_insert(orig, LOGSQL_TABLE_NOTES,notes_tablename,note_query);

		if (hout_query)
		  	safe_sql_insert(orig, LOGSQL_TABLE_HEADERSOUT,hout_tablename,hout_query);

		if (hin_query)
		  	safe_sql_insert(orig, LOGSQL_TABLE_HEADERSIN,hin_tablename,hin_query);

		if (cookie_query)
		  	safe_sql_insert(orig, LOGSQL_TABLE_COOKIES,cookie_tablename,cookie_query);

		return OK;
	}
}


/* Setup of the available httpd.conf configuration commands.
 * Structure: command, function called, NULL, where available, how many arguments, verbose description
 */
static const command_rec log_sql_cmds[] = {
	AP_INIT_FLAG("LogSQLAnnounce", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, announce), RSRC_CONF,
	 "Whether to announce that mod_log_sql is loaded in the server header")
	,
	/* DB connection parameters */
	AP_INIT_TAKE13("LogSQLLoginInfo", set_log_sql_info, NULL, RSRC_CONF,
	 "The database connection URI in the form &quot;driver://user:password@hostname:port/database&quot;")
	,
	AP_INIT_TAKE2("LogSQLDBParam", set_dbparam, NULL, RSRC_CONF,
	 "First argument is the DB parameter, second is the value to assign")
	,
	AP_INIT_FLAG("LogSQLForcePreserve", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, forcepreserve), RSRC_CONF,
	 "Forces logging to preserve file and bypasses database")
	,
	AP_INIT_FLAG("LogSQLDisablePreserve", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, disablepreserve), RSRC_CONF,
	 "Completely disables use of the preserve file")
	,
	AP_INIT_TAKE1("LogSQLPreserveFile", set_server_file_slot,
	 (void *)APR_OFFSETOF(logsql_state,preserve_file), RSRC_CONF,
	 "Name of the file to use for data preservation during database downtime")
	,
	AP_INIT_FLAG("LogSQLCreateTables", set_global_nmv_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, createtables), RSRC_CONF,
	 "Turn on module's capability to create its SQL tables on the fly")
	,
	/* Table names */
	AP_INIT_FLAG("LogSQLMassVirtualHosting", set_global_flag_slot,
	 (void *)APR_OFFSETOF(global_config_t, massvirtual), RSRC_CONF,
	 "Activates option(s) useful for ISPs performing mass virutal hosting")
	,
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
	/* New Log Format */
	AP_INIT_ITERATE("LogSQLTransferLogItems", add_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, transfer_log_format), RSRC_CONF,
	 "What fields to log to the database transfer log")
	,
	AP_INIT_RAW_ARGS("LogSQLRegisterItem", set_register_field,
	 NULL, RSRC_CONF,
	 "Register a new Item for logging, Arguments:  ItemName  function  argument  sqlfield  datatype  datalen<br>"
	 "datatypes are INT, SMALLINT, VARCHAR, CHAR<br>")
	 ,
	AP_INIT_TAKE1("LogSQLShowConfig", set_global_string_slot,
	 (void *)APR_OFFSETOF(global_config_t, showconfig), RSRC_CONF,
	 "Add this to export the entire running function and dfield configuration to the named file")
	,
	/* Machine ID */
	AP_INIT_TAKE1("LogSQLMachineID", set_global_string_slot,
	 (void *)APR_OFFSETOF(global_config_t, machid), RSRC_CONF,
	 "Machine ID that the module will log, useful in web clusters to differentiate machines")
	,
	/* Limits on logging */
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
	/* Special logging table configuration */
	AP_INIT_TAKE1("LogSQLWhichCookie", set_server_string_slot,
	 (void *)APR_OFFSETOF(logsql_state, cookie_name), RSRC_CONF,
	 "The single cookie that you want logged in the access_log when using the 'c' config directive")
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
	AP_INIT_RAW_ARGS("LogSQLDeprecated", ap_set_deprecated, NULL, RSRC_CONF,
	 "<br><b>Deprecated</b><br>The following Commands are deprecated and should not be used.. <br>Read the documentation for more information<br><b>Deprecated</b>")
	,
	/* Deprecated commands */
	AP_INIT_TAKE1("LogSQLTransferLogFormat", set_logformat_slot,
	  (void *)APR_OFFSETOF(logsql_state, transfer_log_format), RSRC_CONF,
	 "<b>(Deprecated) Use LogSQLTransferLogItem to specify symbolic log items instead")
	,
	AP_INIT_TAKE1("LogSQLDatabase", set_dbparam_slot,
	 (void *)"database", RSRC_CONF,
	 "<b>(Deprecated) Use LogSQLDBParam database dbname.</b> The name of the database database for logging")
	,
	AP_INIT_TAKE1("LogSQLTableType", set_dbparam_slot,
	 (void *)"tabletype", RSRC_CONF,
	 "<b>(Deprecated) Use LogSQLDBParam tabletype type.</b> What kind of table to create (MyISAM, InnoDB,...) when creating tables")
	,
	AP_INIT_TAKE1("LogSQLSocketFile", set_dbparam_slot,
	 (void *)"socketfile", RSRC_CONF,
	 "<b>(Deprecated) Use LogSQLDBParam socketfile socket.</b> Name of the file to employ for socket connections to database")
	,
	AP_INIT_TAKE1("LogSQLTCPPort", set_dbparam_slot,
	 (void *)"port", RSRC_CONF,
	 "<b>(Deprecated) Use LogSQLDBParam port port.</b> Port number to use for TCP connections to database, defaults to 3306 if not set")
	,
	{NULL}
};
/* The configuration array that sets up the hooks into the module. */
#if defined(WITH_APACHE20)
static void register_hooks(apr_pool_t *p) {
	ap_hook_post_config(log_sql_post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
	ap_hook_child_init(log_sql_child_init, NULL, NULL, APR_HOOK_MIDDLE);
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
module MODULE_VAR_EXPORT log_sql_module = {
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
