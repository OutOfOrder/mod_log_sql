/* $Id: mod_log_sql.c,v 1.5 2002/01/15 18:40:14 helios Exp $ */


/* DEFINES */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")
#define ERRLEVEL APLOG_ERR|APLOG_NOERRNO
#define DEBUGLEVEL APLOG_INFO|APLOG_NOERRNO
/* (MYSQLSOCKET, DEBUG and WANT_SSL_LOGGING are defined in the Makefile DEFS line.) */



/* INCLUDES */
#include <time.h>
#include <mysql/mysql.h>
#include <stdio.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"

/* M_M_N is defined in /usr/local/Apache/include/ap_mmn.h, 19990320 as of this writing. */
#if MODULE_MAGIC_NUMBER >= 19980324 /* 1.3b6 or later */
	#include "ap_compat.h"
#endif

#ifdef WANT_SSL_LOGGING /* Defined in Makefile */
	#include "mod_ssl.h"
#endif



/* DECLARATIONS */
module mysql_log_module;

MYSQL sql_server, *mysql_log = NULL;

char *db_name = NULL;
char *db_host = NULL;
char *db_user = NULL;
char *db_pwd  = NULL;
char *cookie_name = NULL;

typedef const char *(*item_key_func) (request_rec *, char *);

typedef struct {
	char *referer_table_name;
	char *agent_table_name;
	char *transfer_table_name;
	array_header *referer_ignore_list;
	array_header *transfer_ignore_list;
	array_header *remhost_ignore_list;
	char *transfer_log_format;
} log_mysql_state;



/* FUNCTIONS */
static char *format_integer(pool *p, int i)
{
	char dummy[40];
	ap_snprintf(dummy, sizeof(dummy), "%d", i);
	return pstrdup(p, dummy);
}

static char *pfmt(pool *p, int i)
{
	if (i <= 0) {
		return "-";
	} else {
		return format_integer(p, i);
	}
}

/* Begin the individual functions that, given a request r,
 * extract the needed information from it and return the
 * value to the calling entity.
 */

static const char *extract_remote_host(request_rec *r, char *a)
{
	return (char *) get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME);
}

static const char *extract_remote_logname(request_rec *r, char *a)
{
	return (char *) get_remote_logname(r);
}

static const char *extract_remote_user(request_rec *r, char *a)
{
	char *rvalue = r->connection->user;

	if (rvalue == NULL) {
		rvalue = "-";
	} else if (strlen(rvalue) == 0) {
		rvalue = "\"\"";
	}
	return rvalue;
}

#ifdef WANT_SSL_LOGGING
static const char *extract_ssl_keysize(request_rec *r, char *a)
{
	char *result = NULL;
	
	if (ap_ctx_get(r->connection->client->ctx, "ssl") != NULL) {
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_USEKEYSIZE");
		#ifdef DEBUG
    	    ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_mysql: SSL_KEYSIZE: %s", result);
		#endif
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "0";
	}
}

static const char *extract_ssl_maxkeysize(request_rec *r, char *a)
{
	char *result = NULL;
	
	if (ap_ctx_get(r->connection->client->ctx, "ssl") != NULL) {
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER_ALGKEYSIZE");
		#ifdef DEBUG
    	    ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_mysql: SSL_ALGKEYSIZE: %s", result);
		#endif
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "0";
	}
}

static const char *extract_ssl_cipher(request_rec *r, char *a)
{
	char *result = NULL;
	
	if (ap_ctx_get(r->connection->client->ctx, "ssl") != NULL) {
	    result = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CIPHER");
		#ifdef DEBUG
    	    ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_mysql: SSL_CIPHER: %s", result);
		#endif
		if (result != NULL && result[0] == '\0')
	      result = NULL;
		return result;
	} else {
		return "-";
	}
}
#endif /* WANT_SSL_LOGGING */

static const char *extract_request_method(request_rec *r, char *a)
{
	return r->method;
}

static const char *extract_request_protocol(request_rec *r, char *a)
{
	return r->protocol;
}

static const char *extract_request_line(request_rec *r, char *a)
{
	return r->the_request;
}

static const char *extract_request_file(request_rec *r, char *a)
{
	return r->filename;
}

static const char *extract_request_uri(request_rec *r, char *a)
{
	return r->uri;
}

static const char *extract_status(request_rec *r, char *a)
{
	return pfmt(r->pool, r->status);
}

static const char *extract_bytes_sent(request_rec *r, char *a)
{
	if (!r->sent_bodyct) {
		return "-";
	} else {
		long int bs;
		char dummy[40];
		bgetopt(r->connection->client, BO_BYTECT, &bs);
		ap_snprintf(dummy, sizeof(dummy), "%ld", bs);
		return pstrdup(r->pool, dummy);
	}
}

static const char *extract_header_in(request_rec *r, char *a)
{
	return table_get(r->headers_in, a);
}

static const char *extract_header_out(request_rec *r, char *a)
{
	const char *cp = table_get(r->headers_out, a);
	if (!strcasecmp(a, "Content-type") && r->content_type) {
		cp = r->content_type;
	}
	if (cp) {
		return cp;
	}
	return table_get(r->err_headers_out, a);
}

static const char *extract_request_time(request_rec *r, char *a)
{
	int timz;
	struct tm *t;
	char tstr[MAX_STRING_LEN];

	t = get_gmtoff(&timz);

	if (a && *a) {     /* Custom format */
		strftime(tstr, MAX_STRING_LEN, a, t);
	} else {		   /* CLF format */
		char sign = (timz < 0 ? '-' : '+');

		if (timz < 0) {
			timz = -timz;
		}
		strftime(tstr, MAX_STRING_LEN, "[%d/%b/%Y:%H:%M:%S ", t);
		ap_snprintf(tstr + strlen(tstr), sizeof(tstr) - strlen(tstr), "%c%.2d%.2d]", sign, timz / 60, timz % 60);
	}

	return pstrdup(r->pool, tstr);
}

static const char *extract_request_duration(request_rec *r, char *a)
{
	char duration[22];			 /* Long enough for 2^64 */

	ap_snprintf(duration, sizeof(duration), "%ld", time(NULL) - r->request_time);
	return pstrdup(r->pool, duration);
}

static const char *extract_virtual_host(request_rec *r, char *a)
{
    return ap_get_server_name(r);
}

static const char *extract_server_port(request_rec *r, char *a)
{
	char portnum[22];

	ap_snprintf(portnum, sizeof(portnum), "%u", r->server->port);
	return pstrdup(r->pool, portnum);
}

static const char *extract_child_pid(request_rec *r, char *a)
{
	char pidnum[22];
	ap_snprintf(pidnum, sizeof(pidnum), "%ld", (long) getpid());
	return pstrdup(r->pool, pidnum);
}

static const char *extract_referer(request_rec *r, char *a)
{
	const char *tempref;

	tempref = table_get(r->headers_in, "Referer");
	if (!tempref)
	{
		return "-";
	} else {
		return tempref;
	}
}

static const char *extract_agent(request_rec *r, char *a)
{
    const char *tempag;
    
    tempag = table_get(r->headers_in, "User-Agent");
    if (!tempag)
    {
        return "-";
    } else {
        return tempag;
    }
}

static const char *extract_cookie(request_rec *r, char *a)
{
    const char *cookiestr;
    char *cookieend;
	char *isvalid;
	char *cookiebuf;
    
 	cookiestr  = (char *)table_get(r->headers_in,  "cookie2");
    if (cookiestr != NULL) {
		#ifdef DEBUG
			ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_mysql: Cookie2: [%s]", cookiestr);
		#endif
		isvalid = strstr(cookiestr, cookie_name);
		if (isvalid != NULL) {
			isvalid += strlen(cookie_name) + 1;
		    cookiebuf = ap_pstrdup(r->pool, isvalid);
		    cookieend = strchr(cookiebuf, ';');
		    if (cookieend != NULL)
		       *cookieend = '\0';
		  	return cookiebuf;
		}
	}

 	cookiestr  = (char *)table_get(r->headers_in,  "cookie");
    if (cookiestr != NULL) {
		#ifdef DEBUG
			ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_mysql: Cookie: [%s]", cookiestr);
		#endif
		isvalid = strstr(cookiestr, cookie_name);
		if (isvalid != NULL) {
			isvalid += strlen(cookie_name) + 1;
		    cookiebuf = ap_pstrdup(r->pool, isvalid);
		    cookieend = strchr(cookiebuf, ';');
		    if (cookieend != NULL)
		       *cookieend = '\0';
		  	return cookiebuf;
		}
	}
	
 	cookiestr = table_get(r->headers_out,  "set-cookie");
    if (cookiestr != NULL) {
		#ifdef DEBUG
		     ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_mysql: Set-Cookie: [%s]", cookiestr);
		#endif
		isvalid = strstr(cookiestr, cookie_name);
		if (isvalid != NULL) {
		    isvalid += strlen(cookie_name) + 1;
		    cookiebuf = ap_pstrdup(r->pool, isvalid);
		    cookieend = strchr(cookiebuf, ';');
		    if (cookieend != NULL)
		       *cookieend = '\0';
		  	return cookiebuf;
		}
	}
		
	return "-"; 
}

static const char *extract_request_timestamp(request_rec *r, char *a)
{
	char tstr[32];

	snprintf(tstr, 32, "%ld", time(NULL));
	return pstrdup(r->pool, tstr);
}

static const char *extract_note(request_rec *r, char *a)
{
	return table_get(r->notes, a);
}

static const char *extract_env_var(request_rec *r, char *a)
{
	return table_get(r->subprocess_env, a);
}

/* End declarations of various extract_ functions */



struct log_mysql_item_list {
	  char ch;
	  item_key_func func;
	  const char *sql_field_name;
	  int want_orig_default;
	  int string_contents;
    } log_mysql_item_keys[] = {

	{   'A', extract_agent,             "agent",            1, 1    },
    {   'b', extract_bytes_sent,        "bytes_sent",       0, 0    },
    {   'c', extract_cookie,            "cookie",           0, 1    },
    {   'e', extract_env_var,           "env_var",          0, 1    },
    {   'f', extract_request_file,      "request_file",     0, 1    },
	{   'H', extract_request_protocol,  "request_protocol", 0, 1    },
	{   'h', extract_remote_host,       "remote_host",      0, 1    },
    {   'i', extract_header_in,         "header_in",        0, 1    },
    {   'l', extract_remote_logname,    "remote_logname",   0, 1    },
	{	'm', extract_request_method,    "request_method",   0, 1    },
	{   'n', extract_note,              "note",             0, 1    },
    {   'o', extract_header_out,        "header_out",       0, 1    },
    {   'P', extract_child_pid,         "child_pid",        0, 0    },
    {   'p', extract_server_port,       "server_port",      0, 0    },
    {   'R', extract_referer,           "referer",          1, 1    },
    {   'r', extract_request_line,      "request_line",     1, 1    },
    {   'S', extract_request_timestamp, "time_stamp",       0, 0    },
    {   's', extract_status,            "status",           1, 0    },
    {   'T', extract_request_duration,  "request_duration", 1, 0    },
    {   't', extract_request_time,      "request_time",     0, 1    },
    {   'u', extract_remote_user,       "remote_user",      0, 1    },
    {   'U', extract_request_uri,       "request_uri",      1, 1    },
    {   'v', extract_virtual_host,      "virtual_host",     0, 1    },
	#ifdef WANT_SSL_LOGGING
    {   'q', extract_ssl_keysize,       "ssl_keysize",      0, 1    },
    {   'Q', extract_ssl_maxkeysize,    "ssl_maxkeysize",   0, 1    },
    {   'z', extract_ssl_cipher,        "ssl_cipher",       0, 1    },
	#endif
	{'\0'}
};


/* Routine to escape the 'dangerous' characters that would otherwise
 * corrupt the INSERT string: ', \, and "
 */
const char *mysql_escape_log(const char *str, pool *p)
{
	register int i = 0, j = 0;
	int need_to_escape = 0;

	if (!str) {
		return NULL;
	}

	/* First find out if we need to escape.   */
	i = 0;
	while (str[i]) {
		/* WAS THIS WRONG in 1.05?!?   if (str[i] != '\'' || str[i] != '\\' || str[i] != '\"') { */
		if (str[i] == '\'' || str[i] == '\\' || str[i] == '\"') {
			need_to_escape = 1;
			break;
		}
		i++;
	}

	if (need_to_escape) {
		char *tmp_str;
		int length = strlen(str);

		/* Pre-allocate a new string that could hold twice the original, which would only
		 * happen if the whole original string was 'dangerous' characters.
		 */
		tmp_str = (char *) palloc(p, length * 2 + 1);
		if (!tmp_str) {
			return str;
		}
		
		/* Walk through character-by-character, escaping any dangerous characters found. */
		for (i = 0, j = 0; i < length; i++, j++) {
			switch (str[i]) {
			    case '\'':
			    case '\"':
			    case '\\':
				    tmp_str[j] = '\\';
				    j++;
			    default:
				    tmp_str[j] = str[i];
			}
		}
		tmp_str[j] = '\0';
		return tmp_str;
	} else {
		return str;
	}
}

void open_logdb_link()
{
	if (mysql_log != NULL) {		 /* virtual database link shared with main server */
		return;
	}
	if (db_name) {			 /* open an SQL link */
		mysql_init(&sql_server);
		mysql_log = mysql_real_connect(&sql_server, db_host, db_user, db_pwd, db_name, 0, MYSQLSOCKET, 0);
	}
}

int safe_mysql_query(request_rec *r, const char *query)
{
	int retval = 1;
	struct timespec delay, remainder;
	int ret;
	char *str;
	void (*handler) (int);

	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	handler = signal(SIGPIPE, SIG_IGN);	 

	/* If there's no DB link, or if we run the query and it gacks, try to be graceful */
	if ( !mysql_log || 
	     (
	        (retval = mysql_query(mysql_log, query)) && 
	        (mysql_errno(mysql_log) != 0)
	     )
	   ) 
	   
	   {    /* We need to restart the server link */
		    mysql_log = NULL;
		    ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: connection lost, attempting reconnect");

    		open_logdb_link();

    		if (mysql_log == NULL) {	 /* still unable to link */
    			signal(SIGPIPE, handler);
    			ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: reconnect failed");
    			return retval;
    		}

    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: reconnect successful");
    		retval = mysql_query(mysql_log, query);
	}

	/* Restore SIGPIPE to its original handler function */
	signal(SIGPIPE, handler);

	if (retval) {
	    /* Attempt a single re-try... First sleep for a tiny amount of time. */
        delay.tv_sec = 0;
        delay.tv_nsec = 500000000;  /* max is 999999999 (nine nines) */
        ret = nanosleep(&delay, &remainder);
        if (ret && errno != EINTR)
           perror("nanosleep");

        /* Now re-attempt */
	    retval = mysql_query(mysql_log,query);

	    if (retval) {
    		str = pstrcat(r->pool, "MySQL insert failed:  ", query, NULL);
    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,str);
    		str = pstrcat(r->pool, "MySQL failure reason:  ", MYSQL_ERROR(mysql_log), NULL);
    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,str);
    	} else {
    	    ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: insert successful after a delayed retry.");
    	}
	}
	return retval;
}



const char *set_referer_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->referer_table_name = arg;
	return NULL;
}


const char *set_agent_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->agent_table_name = arg;
	return NULL;
}


const char *set_transfer_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->transfer_table_name = arg;
	return NULL;
}


const char *set_transfer_log_format(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->transfer_log_format = arg;
	return NULL;
}


const char *set_log_mysql_db(cmd_parms *parms, void *dummy, char *arg)
{
	db_name = arg;
	return NULL;
}

const char *set_log_mysql_cookie(cmd_parms *parms, void *dummy, char *arg)
{
	cookie_name = arg;
	return NULL;
}

const char *set_log_mysql_info(cmd_parms *parms, void *dummy, char *host, char *user, char *pwd)
{
	if (*host != '.') {
		db_host = host;
	}
	if (*user != '.') {
		db_user = user;
	}
	if (*pwd != '.') {
		db_pwd = pwd;
	}
	return NULL;
}


const char *add_referer_mysql_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	addme = push_array(cls->referer_ignore_list);
	*addme = pstrdup(cls->referer_ignore_list->pool, arg);
	return NULL;
}

const char *add_transfer_mysql_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	addme = push_array(cls->transfer_ignore_list);
	*addme = pstrdup(cls->transfer_ignore_list->pool, arg);
	return NULL;
}

const char *add_remhost_mysql_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	addme = push_array(cls->remhost_ignore_list);
	*addme = pstrdup(cls->remhost_ignore_list->pool, arg);
	return NULL;
}


/*
 * Apache-specific hooks into the module code
 * that are defined in the array 'mysql_lgog_module' (at EOF)
 */


/* Set up space for the various major configuration options */
void *log_mysql_make_state(pool *p, server_rec *s)
{
	log_mysql_state *cls = (log_mysql_state *) palloc(p, sizeof(log_mysql_state));

	cls->referer_table_name = cls->agent_table_name = cls->transfer_table_name = "";
	
	cls->referer_ignore_list  = make_array(p, 1, sizeof(char *));
	cls->transfer_ignore_list = make_array(p, 1, sizeof(char *));
	cls->remhost_ignore_list  = make_array(p, 1, sizeof(char *));

	cls->transfer_log_format = "";
	return (void *) cls;
}


/* Setup of the available httpd.conf configuration commands.
 * command, function called, NULL, where available, how many arguments, verbose description
 */
command_rec log_mysql_cmds[] = {
	{"MySQLRefererLogTable", set_referer_log_mysql_table,   NULL, 	RSRC_CONF, 	TAKE1,
	 "The MySQL table that holds the referer log"}
	,
	{"MySQLAgentLogTable", set_agent_log_mysql_table, 		NULL, 	RSRC_CONF, 	TAKE1,
	 "The MySQL table that holds the agent log"}
	,
	{"MySQLTransferLogTable", set_transfer_log_mysql_table, NULL, 	RSRC_CONF, 	TAKE1,
	 "The MySQL table that holds the transfer log"}
	,
	{"MySQLTransferLogFormat", set_transfer_log_format, 	NULL, 	RSRC_CONF, 	TAKE1,
	 "Instruct the module what information to log to the MySQL transfer log"}
	,
	{"MySQLRefererIgnore", add_referer_mysql_ignore, 		NULL, 	RSRC_CONF, 	ITERATE,
	 "List of referers to ignore. Accesses that match will not be logged to MySQL"}
	,
	{"MySQLRequestIgnore", add_transfer_mysql_ignore, 		NULL, 	RSRC_CONF, 	ITERATE,
	 "List of URIs to ignore. Accesses that match will not be logged to MySQL"}
	,
	{"MySQLRemhostIgnore", add_remhost_mysql_ignore, 		NULL, 	RSRC_CONF, 	ITERATE,
	 "List of remote hosts to ignore. Accesses that match will not be logged to MySQL"}
	,
	{"MySQLDatabase", set_log_mysql_db, 					NULL, 	RSRC_CONF, 	TAKE1,
	 "The name of the MySQL database for logging"}
	,
	{"MySQLWhichCookie", set_log_mysql_cookie, 				NULL, 	RSRC_CONF, 	TAKE1,
	 "The CookieName that you want logged when using the 'c' config directive"}
	,
	{"MySQLLoginInfo", set_log_mysql_info, 					NULL, 	RSRC_CONF, 	TAKE3,
	 "The MySQL host, user-id and password for logging"}
	,
	{NULL}
};


	
/* Routine to perform the actual construction and execution of the relevant
 * INSERT statements.
 */
int log_mysql_transaction(request_rec *orig)
{
	char **ptrptr, **ptrptr2;
	log_mysql_state *cls = get_module_config(orig->server->module_config,
						 &mysql_log_module);
	char *str;
	const char *referer;
	request_rec *r;
	int retvalue = DECLINED;
	int referer_needed, agent_needed, transfer_needed;

	/* Are there configuration directives for these SQL logs?  For each found
	 * config directive that is found, mark that type as 'needed'.
	 */
	referer_needed = ((cls->referer_table_name[0] != '\0') ? 1 : 0);
	agent_needed = ((cls->agent_table_name[0] != '\0') ? 1 : 0);
	transfer_needed = ((cls->transfer_table_name[0] != '\0') ? 1 : 0);

	if (!referer_needed && !agent_needed && !transfer_needed) {
		return OK;
	}

	if (mysql_log == NULL) {		 /* mysql link not up, hopefully we can do something about it */
		open_logdb_link();
		if (mysql_log == NULL) {
			return OK;
		}
	}

	for (r = orig; r->next; r = r->next) {
		continue;
	}

	/* Log the 'referer' to its own log if configured to do so. */
	if (referer_needed) {			 
		retvalue = OK;
		referer = table_get(orig->headers_in, "Referer");
		if (referer != NULL) {

			/* The following is an upsetting mess of pointers, I'm sorry
			 * Anyone with the motiviation and/or the time should feel free
			 * to make this cleaner... */
			ptrptr2 = (char **) (cls->referer_ignore_list->elts + (cls->referer_ignore_list->nelts * cls->referer_ignore_list->elt_size));

			/* Go through each element of the ignore list and compare it to the
			 * referer_host.  If we get a match, return without logging */
			for (ptrptr = (char **) cls->referer_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->referer_ignore_list->elt_size)) {
				if (strstr(referer, *ptrptr)) {
					return OK;
				}
			}
			str = pstrcat(orig->pool, "insert into ", cls->referer_table_name, " (referer,url,time_stamp) values ('", mysql_escape_log(referer, orig->pool), "','", mysql_escape_log(r->uri, orig->pool), "',unix_timestamp(now()) )", NULL);
			safe_mysql_query(orig, str);
		}
	}

	/* Log the 'user agent' to its own log if configured to do so. */
	if (agent_needed) {			 
		const char *agent, *str;
		
		retvalue = OK;
		agent = table_get(orig->headers_in, "User-Agent");
		
		if (agent != NULL) {
			str = pstrcat(orig->pool, "insert into ", cls->agent_table_name, "(agent,time_stamp) values ('", mysql_escape_log(agent, orig->pool), "',unix_timestamp(now()) )", NULL);
			safe_mysql_query(orig, str);
		}
	}

	/* Log the transfer to its own log if configured to do so. */
	if (transfer_needed) {
		const char *thehost;

		char *fields = "", *values = "", *query;
		const char *formatted_item;
		int i, j, length;

		retvalue = OK;


		/* The following is a stolen upsetting mess of pointers, I'm sorry
		 * Anyone with the motiviation and/or the time should feel free
		 * to make this cleaner, and while at it, clean the same mess at the RefererLog part :) */
		ptrptr2 = (char **) (cls->transfer_ignore_list->elts + (cls->transfer_ignore_list->nelts * cls->transfer_ignore_list->elt_size));

		/* Go through each element of the ignore list and compare it to the
		 * request_uri.  If we get a match, return without logging */
		if (r->uri) {
			for (ptrptr = (char **) cls->transfer_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->transfer_ignore_list->elt_size)) {
				if (strstr(r->uri, *ptrptr)) {
					return retvalue;
				}
			}
		}

		/* Go through each element of the ignore list and compare it to the
		 * remote host.  If we get a match, return without logging */
		ptrptr2 = (char **) (cls->remhost_ignore_list->elts + (cls->remhost_ignore_list->nelts * cls->remhost_ignore_list->elt_size));
		thehost = get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME);
		if (thehost) {
			for (ptrptr = (char **) cls->remhost_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->remhost_ignore_list->elt_size)) {
				if (strstr(thehost, *ptrptr)) {
					return retvalue;
				}
			}
		}

		/* If not specified by the user, use the default format */
		if (cls->transfer_log_format[0] == '\0') {	
			cls->transfer_log_format = "AbHhmRSsTUuv";
		}
		length = strlen(cls->transfer_log_format);

		/* Iterate through the format characters and set up the INSERT string according to
		 * what the user has configured. */
		for (i = 0; i < length; i++) {
			j = 0;
			while (log_mysql_item_keys[j].ch) {
				if (log_mysql_item_keys[j].ch == cls->transfer_log_format[i]) {
					/* Yes, this key is one of the configured keys.
					 * Call the key's function and put the returned value into 'formatted_item' */
					formatted_item = log_mysql_item_keys[j].func(log_mysql_item_keys[j].want_orig_default ? orig : r, "");
				    
				     /* Massage 'formatted_item' for proper SQL eligibility... */
					if (!formatted_item) {
						formatted_item = "";
					} else if (formatted_item[0] == '-' && formatted_item[1] == '\0' && !log_mysql_item_keys[j].string_contents) {
						/* If apache tried to log a '-' character for a numeric field, convert that to a zero 
						 * because the database expects an integer. */
						formatted_item = "0";
					}
				    
				     /* Append the fieldname and value-to-insert to teh appropriate strings, quoting stringvals with ' as appropriate */
					fields = pstrcat(orig->pool, fields, (i > 0 ? "," : ""), log_mysql_item_keys[j].sql_field_name, NULL);
					values = pstrcat(orig->pool, values, (i > 0 ? "," : ""), (log_mysql_item_keys[j].string_contents ? "'" : ""), mysql_escape_log(formatted_item, orig->pool), (log_mysql_item_keys[j].string_contents ? "'" : ""), NULL);
					break;
				}
				j++;
			}
		}

		/* Set up the actual INSERT statement and execute it. */
		query = pstrcat(orig->pool, "insert into ", cls->transfer_table_name, " (", fields, ") values (", values, ")", NULL);
		safe_mysql_query(orig, query);

	}
	return retvalue;
}


/* Called on the exit of an httpd child process */
static void log_mysql_child_exit(server_rec *s, pool *p)
{
		mysql_close(mysql_log);
}


/* The configuration array that sets up the hooks into the module. */
module mysql_log_module = {
	STANDARD_MODULE_STUFF,
	NULL,					 /* initializer */
	NULL,					 /* create per-dir config */
	NULL,					 /* merge per-dir config */
	log_mysql_make_state,	 /* server config */
	NULL,					 /* merge server config */
	log_mysql_cmds,			 /* command table */
	NULL,					 /* handlers */
	NULL,					 /* filename translation */
	NULL,					 /* check_user_id */
	NULL,					 /* check auth */
	NULL,					 /* check access */
	NULL,					 /* type_checker */
	NULL,					 /* fixups */
	log_mysql_transaction,	 /* logger */
	NULL,					 /* header parser */
#if MODULE_MAGIC_NUMBER >= 19970728 /* 1.3-dev or later support these additionals... */
	NULL,                    /* child_init */
	log_mysql_child_exit,    /* process exit/cleanup */
	NULL					 /* [#0] post read-request */
#endif
	  
};
