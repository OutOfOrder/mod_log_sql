/* $Id: mod_log_sql.c,v 1.9 2002/04/21 23:01:53 helios Exp $ */

/* --------*
 * DEFINES *
 * --------*/

/* The enduser probably won't modify these */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")
#define ERRLEVEL APLOG_ERR|APLOG_NOERRNO
#define WARNINGLEVEL APLOG_WARNING|APLOG_NOERRNO
#define NOTICELEVEL APLOG_NOTICE|APLOG_NOERRNO
#define DEBUGLEVEL APLOG_DEBUG|APLOG_NOERRNO

/* The enduser may wish to modify these */
#define WANT_SSL_LOGGING
#undef DEBUG


/* ---------*
 * INCLUDES *
 * ---------*/
#include <time.h>
#include <mysql/mysql.h>
#include <stdio.h>
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"

#if MODULE_MAGIC_NUMBER >= 19980324 /* M_M_N is defined in /usr/local/Apache/include/ap_mmn.h, 19990320 as of this writing. */
	#include "ap_compat.h"
#endif

#ifdef WANT_SSL_LOGGING
	#include "mod_ssl.h"
#endif


/* -------------*
 * DECLARATIONS *
 * -------------*/

/* Declare ourselves so the configuration routines can find and know us. */
module mysql_log_module;

/* The contents of these are known 'Apache wide' and are not variable
 * on a per-virtual-server basis.  Every virtual server 'knows' the
 * same versions of these variables.
 */
MYSQL sql_server, *mysql_log = NULL;

int massvirtual = 0;
char *db_name = NULL;
char *db_host = NULL;
char *db_user = NULL;
char *db_pwd  = NULL;
char *socket_file = "/var/lib/mysql/mysql.sock";

typedef const char *(*item_key_func) (request_rec *, char *);

/* But the contents of this structure will vary by virtual server. 
 * This permits each virtual server to vary its configuration slightly
 * for per-server customization. 
 * 
 * Each child process has its own segregated copy of this structure.
 */
typedef struct {
	int create_tables;
	int table_made;
	char *referer_table_name;
	char *agent_table_name;
	char *transfer_table_name;
	array_header *referer_ignore_list;
	array_header *transfer_ignore_list;
	array_header *remhost_ignore_list;
	char *transfer_log_format;
	char *preserve_file;
	char *cookie_name;
} log_mysql_state;


/* -----------------*
 * HELPER FUNCTIONS *
 * -----------------*/
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
    	    ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"SSL_KEYSIZE: %s", result);
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
    	    ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"SSL_ALGKEYSIZE: %s", result);
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
    	    ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"SSL_CIPHER: %s", result);
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
    
	log_mysql_state *cls = get_module_config(r->server->module_config, &mysql_log_module);
	
	#ifdef DEBUG
	  	ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"watching for cookie '%s'", cls->cookie_name);
	#endif
	
	/* Fetch out the cookie header */
 	cookiestr  = (char *)table_get(r->headers_in,  "cookie2");
    if (cookiestr != NULL) {
		#ifdef DEBUG
			ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"Cookie2: [%s]", cookiestr);
		#endif
		/* Does the cookie string contain one with our name? */
		isvalid = strstr(cookiestr, cls->cookie_name);
		if (isvalid != NULL) {
			/* Move past the cookie name and equal sign */
			isvalid += strlen(cls->cookie_name) + 1;
			/* Duplicate it into the pool */
		    cookiebuf = ap_pstrdup(r->pool, isvalid);
			/* Segregate just this cookie out of the string 
			 * with a terminating nul at the first semicolon */
		    cookieend = strchr(cookiebuf, ';');
		    if (cookieend != NULL)
		       *cookieend = '\0';
		  	return cookiebuf;
		}
	}

 	cookiestr  = (char *)table_get(r->headers_in,  "cookie");
    if (cookiestr != NULL) {
		#ifdef DEBUG
			ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"Cookie: [%s]", cookiestr);
		#endif
		isvalid = strstr(cookiestr, cls->cookie_name);
		if (isvalid != NULL) {
			isvalid += strlen(cls->cookie_name) + 1;
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
		     ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"Set-Cookie: [%s]", cookiestr);
		#endif
		isvalid = strstr(cookiestr, cls->cookie_name);
		if (isvalid != NULL) {
		    isvalid += strlen(cls->cookie_name) + 1;
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
	return table_get(r->subprocess_env, "HTTP_USER_AGENT");
}

/* End declarations of various extract_ functions */



struct log_mysql_item_list {
	  char ch;						/* its letter code */
	  item_key_func func;			/* its extraction function */
	  const char *sql_field_name;	/* its column in SQL */
	  int want_orig_default;		/* if it requires the original request prior to internal redirection */
	  int string_contents;			/* if it returns a string */
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
const char *escape_query(const char *from_str, pool *p)
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
		to_str = (char *) ap_palloc(p, length * 2 + 1);
		if (!to_str) {
			return from_str;
		}
		
		if (!mysql_log) {
			/* Well, I would have liked to use the current database charset.  mysql is
			 * unavailable, however, so I fall back to the slightly less respectful
			 * mysql_escape_string() function that uses the default charset.
			 */
			retval = mysql_escape_string(to_str, from_str, length);
		} else {	
			/* MySQL is available, so I'll go ahead and respect the current charset when
			 * I perform the escape.
			 */
			retval = mysql_real_escape_string(mysql_log, to_str, from_str, length);
		}
		
		if (retval)
		  return to_str;
		else
		  return from_str;
	}
}

int open_logdb_link()
{
	/* Returns 2 if already connected, 1 if successful, 0 if unsuccessful */
	
	if (mysql_log != NULL) {
		return 2;
	}

	if (db_name) {
		mysql_init(&sql_server);
		mysql_log = mysql_real_connect(&sql_server, db_host, db_user, db_pwd, db_name, 0, socket_file, 0);

		if (mysql_log != NULL) {
			return 1;
		} else {
			return 0;
		}
	}
	return 0;
}

void preserve_entry(request_rec *r, const char *query)
{
	FILE *fp;
	log_mysql_state *cls = get_module_config(r->server->module_config, &mysql_log_module);
	
	fp = pfopen(r->pool, cls->preserve_file, "a");
	if (fp == NULL)
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"attempted append of local offline file but failed.");
	else 
		fprintf(fp,"%s;\n", query);
	pfclose(r->pool, fp);
}

/*-----------------------------------------------------*/
/* safe_mysql_query: perform a database insert with    */
/* a degree of safety and error checking.              */
/*                                                     */
/* Parms:   request record, SQL insert statement       */
/* Returns: 0 (OK) on success                          */
/*          mysql return code on error                 */
/*-----------------------------------------------------*/
int safe_mysql_query(request_rec *r, const char *query)
{
	int retval;
	struct timespec delay, remainder;
	int ret;
	char *str;
	void (*handler) (int);
	

	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	handler = signal(SIGPIPE, SIG_IGN);	 

	/* First attempt for the query */
	retval = mysql_query(mysql_log, query);

	/* If we ran the query and it returned an error, try to be graceful.
	 * We only reach this point if the module thinks it has a valid connection to the
	 * database (i.e. mysql_log is non-null).  But that connection could go sour
	 * at any time, hence the check. */
	if ( retval != 0 ) 
    {
			log_mysql_state *cls = get_module_config(r->server->module_config, &mysql_log_module);
		
			/* Something went wrong, so start by trying to restart the db link. */
		    ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"attempting reconnect because API said: %s", mysql_error(mysql_log));

			mysql_log = NULL;
			open_logdb_link();

    		if (mysql_log == NULL) {	 /* still unable to link */
    			signal(SIGPIPE, handler);
    			ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"httpd child reconnect failed, unable to reach database. SQL logging stopped until an httpd child regains a db connection.");
				ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"log entries are being preserved in %s", cls->preserve_file);
				preserve_entry(r, query);
    			return retval;
    		} else {
	    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"reconnect successful.");
			}

		    /* Attempt a single re-try... First sleep for a tiny amount of time. */
	        delay.tv_sec = 0;
	        delay.tv_nsec = 500000000;  /* max is 999999999 (nine nines) */
	        ret = nanosleep(&delay, &remainder);
	        if (ret && errno != EINTR)
				ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"nanosleep unsuccessful.");

	        /* Now make our second attempt */
		    retval = mysql_query(mysql_log,query);

			/* If this one also failed, log that and append to our local offline file */
		    if ( retval != 0 )
		    {
	    		str = ap_pstrcat(r->pool, "delayed insert attempt failed, API said: ", MYSQL_ERROR(mysql_log), NULL);
	    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,str);

				preserve_entry(r, query);
				ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"entry preserved in %s", cls->preserve_file);
			} else {
	    	    ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"insert successful after a delayed retry.");
	    	}
	}

	/* Restore SIGPIPE to its original handler function */
	signal(SIGPIPE, handler);
	
	return retval;
}


/* ------------------------------------------------*
 * Command handlers that are called according      *
 * to the directives found at Apache runtime.      *
 * ------------------------------------------------*/

const char *set_massvirtual(cmd_parms *parms, void *dummy, int flag)
{
	massvirtual = ( flag ? 1 : 0);
	return NULL;
}

const char *set_log_mysql_create(cmd_parms *parms, void *dummy, int flag)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);
	
	cls->create_tables = ( flag ? 1 : 0);
	return NULL;
}

const char *set_log_mysql_db(cmd_parms *parms, void *dummy, char *arg)
{
	db_name = arg;
	return NULL;
}

const char *set_log_mysql_cookie(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->cookie_name = arg;
	return NULL;
}

const char *set_log_mysql_preserve_file(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->preserve_file = arg;
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

const char *set_transfer_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	if (massvirtual == 1) {
		char *base = "access_";
		char *tablename;
		int i;
		
		/* Find memory long enough to hold the table name + \0. */
		/* old way: */
		/*  tablename = (char*)ap_palloc(parms->pool, (strlen(base) + strlen(parms->server->server_hostname) + 1) * sizeof(char));*/
		/*  strcpy(tablename, base);*/
		/*  strcat(tablename, parms->server->server_hostname);*/
		
		tablename = ap_pstrcat(parms->pool, base, parms->server->server_hostname, NULL);

		/* Transform any dots to underscores */
		for (i = 0; i < strlen(tablename); i++) {
			if (tablename[i] == '.')
			  tablename[i] = '_';
		}
		
		/* Tell this virtual server its transfer table name, and
		 * turn on create_tables, which is implied by massvirtual.
		 */
		cls->transfer_table_name = tablename;
		cls->create_tables = 1;
	} else {
		cls->transfer_table_name = arg;
	}
	return NULL;
}

const char *set_transfer_log_format(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	cls->transfer_log_format = arg;
	return NULL;
}

const char *set_mysql_socket_file(cmd_parms *parms, void *dummy, char *arg)
{
	socket_file = arg;

	return NULL;
}

const char *add_referer_mysql_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	addme = push_array(cls->referer_ignore_list);
	*addme = pstrdup(cls->referer_ignore_list->pool, arg);
	return NULL;
}

const char *add_transfer_mysql_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	addme = push_array(cls->transfer_ignore_list);
	*addme = pstrdup(cls->transfer_ignore_list->pool, arg);
	return NULL;
}

const char *add_remhost_mysql_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_mysql_state *cls = get_module_config(parms->server->module_config, &mysql_log_module);

	addme = push_array(cls->remhost_ignore_list);
	*addme = pstrdup(cls->remhost_ignore_list->pool, arg);
	return NULL;
}




/*------------------------------------------------------------*
 * Apache-specific hooks into the module code                 *
 * that are defined in the array 'mysql_lgog_module' (at EOF) *
 *------------------------------------------------------------*/


/* 
 * This function is called during server initialisation when an heavy-weight
 * process (such as a child) is being initialised.  As with the
 * module-initialisation function, any information that needs to be recorded
 * must be in static cells, since there's no configuration record.
 *
 * There is no return value.
 */
static void log_mysql_child_init(server_rec *s, pool *p)
{
	int retval; 
	
	retval = open_logdb_link();
	#ifdef DEBUG
	if (retval > 0) {
   	    ap_log_error(APLOG_MARK,DEBUGLEVEL,s,"open_logdb_link successful");
	}
	#endif
}

/* 
 * This function is called when an heavy-weight process (such as a child) is
 * being run down or destroyed.  As with the child-initialisation function,
 * any information that needs to be recorded must be in static cells, since
 * there's no configuration record.
 *
 * There is no return value.
 */
static void log_mysql_child_exit(server_rec *s, pool *p)
{
	mysql_close(mysql_log);
}


/*
void *log_mysql_initializer(server_rec *main_server, pool *p)
{
	server_rec *s;
	
    log_mysql_state main_conf = ap_get_module_config(main_server->module_config, &mysql_log_module);

	for (server_rec *s = main_server; s; s = s->next) {
	    conf = ap_get_module_config(s->module_config, &mysql_log_module);
	    if (conf->transfer_log_format == NULL && s != main_server) {
	        *conf = *main_conf;
		}
			
}
 */

/*
 * This function gets called to create a per-server configuration
 * record.  It will always be called for the main server and
 * for each virtual server that is established.  Each server maintains
 * its own state that is separate from the others' states.
 *
 * The return value is a pointer to the created module-specific
 * structure.
 */
void *log_mysql_make_state(pool *p, server_rec *s)
{
	
	log_mysql_state *cls = (log_mysql_state *) ap_palloc(p, sizeof(log_mysql_state));


	cls->transfer_table_name = NULL;
	cls->transfer_log_format = NULL;
	
	cls->referer_ignore_list  = make_array(p, 1, sizeof(char *));
	cls->transfer_ignore_list = make_array(p, 1, sizeof(char *));
	cls->remhost_ignore_list  = make_array(p, 1, sizeof(char *));
	
	cls->table_made    = 0;
	cls->create_tables = 0;
	
	cls->preserve_file = "/tmp/mysql-preserve";
	
	return (void *) cls;
}


/* Setup of the available httpd.conf configuration commands.
 * Structure: command, function called, NULL, where available, how many arguments, verbose description
 */
command_rec log_mysql_cmds[] = {
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
	{"MySQLCreateTables", set_log_mysql_create,				NULL, 	RSRC_CONF, 	FLAG,
	 "Turn on module's capability to create its SQL tables on the fly"}
	,
	{"MySQLMassVirtualHosting", set_massvirtual,            NULL,   RSRC_CONF,  FLAG,
	 "Activates option(s) useful for ISPs performing mass virutal hosting"}
	,
	{"MySQLPreserveFile", set_log_mysql_preserve_file,		NULL, 	RSRC_CONF, 	TAKE1,
	 "Name of the file to use for data preservation during database downtime"}
	,
	{"MySQLSocketFile", set_mysql_socket_file,				NULL, 	RSRC_CONF, 	TAKE1,
	 "Name of the file to employ for socket connections to MySQL"}
	,
	{NULL}
};


	
/* Routine to perform the actual construction and execution of the relevant
 * INSERT statements.
 */
int log_mysql_transaction(request_rec *orig)
{
	char **ptrptr, **ptrptr2;
	log_mysql_state *cls = get_module_config(orig->server->module_config, &mysql_log_module);
	const char *str;
	request_rec *r;
	
	/* Are there configuration directives for these SQL logs?  For each found
	 * config directive that is found, mark that type as 'needed'.
	 */
	if ( ((cls->transfer_table_name == NULL) ? 1 : 0) ) {
		return DECLINED;
	} else {
		const char *thehost;
		char *fields = "", *values = "";
		const char *formatted_item;
		int i, j, length;
		char *createstring = NULL;

		for (r = orig; r->next; r = r->next) {
			continue;
		}

		/* The following is a stolen upsetting mess of pointers, I'm sorry
		 * Anyone with the motiviation and/or the time should feel free
		 * to make this cleaner, and while at it, clean the same mess at the RefererLog part :) */
		ptrptr2 = (char **) (cls->transfer_ignore_list->elts + (cls->transfer_ignore_list->nelts * cls->transfer_ignore_list->elt_size));

		/* Go through each element of the ignore list and compare it to the
		 * request_uri.  If we get a match, return without logging */
		if (r->uri) {
			for (ptrptr = (char **) cls->transfer_ignore_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->transfer_ignore_list->elt_size)) {
				if (strstr(r->uri, *ptrptr)) {
					return OK;
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
					return OK;
				}
			}
		}

		/* If not specified by the user, use the default format */
		if (cls->transfer_log_format == NULL) {	
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
						 * because the database expects a numeral and will reject the '-' character. */
						formatted_item = "0";
					}
				    
				     /* Append the fieldname and value-to-insert to the appropriate strings, quoting stringvals with ' as appropriate */
					fields = pstrcat(r->pool, fields, (i > 0 ? "," : ""),
									 log_mysql_item_keys[j].sql_field_name, NULL);
					
					values = pstrcat(r->pool, values, (i > 0 ? "," : ""),
									 (log_mysql_item_keys[j].string_contents ? "'" : ""),
								     escape_query(formatted_item, r->pool),
									 (log_mysql_item_keys[j].string_contents ? "'" : ""), NULL);
					break;
				}
				j++;

			}
		}

		
		/* Is this virtual server's table flagged as made?  We flag it as such in order
		 * to avoid extra processing with each request.  If it's not flagged as made,
		 * set up the CREATE string.
		 */													  
		if ((cls->table_made != 1) && (cls->create_tables != 0)) {		
			char *createprefix = "create table if not exists ";
			char *createsuffix =
			 " (agent varchar(255),\
			   bytes_sent int unsigned,\
	           child_pid smallint unsigned,\
	           cookie varchar(255),\
	           request_file varchar(255),\
	           referer varchar(255),\
	           remote_host varchar(50),\
	           remote_logname varchar(50),\
	           remote_user varchar(50),\
	           request_duration smallint unsigned,\
	           request_line varchar(255),\
	           request_method varchar(6),\
	           request_protocol varchar(10),\
	           request_time char(28),\
	           request_uri varchar(50),\
	           server_port smallint unsigned,\
	           ssl_cipher varchar(25),\
	           ssl_keysize smallint unsigned,\
	           ssl_maxkeysize smallint unsigned,\
	           status smallint unsigned,\
	           time_stamp int unsigned,\
	           virtual_host varchar(50))";

			/* Find memory long enough to hold the whole CREATE string + \0 */
			/* old way:
			 * createstring = (char*)ap_palloc(orig->pool,(strlen(createprefix) + strlen(cls->transfer_table_name) + strlen(createsuffix) + 1) * sizeof(char));
			 * strcpy (createstring, createprefix);
			 * strcat (createstring, cls->transfer_table_name);
			 * strcat (createstring, createsuffix); */
			
			createstring = ap_pstrcat(orig->pool, createprefix, cls->transfer_table_name, createsuffix, NULL);			
			
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,orig->server,"create string: %s", createstring);
			#endif

		}
		  
		/* Set up the actual INSERT statement and escape it. */
		str = ap_pstrcat(r->pool, "insert into ", cls->transfer_table_name, " (", fields, ") values (", values, ")", NULL);

		#ifdef DEBUG
	        ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"insert string: %s", str);
	    #endif
		  
		
		/* How's our mysql link integrity? */
		if (mysql_log == NULL) {

			/* Make a try to establish the link */
			open_logdb_link();
			
			if (mysql_log == NULL) {
				/* Unable to re-establish a DB link, so assume that it's really
				 * gone and send the entry to the preserve file instead. 
				 * Note that we don't keep logging the db error over and over. */
				preserve_entry(orig, str);
				return OK;
			} else {
				/* Whew, we got the DB link back */
				ap_log_error(APLOG_MARK,NOTICELEVEL,orig->server,"httpd child established database connection");
			}
		}
		
		if ((cls->table_made != 1) && (cls->create_tables != 0)) {
		  	mysql_query(mysql_log,createstring);
		  	cls->table_made = 1;
		}

  	    /* Make the insert */
		safe_mysql_query(orig, str);

		return OK;
	}
}




/* The configuration array that sets up the hooks into the module. */
module mysql_log_module = {
	STANDARD_MODULE_STUFF,
	NULL,					 /* module initializer 				*/
	NULL,					 /* create per-dir config 			*/
	NULL,					 /* merge per-dir config 			*/
	log_mysql_make_state,	 /* create server config 			*/
	NULL,					 /* merge server config 			*/
	log_mysql_cmds,			 /* config directive table 			*/
	NULL,					 /* [9] content handlers 			*/
	NULL,					 /* [2] URI-to-filename translation */
	NULL,					 /* [5] check/validate user_id 		*/
	NULL,					 /* [6] check authorization 		*/
	NULL,					 /* [4] check access by host		*/
	NULL,					 /* [7] MIME type checker/setter 	*/
	NULL,					 /* [8] fixups 						*/
	log_mysql_transaction,	 /* [10] logger 					*/
	NULL					 /* [3] header parser 				*/
#if MODULE_MAGIC_NUMBER >= 19970728 /* 1.3-dev or later support these additionals... */
	,log_mysql_child_init,   /* child process initializer 		*/
	log_mysql_child_exit,    /* process exit/cleanup 			*/
	NULL					 /* [1] post read-request 			*/
#endif
	  
};
