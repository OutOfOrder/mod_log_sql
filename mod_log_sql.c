/* $Id: mod_log_sql.c,v 1.19 2002/11/27 07:13:58 helios Exp $ */

/* --------*
 * DEFINES *
 * --------*/

/* The enduser may wish to modify this */
#define DEBUG

/* The enduser won't modify these */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")
#define ERRLEVEL APLOG_ERR|APLOG_NOERRNO
#define WARNINGLEVEL APLOG_WARNING|APLOG_NOERRNO
#define NOTICELEVEL APLOG_NOTICE|APLOG_NOERRNO
#define DEBUGLEVEL APLOG_DEBUG|APLOG_NOERRNO

/* ---------*
 * INCLUDES *
 * ---------*/
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "mysql.h"

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
module sql_log_module;

/* The contents of these are known 'Apache wide' and are not variable
 * on a per-virtual-server basis.  Every virtual server 'knows' the
 * same versions of these variables.
 */
MYSQL sql_server, *mysql_log = NULL;

int massvirtual = 0;
int create_tables = 0;
int force_preserve = 0;
char *db_name = NULL;
char *db_host = NULL;
char *db_user = NULL;
char *db_pwd  = NULL;
char *mach_id = NULL;
char *socket_file = "/tmp/mysql.sock";
unsigned int tcp_port = 3306;
#ifdef WANT_DELAYED_MYSQL_INSERT
 char *insert_stmt = "insert delayed into ";
#else
 char *insert_stmt = "insert into ";
#endif

typedef const char *(*item_key_func) (request_rec *, char *);

/* But the contents of this structure will vary by virtual server.
 * This permits each virtual server to vary its configuration slightly
 * for per-server customization.
 *
 * Each child process has its own segregated copy of this structure.
 */
typedef struct {
	int table_made;
	array_header *transfer_ignore_list;
	array_header *remhost_ignore_list;
	array_header *notes_list;
	array_header *hout_list;
	array_header *hin_list;
	array_header *cookie_list;
	char *notes_table_name;
	char *hout_table_name;
	char *hin_table_name;
	char *cookie_table_name;
	char *transfer_table_name;
	char *transfer_log_format;
	char *preserve_file;
	char *cookie_name;
} log_sql_state;


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

/*
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
*/

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

static const char *extract_machine_id(request_rec *r, char *a)
{
	if (!mach_id)
		return "-";
	else
		return mach_id;
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

	log_sql_state *cls = get_module_config(r->server->module_config, &sql_log_module);

	if (cls->cookie_name != NULL) {
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
	}

	return "-";
}

static const char *extract_specific_cookie(request_rec *r, char *a)
{
    const char *cookiestr;
    char *cookieend;
	char *isvalid;
	char *cookiebuf;

	if (a != NULL) {
		#ifdef DEBUG
		  	ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"watching for cookie '%s'", a);
		#endif

		/* Fetch out the cookie header */
	 	cookiestr  = (char *)table_get(r->headers_in,  "cookie2");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"Cookie2: [%s]", cookiestr);
			#endif
			/* Does the cookie string contain one with our name? */
			isvalid = strstr(cookiestr, a);
			if (isvalid != NULL) {
				/* Move past the cookie name and equal sign */
				isvalid += strlen(a) + 1;
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
			isvalid = strstr(cookiestr, a);
			if (isvalid != NULL) {
				isvalid += strlen(a) + 1;
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
			isvalid = strstr(cookiestr, a);
			if (isvalid != NULL) {
			    isvalid += strlen(a) + 1;
			    cookiebuf = ap_pstrdup(r->pool, isvalid);
			    cookieend = strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return cookiebuf;
			}
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

/*
static const char *extract_note(request_rec *r, char *a)
{
	return ap_table_get(r->notes, a);

}
*/

static const char *extract_env_var(request_rec *r, char *a)
{
	return ap_table_get(r->subprocess_env, a);
}

static const char *extract_unique_id(request_rec *r, char *a)
{
    const char *tempid;

	tempid = ap_table_get(r->subprocess_env, "UNIQUE_ID");
	if (!tempid)
	  return "-";
	else
	  return tempid;
}

/* End declarations of various extract_ functions */



struct log_sql_item_list {
	  char ch;						/* its letter code */
	  item_key_func func;			/* its extraction function */
	  const char *sql_field_name;	/* its column in SQL */
	  int want_orig_default;		/* if it requires the original request prior to internal redirection */
	  int string_contents;			/* if it returns a string */
    } log_sql_item_keys[] = {

	{   'A', extract_agent,             "agent",            1, 1    },
	{   'b', extract_bytes_sent,        "bytes_sent",       0, 0    },
    {   'c', extract_cookie,            "cookie",           0, 1    },
    {   'e', extract_env_var,           "env_var",          0, 1    },
    {   'f', extract_request_file,      "request_file",     0, 1    },
	{   'H', extract_request_protocol,  "request_protocol", 0, 1    },
	{   'h', extract_remote_host,       "remote_host",      0, 1    },
	{   'I', extract_unique_id,         "id",               0, 1    },
	{   'l', extract_remote_logname,    "remote_logname",   0, 1    },
	{   'm', extract_request_method,    "request_method",   0, 1    },
	{   'M', extract_machine_id,        "machine_id",       0, 1    },
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

int open_logdb_link(server_rec* s)
{
	/* Returns:
	   3 if preserve forced
	   2 if already connected
	   1 if successful
	   0 if unsuccessful
	*/

	if (force_preserve)
		return 3;

	if (mysql_log)
		return 2;

	if (db_name) {
		mysql_init(&sql_server);
		mysql_log = mysql_real_connect(&sql_server, db_host, db_user, db_pwd, db_name, tcp_port, socket_file, 0);

		if (mysql_log) {
			#ifdef DEBUG
			  ap_log_error(APLOG_MARK,DEBUGLEVEL,s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
			  										db_host, tcp_port, db_name, db_user, socket_file);
			#endif
			return 1;
		} else {
			#ifdef DEBUG
			  ap_log_error(APLOG_MARK,DEBUGLEVEL,s,"mod_log_sql: database connection error: %s",MYSQL_ERROR(&sql_server));
			  ap_log_error(APLOG_MARK,DEBUGLEVEL,s,"HOST: '%s' PORT: '%d' DB: '%s' USER: '%s' SOCKET: '%s'",
			  										db_host, tcp_port, db_name, db_user, socket_file);
		 	#endif
			return 0;
		}
	}

	return 0;
}

const char *extract_table(void *data, const char *key, const char *val)
{
    request_rec *r = (request_rec *)data;

	return ap_pstrcat(r->pool, key, " = ", val, " ", NULL);
}

void preserve_entry(request_rec *r, const char *query)
{
	FILE *fp;
	log_sql_state *cls = get_module_config(r->server->module_config, &sql_log_module);

	fp = pfopen(r->pool, cls->preserve_file, "a");
	if (fp == NULL)
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: attempted append of local preserve file but failed.");
	else {
		fprintf(fp,"%s;\n", query);
		pfclose(r->pool, fp);
		#ifdef DEBUG
		  ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: entry preserved in %s", cls->preserve_file);
		#endif
	}
}


/*-----------------------------------------------------*/
/* safe_mysql_query: perform a database query with     */
/* a degree of safety and error checking.              */
/*                                                     */
/* Parms:   request record, SQL insert statement       */
/* Returns: 0 (OK) on success                          */
/*          1 if have no log handle                    */
/*          actual MySQL return code on error          */
/*-----------------------------------------------------*/
unsigned int safe_mysql_query(request_rec *r, const char *query)
{
	unsigned int retval;
	unsigned int real_error;
	struct timespec delay, remainder;
	int ret;
	void (*handler) (int);


	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	handler = signal(SIGPIPE, SIG_IGN);

	/* First attempt for the query */
	if (mysql_log != NULL)
		retval = mysql_query(mysql_log, query);
	else
	  	return 1;

	if ( retval != 0 )
    {
		/* If we ran the query and it returned an error, try to be robust.
		 * (After all, the module thought it had a valid mysql_log connection but the query
		 * could have failed for a number of reasons, so we have to be extra-safe and check.) */

		log_sql_state *cls = get_module_config(r->server->module_config, &sql_log_module);

		real_error = mysql_errno(mysql_log); /* What really happened? */

		/* Something went wrong, so start by trying to restart the db link. */
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: first attempt failed, API said: error %d, %s", real_error, MYSQL_ERROR(mysql_log));
		mysql_close(mysql_log);
		mysql_log = NULL;
		open_logdb_link(r->server);

    	if (mysql_log == NULL) {	 /* still unable to link */
    		signal(SIGPIPE, handler);
    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: reconnect failed, unable to reach database. SQL logging stopped until child regains a db connection.");
			ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: log entries are being preserved in %s", cls->preserve_file);
    		return 1;
    	} else
	    	ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: reconnect successful");

		/* First sleep for a tiny amount of time. */
	    delay.tv_sec = 0;
	    delay.tv_nsec = 250000000;  /* max is 999999999 (nine nines) */
	    ret = nanosleep(&delay, &remainder);
	    if (ret && errno != EINTR)
			ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: nanosleep unsuccessful");

	    /* Then make our second attempt */
		retval = mysql_query(mysql_log,query);

		/* If this one also failed, log that and append to our local offline file */
		if ( retval != 0 )
		{
			real_error = mysql_errno(mysql_log);
	    	ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: second attempt failed, API said: error %d, %s", real_error, MYSQL_ERROR(mysql_log));
			retval = real_error;
		} else
	        ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: second attempt successful");
	}

	/* Restore SIGPIPE to its original handler function */
	signal(SIGPIPE, handler);

	return retval;
}

/*-----------------------------------------------------*/
/* safe_create_tables: create SQL table set for the    */
/* virtual server represented by cls.                  */
/*                                                     */
/* Parms:   virtserver structure, request record       */
/* Returns: 0 on no errors							   */
/*          mysql error code on failure				   */
/*-----------------------------------------------------*/
int safe_create_tables(log_sql_state *cls, request_rec *r)
{
	int retval;
	unsigned int create_results;
	char *create_access = NULL;
	char *create_notes = NULL;
	char *create_hout = NULL;
	char *create_hin = NULL;
	char *create_cookies = NULL;

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
       request_uri varchar(50),\
       server_port smallint unsigned,\
       ssl_cipher varchar(25),\
       ssl_keysize smallint unsigned,\
       ssl_maxkeysize smallint unsigned,\
       status smallint unsigned,\
       time_stamp int unsigned,\
       virtual_host varchar(50))";

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

	/* Find memory long enough to hold the whole CREATE string + \0 */
	create_access = ap_pstrcat(r->pool, createprefix, cls->transfer_table_name, access_suffix, NULL);
	create_notes  = ap_pstrcat(r->pool, createprefix, cls->notes_table_name, notes_suffix, NULL);
	create_hout   = ap_pstrcat(r->pool, createprefix, cls->hout_table_name, headers_suffix, NULL);
	create_hin    = ap_pstrcat(r->pool, createprefix, cls->hin_table_name, headers_suffix, NULL);
	create_cookies= ap_pstrcat(r->pool, createprefix, cls->cookie_table_name, cookies_suffix, NULL);

	#ifdef DEBUG
		ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: create string: %s", create_access);
		ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: create string: %s", create_notes);
		ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: create string: %s", create_hout);
		ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: create string: %s", create_hin);
		ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: create string: %s", create_cookies);
	#endif

	/* Assume that things worked unless told otherwise */
	cls->table_made = 1;
	retval = 0;

  	if ((create_results = safe_mysql_query(r, create_access)) != 0) {
		cls->table_made = 0;
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: failed to create access table");
		retval = create_results;
	}

	if ((create_results = safe_mysql_query(r, create_notes)) != 0) {
		cls->table_made = 0;
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: failed to create notes table");
		retval = create_results;
	}

	if ((create_results = safe_mysql_query(r, create_hin)) != 0) {
		cls->table_made = 0;
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: failed to create header_out table");
		retval = create_results;
	}

	if ((create_results = safe_mysql_query(r, create_hout)) != 0) {
		cls->table_made = 0;
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: failed to create header_in table");
		retval = create_results;
	}

	if ((create_results = safe_mysql_query(r, create_cookies)) != 0) {
		cls->table_made = 0;
		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"mod_log_sql: failed to create cookies table");
		retval = create_results;
	}

	return retval;
}

/* ------------------------------------------------*
 * Command handlers that are called according      *
 * to the directives found at Apache runtime.      *
 * ------------------------------------------------*/

const char *set_log_sql_massvirtual(cmd_parms *parms, void *dummy, int flag)
{
	massvirtual = ( flag ? 1 : 0);
	return NULL;
}

const char *set_log_sql_force_preserve(cmd_parms *parms, void *dummy, int flag)
{
	force_preserve = ( flag ? 1 : 0);
	return NULL;
}

const char *set_log_sql_machine_id(cmd_parms *parms, void *dummy, char *arg)
{
	mach_id = arg;
	return NULL;
}

const char *set_log_sql_create(cmd_parms *parms, void *dummy, int flag)
{
	if (massvirtual != 0)
	    ap_log_error(APLOG_MARK,WARNINGLEVEL,parms->server,"mod_log_sql: do not set LogSQLCreateTables when LogSQLMassVirtualHosting is On. Ignoring.");
	else
		create_tables = ( flag ? 1 : 0);
	return NULL;
}

const char *set_log_sql_db(cmd_parms *parms, void *dummy, char *arg)
{
	db_name = arg;
	return NULL;
}

const char *set_log_sql_cookie(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	cls->cookie_name = arg;
	return NULL;
}

const char *set_log_sql_preserve_file(cmd_parms *parms, void *dummy, char *arg)
{
	/* char *pfile; */
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	/* pfile = ap_pstrcat(parms->pool, "/tmp/", arg, NULL); */
	cls->preserve_file = arg;
	return NULL;
}

const char *set_log_sql_info(cmd_parms *parms, void *dummy, char *host, char *user, char *pwd)
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

const char *set_log_sql_transfer_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	if (massvirtual != 0)
		ap_log_error(APLOG_MARK,WARNINGLEVEL,parms->server,"mod_log_sql: do not set LogSQLTransferLogTable when LogSQLMassVirtualHosting is On. Ignoring.");
	else
		cls->transfer_table_name = arg;
	return NULL;
}

const char *set_log_sql_cookie_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	if (massvirtual != 0)
		ap_log_error(APLOG_MARK,WARNINGLEVEL,parms->server,"mod_log_sql: do not set LogSQLCookieLogTable when LogSQLMassVirtualHosting is On. Ignoring.");
	else
		cls->cookie_table_name = arg;
	return NULL;
}

const char *set_log_sql_notes_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	if (massvirtual != 0)
		ap_log_error(APLOG_MARK,WARNINGLEVEL,parms->server,"mod_log_sql: do not set LogSQLNotesLogTable when LogSQLMassVirtualHosting is On. Ignoring.");
	else
		cls->notes_table_name = arg;
	return NULL;
}

const char *set_log_sql_hin_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	if (massvirtual != 0)
		ap_log_error(APLOG_MARK,WARNINGLEVEL,parms->server,"mod_log_sql: do not set LogSQLHeadersInLogTable when LogSQLMassVirtualHosting is On. Ignoring.");
	else
		cls->hin_table_name = arg;
	return NULL;
}

const char *set_log_sql_hout_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	if (massvirtual != 0)
		ap_log_error(APLOG_MARK,WARNINGLEVEL,parms->server,"mod_log_sql: do not set LogSQLHeadersOutLogTable when LogSQLMassVirtualHosting is On. Ignoring.");
	else
		cls->hout_table_name = arg;
	return NULL;
}

const char *set_log_sql_transfer_log_format(cmd_parms *parms, void *dummy, char *arg)
{
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	cls->transfer_log_format = arg;
	return NULL;
}

const char *set_log_sql_socket_file(cmd_parms *parms, void *dummy, char *arg)
{
	socket_file = arg;

	return NULL;
}

const char *set_log_sql_tcp_port(cmd_parms *parms, void *dummy, char *arg)
{
	tcp_port = (unsigned int)atoi(arg);

	return NULL;
}

const char *add_log_sql_transfer_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	addme = push_array(cls->transfer_ignore_list);
	*addme = pstrdup(cls->transfer_ignore_list->pool, arg);
	return NULL;
}

const char *add_log_sql_remhost_ignore(cmd_parms *parms, void *dummy, char *arg)
{
	char **addme;
	log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

	addme = push_array(cls->remhost_ignore_list);
	*addme = pstrdup(cls->remhost_ignore_list->pool, arg);
	return NULL;
}

const char *add_log_sql_note(cmd_parms *parms, void *dummy, char *arg)
{
    char **addme;
    log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

    addme = push_array(cls->notes_list);
    *addme = pstrdup(cls->notes_list->pool, arg);
    return NULL;
}

const char *add_log_sql_hout(cmd_parms *parms, void *dummy, char *arg)
{
    char **addme;
    log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

    addme = push_array(cls->hout_list);
    *addme = pstrdup(cls->hout_list->pool, arg);
    return NULL;
}

const char *add_log_sql_hin(cmd_parms *parms, void *dummy, char *arg)
{
    char **addme;
    log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

    addme = push_array(cls->hin_list);
    *addme = pstrdup(cls->hin_list->pool, arg);
    return NULL;
}

const char *add_log_sql_cookie(cmd_parms *parms, void *dummy, char *arg)
{
    char **addme;
    log_sql_state *cls = get_module_config(parms->server->module_config, &sql_log_module);

    addme = push_array(cls->cookie_list);
    *addme = pstrdup(cls->cookie_list->pool, arg);
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
static void log_sql_child_init(server_rec *s, pool *p)
{
	int retval; 

	retval = open_logdb_link(s);
	if (retval == 0)
		ap_log_error(APLOG_MARK,ERRLEVEL,s,"mod_log_sql: child spawned but unable to open database link");

	#ifdef DEBUG
	if ( (retval == 1) || (retval == 2) )
		ap_log_error(APLOG_MARK,DEBUGLEVEL,s,"mod_log_sql: open_logdb_link successful");
	if (retval == 3)
 		ap_log_error(APLOG_MARK,DEBUGLEVEL,s,"mod_log_sql: open_logdb_link said that preservation is forced");
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
static void log_sql_child_exit(server_rec *s, pool *p)
{
	mysql_close(mysql_log);
}


/*
void *log_sql_initializer(server_rec *main_server, pool *p)
{
	server_rec *s;

    log_sql_state main_conf = ap_get_module_config(main_server->module_config, &sql_log_module);

	for (server_rec *s = main_server; s; s = s->next) {
	    conf = ap_get_module_config(s->module_config, &sql_log_module);
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
void *log_sql_make_state(pool *p, server_rec *s)
{

	log_sql_state *cls = (log_sql_state *) ap_palloc(p, sizeof(log_sql_state));

	/* These defaults are overridable in the httpd.conf file. */
	cls->transfer_table_name = NULL; /* No default b/c we want its absence to disable logging */
	cls->transfer_log_format = "AbHhmRSsTUuv";
	cls->notes_table_name    = "notes";
	cls->hin_table_name      = "headers_in";
	cls->hout_table_name     = "headers_out";
	cls->cookie_table_name   = "cookies";
	cls->preserve_file 		 = "/tmp/sql-preserve";

	cls->transfer_ignore_list = make_array(p, 1, sizeof(char *));
	cls->remhost_ignore_list  = make_array(p, 1, sizeof(char *));
	cls->notes_list           = make_array(p, 1, sizeof(char *));
	cls->hin_list             = make_array(p, 1, sizeof(char *));
	cls->hout_list            = make_array(p, 1, sizeof(char *));
	cls->cookie_list          = make_array(p, 1, sizeof(char *));
	cls->table_made = 0;
	cls->cookie_name = NULL;

	return (void *) cls;
}


/* Setup of the available httpd.conf configuration commands.
 * Structure: command, function called, NULL, where available, how many arguments, verbose description
 */
command_rec log_sql_cmds[] = {
	{"LogSQLTransferLogTable", set_log_sql_transfer_table, 			NULL, 	RSRC_CONF, 	TAKE1,
	 "The database table that holds the transfer log"}
	,
	{"LogSQLNotesLogTable", set_log_sql_notes_table,	    		NULL, 	RSRC_CONF, 	TAKE1,
	 "The database table that holds the notes"}
	,
	{"LogSQLHeadersOutLogTable", set_log_sql_hout_table,    		NULL, 	RSRC_CONF, 	TAKE1,
	 "The database table that holds the outbound headers"}
	,
	{"LogSQLHeadersInLogTable", set_log_sql_hin_table,	    		NULL, 	RSRC_CONF, 	TAKE1,
	 "The database table that holds the inbound headers"}
	,
	{"LogSQLCookieLogTable", set_log_sql_cookie_table,	    		NULL, 	RSRC_CONF, 	TAKE1,
	 "The database table that holds the cookie info"}
	,
	{"LogSQLTransferLogFormat", set_log_sql_transfer_log_format,	NULL, 	RSRC_CONF, 	TAKE1,
	 "Instruct the module what information to log to the database transfer log"}
	,
	{"LogSQLMachineID", set_log_sql_machine_id,						NULL, 	RSRC_CONF, 	TAKE1,
	 "Machine ID that the module will log, useful in web clusters to differentiate machines"}
	,
	{"LogSQLRequestIgnore", add_log_sql_transfer_ignore, 			NULL, 	RSRC_CONF, 	ITERATE,
	 "List of URIs to ignore. Accesses that match will not be logged to database"}
	,
	{"LogSQLRemhostIgnore", add_log_sql_remhost_ignore, 			NULL, 	RSRC_CONF, 	ITERATE,
	 "List of remote hosts to ignore. Accesses that match will not be logged to database"}
	,
	{"LogSQLDatabase", set_log_sql_db, 								NULL, 	RSRC_CONF, 	TAKE1,
	 "The name of the database database for logging"}
	,
	{"LogSQLWhichCookie", set_log_sql_cookie, 						NULL, 	RSRC_CONF, 	TAKE1,
	 "The single cookie that you want logged in the access_log when using the 'c' config directive"}
	,
	{"LogSQLLoginInfo", set_log_sql_info, 							NULL, 	RSRC_CONF, 	TAKE3,
	 "The database host, user-id and password for logging"}
	,
	{"LogSQLCreateTables", set_log_sql_create,						NULL, 	RSRC_CONF, 	FLAG,
	 "Turn on module's capability to create its SQL tables on the fly"}
	,
	{"LogSQLMassVirtualHosting", set_log_sql_massvirtual,      		NULL,   RSRC_CONF,  FLAG,
	 "Activates option(s) useful for ISPs performing mass virutal hosting"}
	,
	{"LogSQLForcePreserve", set_log_sql_force_preserve,      		NULL,   RSRC_CONF,  FLAG,
	 "Forces logging to preserve file and bypasses database"}
	,
	{"LogSQLPreserveFile", set_log_sql_preserve_file,				NULL, 	RSRC_CONF, 	TAKE1,
	 "Name of the file to use for data preservation during database downtime"}
	,
	{"LogSQLSocketFile", set_log_sql_socket_file,					NULL, 	RSRC_CONF, 	TAKE1,
	 "Name of the file to employ for socket connections to database"}
	,
	{"LogSQLTCPPort", set_log_sql_tcp_port,							NULL, 	RSRC_CONF, 	TAKE1,
	 "Port number to use for TCP connections to database, defaults to 3306 if not set"}
	,
	{"LogSQLWhichNotes", add_log_sql_note,							NULL,	RSRC_CONF,	ITERATE,
	 "Notes that you would like to log in a separate table"}
	,
	{"LogSQLWhichHeadersOut", add_log_sql_hout,						NULL,	RSRC_CONF,	ITERATE,
	 "Outbound headers that you would like to log in a separate table"}
	,
	{"LogSQLWhichHeadersIn", add_log_sql_hin,						NULL,	RSRC_CONF,	ITERATE,
	 "Inbound headers that you would like to log in a separate table"}
	,
	{"LogSQLWhichCookies", add_log_sql_cookie,	 					NULL, 	RSRC_CONF, 	ITERATE,
	 "The cookie(s) that you would like to log in a separate table"}
	,
	{NULL}
};



/* Routine to perform the actual construction and execution of the relevant
 * INSERT statements.
 */
int log_sql_transaction(request_rec *orig)
{
	char **ptrptr, **ptrptr2;
	log_sql_state *cls = get_module_config(orig->server->module_config, &sql_log_module);
	const char *access_query;
	request_rec *r;

	/* We handle mass virtual hosting differently.  Dynamically determine the name
	 * of the table from the virtual server's name, and flag it for creation.
	 */
	if ( massvirtual == 1 ) {
		char *access_base = "access_";
		char *notes_base = "notes_";
		char *hout_base = "headout_";
		char *hin_base = "headin_";
		char *cookie_base = "cookies_";
		char *a_tablename;
		char *n_tablename;
		char *i_tablename;
		char *o_tablename;
		char *c_tablename;
		int i;

		/* Find memory long enough to hold the table name + \0. */
		a_tablename = ap_pstrcat(orig->pool, access_base, ap_get_server_name(orig), NULL);
		n_tablename = ap_pstrcat(orig->pool, notes_base,  ap_get_server_name(orig), NULL);
		i_tablename = ap_pstrcat(orig->pool, hin_base,    ap_get_server_name(orig), NULL);
		o_tablename = ap_pstrcat(orig->pool, hout_base,   ap_get_server_name(orig), NULL);
		c_tablename = ap_pstrcat(orig->pool, cookie_base, ap_get_server_name(orig), NULL);

		/* Transform any dots to underscores */
		for (i = 0; i < strlen(a_tablename); i++) {
			if (a_tablename[i] == '.')
			  a_tablename[i] = '_';
		}
		for (i = 0; i < strlen(n_tablename); i++) {
			if (n_tablename[i] == '.')
			  n_tablename[i] = '_';
		}
		for (i = 0; i < strlen(i_tablename); i++) {
			if (i_tablename[i] == '.')
			  i_tablename[i] = '_';
		}
		for (i = 0; i < strlen(o_tablename); i++) {
			if (o_tablename[i] == '.')
			  o_tablename[i] = '_';
		}
		for (i = 0; i < strlen(c_tablename); i++) {
			if (c_tablename[i] == '.')
			  c_tablename[i] = '_';
		}

		/* Tell this virtual server its transfer table name, and
		 * turn on create_tables, which is implied by massvirtual.
		 */
		cls->transfer_table_name = a_tablename;
		cls->notes_table_name = n_tablename;
		cls->hout_table_name = o_tablename;
		cls->hin_table_name = i_tablename;
		cls->cookie_table_name = c_tablename;
		create_tables = 1;
	}

	/* Do we have enough info to log? */
	if ( cls->transfer_table_name == NULL ) {
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
		int i, j, length;
		int result;

		for (r = orig; r->next; r = r->next) {
			continue;
		}

		/* The following is a stolen upsetting mess of pointers, I'm sorry.
		 * Anyone with the motiviation and/or the time should feel free
		 * to make this cleaner. :) */
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

		length = strlen(cls->transfer_log_format);

		/* Iterate through the format characters and set up the INSERT string according to
		 * what the user has configured. */
		for (i = 0; i < length; i++) {
			j = 0;

			while (log_sql_item_keys[j].ch) {

				  if (log_sql_item_keys[j].ch == cls->transfer_log_format[i]) {
					/* Yes, this key is one of the configured keys.
					 * Call the key's function and put the returned value into 'formatted_item' */
					formatted_item = log_sql_item_keys[j].func(log_sql_item_keys[j].want_orig_default ? orig : r, "");

				     /* Massage 'formatted_item' for proper SQL eligibility... */
					if (!formatted_item) {
						formatted_item = "";
					} else if (formatted_item[0] == '-' && formatted_item[1] == '\0' && !log_sql_item_keys[j].string_contents) {
						/* If apache tried to log a '-' character for a numeric field, convert that to a zero
						 * because the database expects a numeral and will reject the '-' character. */
						formatted_item = "0";
					}

				     /* Append the fieldname and value-to-insert to the appropriate strings, quoting stringvals with ' as appropriate */
					fields = pstrcat(r->pool, fields, (i > 0 ? "," : ""),
									 log_sql_item_keys[j].sql_field_name, NULL);

					values = pstrcat(r->pool, values, (i > 0 ? "," : ""),
									 (log_sql_item_keys[j].string_contents ? "'" : ""),
								     escape_query(formatted_item, r->pool),
									 (log_sql_item_keys[j].string_contents ? "'" : ""), NULL);
					break;
				}
				j++;

			}
		}

		/* Work through the list of notes defined by LogSQLWhichNotes */
		i = 0;
		unique_id = extract_unique_id(r, "");

		ptrptr2 = (char **) (cls->notes_list->elts + (cls->notes_list->nelts * cls->notes_list->elt_size));
		for (ptrptr = (char **) cls->notes_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->notes_list->elt_size)) {
			/* If the specified note (*ptrptr) exists for the current request... */
		    if ((theitem = ap_table_get(r->notes, *ptrptr))) {
				itemsets = ap_pstrcat(r->pool, itemsets,
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
			note_query = ap_pstrcat(r->pool, insert_stmt, "`", cls->notes_table_name, "` (id, item, val) values ", itemsets, NULL);
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,orig->server,"mod_log_sql: note string: %s", note_query);
		   	#endif
		}

		/* Work through the list of headers-out defined by LogSQLWhichHeadersOut*/
		i = 0;
		itemsets = "";

		ptrptr2 = (char **) (cls->hout_list->elts + (cls->hout_list->nelts * cls->hout_list->elt_size));
		for (ptrptr = (char **) cls->hout_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->hout_list->elt_size)) {
			/* If the specified header (*ptrptr) exists for the current request... */
		    if ((theitem = ap_table_get(r->headers_out, *ptrptr))) {
				itemsets = ap_pstrcat(r->pool, itemsets,
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
		    hout_query = ap_pstrcat(r->pool, insert_stmt, "`", cls->hout_table_name, "` (id, item, val) values ", itemsets, NULL);
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,orig->server,"mod_log_sql: header_out string: %s", hout_query);
		   	#endif
		}


		/* Work through the list of headers-in defined by LogSQLWhichHeadersIn */
		i = 0;
		itemsets = "";

		ptrptr2 = (char **) (cls->hin_list->elts + (cls->hin_list->nelts * cls->hin_list->elt_size));
		for (ptrptr = (char **) cls->hin_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->hin_list->elt_size)) {
			/* If the specified header (*ptrptr) exists for the current request... */
		    if ((theitem = ap_table_get(r->headers_in, *ptrptr))) {
				itemsets = ap_pstrcat(r->pool, itemsets,
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
			hin_query = ap_pstrcat(r->pool, insert_stmt, "`", cls->hin_table_name, "` (id, item, val) values ", itemsets, NULL);
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,orig->server,"mod_log_sql: header_in string: %s", hin_query);
		   	#endif
		}


		/* Work through the list of cookies defined by LogSQLWhichCookies */
		i = 0;
		itemsets = "";

		ptrptr2 = (char **) (cls->cookie_list->elts + (cls->cookie_list->nelts * cls->cookie_list->elt_size));
		for (ptrptr = (char **) cls->cookie_list->elts; ptrptr < ptrptr2; ptrptr = (char **) ((char *) ptrptr + cls->cookie_list->elt_size)) {
			/* If the specified cookie (*ptrptr) exists for the current request... */
		    if ( strncmp((theitem = extract_specific_cookie(r, *ptrptr)), "-", 1) ) {
				itemsets = ap_pstrcat(r->pool, itemsets,
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
			cookie_query = ap_pstrcat(r->pool, insert_stmt, "`", cls->cookie_table_name, "` (id, item, val) values ", itemsets, NULL);
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,orig->server,"mod_log_sql: cookie string: %s", cookie_query);
		   	#endif
		}


		/* Set up the actual INSERT statement */
		access_query = ap_pstrcat(r->pool, insert_stmt, "`", cls->transfer_table_name, "` (", fields, ") values (", values, ")", NULL);

		#ifdef DEBUG
	        ap_log_error(APLOG_MARK,DEBUGLEVEL,r->server,"mod_log_sql: access string: %s", access_query);
	    #endif

		/* If the person activated force-preserve, go ahead and push all the entries
		 * into the preserve file, then return.
		 */
		if (force_preserve) {
			#ifdef DEBUG
				ap_log_error(APLOG_MARK,DEBUGLEVEL,orig->server,"mod_log_sql: preservation forced");
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
		if (mysql_log == NULL) {

			/* Make a try to establish the link */
			open_logdb_link(r->server);

			if (mysql_log == NULL) {
				/* Unable to re-establish a DB link, so assume that it's really
				 * gone and send the entry to the preserve file instead.
				 * This short-circuits safe_mysql_query during a db outage and therefore
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
				ap_log_error(APLOG_MARK,NOTICELEVEL,orig->server,"mod_log_sql: child established database connection");
			}
		}


		/* ---> So as of here we have a non-null value of mysql_log. <--- */
		/* ---> i.e. we have a good MySQL connection.                <--- */


		/* Make the tables if we're supposed to. */
		if ((cls->table_made != 1) && (create_tables != 0)) {
			result = safe_create_tables(cls, orig);
			if (result != 0)
			  	ap_log_error(APLOG_MARK,ERRLEVEL,orig->server,"mod_log_sql: child attempted but failed to create one or more tables for %s", ap_get_server_name(orig));
			else
			    ap_log_error(APLOG_MARK,NOTICELEVEL,orig->server,"mod_log_sql: no problems creating tables for %s", ap_get_server_name(orig));
		}

  	    /* Make the access-table insert */
		result = safe_mysql_query(orig, access_query);

		/* It failed, but NOT because table didn't exist */
		if ( (result != 0) && (result != 1146) )
		 	preserve_entry(orig,access_query);

		/* It failed because table didn't exist */
		if (result == 1146) {
			ap_log_error(APLOG_MARK,ERRLEVEL,orig->server,"mod_log_sql: hmm, table didn't yet exist; creating");
			result = safe_create_tables(cls, orig);
			if (result != 0) {
				ap_log_error(APLOG_MARK,ERRLEVEL,orig->server,"mod_log_sql: child attempted but failed to create one or more tables for %s, preserving query", ap_get_server_name(orig));
				preserve_entry(orig,access_query);
			} else {
				ap_log_error(APLOG_MARK,ERRLEVEL,orig->server,"mod_log_sql: table successfully created, query will now be retried");
				result = safe_mysql_query(orig, access_query);
				if (result != 0 ) {
					ap_log_error(APLOG_MARK,ERRLEVEL,orig->server,"mod_log_sql: giving up, preserving query");
					preserve_entry(orig,access_query);
					return OK;
				}
   			}
		}

		/* Log the optional notes, headers, etc. */
		if ( note_query != NULL )
			safe_mysql_query(orig, note_query);

		if ( hout_query != NULL )
		  	safe_mysql_query(orig, hout_query);

		if ( hin_query != NULL )
		  	safe_mysql_query(orig, hin_query);

		if ( cookie_query != NULL )
		  	safe_mysql_query(orig, cookie_query);

		return OK;
	}
}




/* The configuration array that sets up the hooks into the module. */
module sql_log_module = {
	STANDARD_MODULE_STUFF,
	NULL,					 /* module initializer 				*/
	NULL,					 /* create per-dir config 			*/
	NULL,					 /* merge per-dir config 			*/
	log_sql_make_state,		 /* create server config 			*/
	NULL,					 /* merge server config 			*/
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
