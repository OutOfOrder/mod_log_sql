/* $Id: mod_log_sql.c,v 1.3 2001/12/03 19:54:02 helios Exp $
 *
 * mod_log_mysql.c
 * Release v 1.10
 *
 * Hi, I'm the new maintainer of this code.  If you have any questions,
 * comments or suggestions (which are always welcome), please contact Chris
 * Powell <chris@grubbybaby.com>.  This code still falls under the rules of
 * the Apache license, and all credit for the code up to my changes is still
 * preserved below.
 *
 * ====================================================================
 *
 * The original preface from version 1.05: This module was patched, wrapped
 * and coded by Zeev Suraski <bourbon@netvision.net.il>
 *
 * It may be used freely, with the same restrictions as its predecessors
 * (specified below).  This module is based on code from standard apache
 * modules.  Their copyright notice follows.
 *
 * ====================================================================
 * Copyright (c) 1995-1997 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/* DEFINES */
#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")

#define ERRLEVEL APLOG_ERR|APLOG_NOERRNO

#undef DEBUG
#ifdef DEBUG
	#define DEBUGLEVEL APLOG_INFO|APLOG_NOERRNO
#endif



/* INCLUDES */
#include <time.h>
#include <mysql/mysql.h>
#include <stdio.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#if MODULE_MAGIC_NUMBER >= 19980324
	#include "ap_compat.h"
#endif

#ifdef WANT_SSL_LOGGING
	#include "/usr/local/src/apache_1.3.22/src/modules/ssl/mod_ssl.h"
#endif



/* DECLARATIONS */
module mysql_log_module;
MYSQL log_sql_server, *mysql_log = NULL;
char *log_db_name = NULL, *db_host = NULL, *db_user = NULL, *db_pwd = NULL, *cookie_name = NULL;

typedef const char *(*item_key_func) (request_rec *, char *);
typedef struct {
	char *referer_table_name, *agent_table_name, *transfer_table_name;
	array_header *referer_ignore_list;
	array_header *transfer_ignore_list;
	array_header *remhost_ignore_list;
	char *transfer_log_format;
} log_mysql_state;



#if MODULE_MAGIC_NUMBER < 19970103  /* Defined in /usr/local/Apache/include/ap_mmn.h, 19990320 as of this writing. */
extern const char *log_request_protocol(request_rec *r, char *a);
extern const char *log_request_method(request_rec *r, char *a);
extern const char *log_remote_host(request_rec *r, char *a);
extern const char *log_remote_logname(request_rec *r, char *a);
extern const char *log_remote_user(request_rec *r, char *a);
extern const char *log_request_time(request_rec *r, char *a);
extern const char *log_request_timestamp(request_rec *r, char *a);
extern const char *log_request_duration(request_rec *r, char *a);
extern const char *log_request_line(request_rec *r, char *a);
extern const char *log_request_file(request_rec *r, char *a);
extern const char *log_request_uri(request_rec *r, char *a);
extern const char *log_status(request_rec *r, char *a);
extern const char *log_bytes_sent(request_rec *r, char *a);
extern const char *log_header_in(request_rec *r, char *a);
extern const char *log_header_out(request_rec *r, char *a);
extern const char *log_note(request_rec *r, char *a);
extern const char *log_env_var(request_rec *r, char *a);
extern const char *log_virtual_host(request_rec *r, char *a);
extern const char *log_server_port(request_rec *r, char *a);
extern const char *log_child_pid(request_rec *r, char *a);
#else

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

static const char *log_remote_host(request_rec *r, char *a)
{
	return (char *) get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME);
}

static const char *log_remote_logname(request_rec *r, char *a)
{
	return (char *) get_remote_logname(r);
}

static const char *log_remote_user(request_rec *r, char *a)
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
static const char *log_ssl_keysize(request_rec *r, char *a)
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

static const char *log_ssl_maxkeysize(request_rec *r, char *a)
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

static const char *log_ssl_cipher(request_rec *r, char *a)
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
		return "0";
	}
}
#endif /* WANT_SSL_LOGGING */

static const char *log_request_method(request_rec *r, char *a)
{
	return r->method;
}

static const char *log_request_protocol(request_rec *r, char *a)
{
	return r->protocol;
}

static const char *log_request_line(request_rec *r, char *a)
{
	return r->the_request;
}

static const char *log_request_file(request_rec *r, char *a)
{
	return r->filename;
}

static const char *log_request_uri(request_rec *r, char *a)
{
	return r->uri;
}

static const char *log_status(request_rec *r, char *a)
{
	return pfmt(r->pool, r->status);
}

static const char *log_bytes_sent(request_rec *r, char *a)
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

static const char *log_header_in(request_rec *r, char *a)
{
	return table_get(r->headers_in, a);
}

static const char *log_header_out(request_rec *r, char *a)
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

static const char *log_request_time(request_rec *r, char *a)
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

static const char *log_request_duration(request_rec *r, char *a)
{
	char duration[22];			 /* Long enough for 2^64 */

	ap_snprintf(duration, sizeof(duration), "%ld", time(NULL) - r->request_time);
	return pstrdup(r->pool, duration);
}

static const char *log_virtual_host(request_rec *r, char *a)
{
	return pstrdup(r->pool, r->server->server_hostname);
}

static const char *log_server_port(request_rec *r, char *a)
{
	char portnum[22];

	ap_snprintf(portnum, sizeof(portnum), "%u", r->server->port);
	return pstrdup(r->pool, portnum);
}

static const char *log_child_pid(request_rec *r, char *a)
{
	char pidnum[22];
	ap_snprintf(pidnum, sizeof(pidnum), "%ld", (long) getpid());
	return pstrdup(r->pool, pidnum);
}

static const char *log_referer(request_rec *r, char *a)
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

static const char *log_agent(request_rec *r, char *a)
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

static const char *log_cookie(request_rec *r, char *a)
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


const char *log_request_timestamp(request_rec *r, char *a)
{
	char tstr[32];

	snprintf(tstr, 32, "%ld", time(NULL));
	return pstrdup(r->pool, tstr);
}

static const char *log_note(request_rec *r, char *a)
{
	return table_get(r->notes, a);
}

static const char *log_env_var(request_rec *r, char *a)
{
	return table_get(r->subprocess_env, a);
}
#endif /* MODULE_MAGIC_NUMBER */


/* End declarations of various log_ functions */


struct log_mysql_item_list {
	  char ch;
	  item_key_func func;
	  const char *sql_field_name;
	  int want_orig_default;
	  int string_contents;
    } log_mysql_item_keys[] = {

	{   'A', log_agent,             "agent",            1, 1    },
    {   'b', log_bytes_sent,        "bytes_sent",       0, 0    },
    {   'c', log_cookie,            "cookie",           0, 1    },
    {   'e', log_env_var,           "env_var",          0, 1    },
    {   'f', log_request_file,      "request_file",     0, 1    },
	{   'H', log_request_protocol,  "request_protocol", 0, 1    },
	{   'h', log_remote_host,       "remote_host",      0, 1    },
    {   'i', log_header_in,         "header_in",        0, 1    },
    {   'l', log_remote_logname,    "remote_logname",   0, 1    },
	{	'm', log_request_method,    "request_method",   0, 1    },
	{   'n', log_note,              "note",             0, 1    },
    {   'o', log_header_out,        "header_out",       0, 1    },
    {   'P', log_child_pid,         "child_pid",        0, 0    },
    {   'p', log_server_port,       "server_port",      0, 0    },
    {   'R', log_referer,           "referer",          1, 1    },
    {   'r', log_request_line,      "request_line",     1, 1    },
    {   'S', log_request_timestamp, "time_stamp",       0, 0    },
    {   's', log_status,            "status",           1, 0    },
    {   'T', log_request_duration,  "request_duration", 1, 0    },
    {   't', log_request_time,      "request_time",     0, 1    },
    {   'u', log_remote_user,       "remote_user",      0, 1    },
    {   'U', log_request_uri,       "request_uri",      1, 1    },
    {   'v', log_virtual_host,      "virtual_host",     0, 1    },
	#ifdef WANT_SSL_LOGGING
    {   'q', log_ssl_keysize,       "ssl_keysize",      0, 1    },
    {   'Q', log_ssl_maxkeysize,    "ssl_maxkeysize",   0, 1    },
    {   'z', log_ssl_cipher,        "ssl_cipher",       0, 1    },
	#endif
	{'\0'}
};


/* Routine to escape 'dangerous' characters that would otherwise
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
		tmp_str = (char *) palloc(p, length *2 + 1);
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


void open_log_dblink()
{
	if (mysql_log != NULL) {		 /* virtual database link shared with main server */
		return;
	}
	if (log_db_name) {			 /* open an SQL link */
		mysql_log = mysql_connect(&log_sql_server, db_host, db_user, db_pwd);
		if (mysql_log) {		 /* link opened */
			if (mysql_select_db(mysql_log, log_db_name) != 0) {	/* unable to select database */
				mysql_close(mysql_log);
				mysql_log = NULL;
			}
		}
	}
}


void *make_log_mysql_state(pool *p, server_rec *s)
{
	log_mysql_state *cls = (log_mysql_state *) palloc(p, sizeof(log_mysql_state));

	cls->referer_table_name = cls->agent_table_name = cls->transfer_table_name = "";
	cls->referer_ignore_list = make_array(p, 1, sizeof(char *));
	cls->transfer_ignore_list = make_array(p, 1, sizeof(char *));
	cls->remhost_ignore_list = make_array(p, 1, sizeof(char *));
	cls->transfer_log_format = "";
	return (void *) cls;
}

const char *set_referer_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	cls->referer_table_name = arg;
	return NULL;
}


const char *set_agent_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	cls->agent_table_name = arg;
	return NULL;
}


const char *set_transfer_log_mysql_table(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	cls->transfer_table_name = arg;
	return NULL;
}


const char *set_transfer_log_format(cmd_parms *parms, void *dummy, char *arg)
{
	log_mysql_state *cls = get_module_config(parms->server->module_config,
						 &mysql_log_module);

	cls->transfer_log_format = arg;
	return NULL;
}


const char *set_log_mysql_db(cmd_parms *parms, void *dummy, char *arg)
{
	log_db_name = arg;
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

command_rec log_mysql_cmds[] = {
	{"MySQLRefererLogTable", set_referer_log_mysql_table, NULL, RSRC_CONF, TAKE1,
	 "The MySQL table that holds the referer log"}
	,
	{"MySQLAgentLogTable", set_agent_log_mysql_table, NULL, RSRC_CONF, TAKE1,
	 "The MySQL table that holds the agent log"}
	,
	{"MySQLTransferLogTable", set_transfer_log_mysql_table, NULL, RSRC_CONF, TAKE1,
	 "The MySQL table that holds the transfer log"}
	,
	{"MySQLTransferLogFormat", set_transfer_log_format, NULL, RSRC_CONF, TAKE1,
	 "Instruct the module what information to log to the MySQL transfer log"}
	,
	{"MySQLRefererIgnore", add_referer_mysql_ignore, NULL, RSRC_CONF, ITERATE,
	 "List of referers to ignore, accesses that match will not be logged to MySQL"}
	,
	{"MySQLRequestIgnore", add_transfer_mysql_ignore, NULL, RSRC_CONF, ITERATE,
	 "List of URIs to ignore, accesses that match will not be logged to MySQL"}
	,
	{"MySQLRemhostIgnore", add_remhost_mysql_ignore, NULL, RSRC_CONF, ITERATE,
	 "List of remote hosts to ignore, accesses that match will not be logged to MySQL"}
	,
	{"MySQLDatabase", set_log_mysql_db, NULL, RSRC_CONF, TAKE1,
	 "The name of the MySQL database for logging"}
	,
	{"MySQLWhichCookie", set_log_mysql_cookie, NULL, RSRC_CONF, TAKE1,
	 "The CookieName that you want logged when using the 'c' config directive"}
	,
	{"MySQLLoginInfo", set_log_mysql_info, NULL, RSRC_CONF, TAKE3,
	 "The MySQL host, user-id and password for logging"}
	,
	{NULL}
};


int safe_mysql_query(request_rec *r, const char *query)
{
	int error = 1;
	struct timespec delay, remainder;
	int ret;
	char *str;
	void (*handler) (int);

	/* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
	handler = signal(SIGPIPE, SIG_IGN);	 

	/* If there's no DB link, or if we run the query and it gacks, try to be graceful */
	if ( !mysql_log || 
	     (
	        (error = mysql_query(mysql_log, query)) && 
	        !strcasecmp(mysql_error(mysql_log), "MySQL server has gone away")
	     )
	   ) 
	   
	   {    /* We need to restart the server link */
		    mysql_log = NULL;
		    ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: connection lost, attempting reconnect");

    		open_log_dblink();

    		if (mysql_log == NULL) {	 /* still unable to link */
    			signal(SIGPIPE, handler);
    			ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: reconnect failed.");
    			return error;
    		}

    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL:  reconnect successful.");
    		error = mysql_query(mysql_log, query);
	}

	/* Restore SIGPIPE to its original handler function */
	signal(SIGPIPE, handler);

	if (error) {
	    /* Attempt a single re-try... First sleep for a tiny amount of time. */
        delay.tv_sec = 0;
        delay.tv_nsec = 500000000;  /* max is 999999999 (nine nines) */
        ret = nanosleep(&delay, &remainder);
        if (ret && errno != EINTR)
           perror("nanosleep");

        /* Now re-attempt */
	    error = mysql_query(mysql_log,query);

	    if (error) {
    		str = pstrcat(r->pool, "MySQL query failed:  ", query, NULL);
    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,str);
    		str = pstrcat(r->pool, "MySQL failure reason:  ", MYSQL_ERROR(mysql_log), NULL);
    		ap_log_error(APLOG_MARK,ERRLEVEL,r->server,str);
    	} else {
    	    ap_log_error(APLOG_MARK,ERRLEVEL,r->server,"MySQL: insert successful after a delayed retry.");
    	}
	}
	return error;
}


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
		open_log_dblink();
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



module mysql_log_module = {
	STANDARD_MODULE_STUFF,
	NULL,					 /* initializer */
	NULL,					 /* create per-dir config */
	NULL,					 /* merge per-dir config */
	make_log_mysql_state,	 /* server config */
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
	NULL					 /* header parser */
};
