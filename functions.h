/* $Header: /home/cvs/mod_log_sql/functions.h,v 1.1 2004/01/20 19:38:08 urkle Exp $ */
/* Begin the individual functions that, given a request r,
 * extract the needed information from it and return the
 * value to the calling entity.
 */

static const char *extract_remote_host(request_rec *r, char *a)
{
	return (char *) ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
}

static const char *extract_remote_logname(request_rec *r, char *a)
{
	return (char *) ap_get_remote_logname(r);
}

static const char *extract_remote_user(request_rec *r, char *a)
{
	#ifdef WITH_APACHE13
	char *rvalue = r->connection->user;
	#else
	char *rvalue = r->user;
	#endif
	if (rvalue == NULL) {
		rvalue = "-";
	} else if (strlen(rvalue) == 0) {
		rvalue = "\"\"";
	}
	return rvalue;
}

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

static const char *extract_request_args(request_rec *r, char *a)
{
	return r->args;
}

static const char *extract_status(request_rec *r, char *a)
{
	if (r->status <= 0) {
		return "-";
	} else {
		return apr_psprintf(r->pool, "%d", r->status);
	}
}

static const char *extract_bytes_sent(request_rec *r, char *a)
{
	if (!r->sent_bodyct || !r->bytes_sent) {
		return "-";
	} else {
		return apr_psprintf(r->pool, "%" APR_OFF_T_FMT, r->bytes_sent);
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

static const char *extract_virtual_host(request_rec *r, char *a)
{
    return apr_pstrdup(r->pool, r->server->server_hostname);
}

static const char *extract_machine_id(request_rec *r, char *a)
{
	if (!global_config.machid)
		return "-";
	else
		return global_config.machid;
}

static const char *extract_server_port(request_rec *r, char *a)
{
    return apr_psprintf(r->pool, "%u",
                        r->server->port ? r->server->port : ap_default_port(r));
}

static const char *extract_child_pid(request_rec *r, char *a)
{
    if (*a == '\0' || !strcmp(a, "pid")) {
        return apr_psprintf(r->pool, "%" APR_PID_T_FMT, getpid());
    }
    else if (!strcmp(a, "tid")) {
#if APR_HAS_THREADS
        apr_os_thread_t tid = apr_os_thread_current();
#else
        int tid = 0; /* APR will format "0" anyway but an arg is needed */
#endif
        return apr_psprintf(r->pool, "%pT", &tid);
    }
    /* bogus format */
    return a;
}

static const char *extract_referer(request_rec *r, char *a)
{
	const char *tempref;

	tempref = apr_table_get(r->headers_in, "Referer");
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

    tempag = apr_table_get(r->headers_in, "User-Agent");
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

	logsql_state *cls = ap_get_module_config(r->server->module_config,
											&log_sql_module);

	if (cls->cookie_name != NULL) {
		#ifdef DEBUG
		  	log_error(APLOG_MARK,APLOG_DEBUG, r->server,
				"watching for cookie '%s'", cls->cookie_name);
		#endif

		/* Fetch out the cookie header */
	 	cookiestr  = (char *)apr_table_get(r->headers_in,  "cookie2");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG, r->server,
					"Cookie2: [%s]", cookiestr);
			#endif
			/* Does the cookie string contain one with our name? */
			isvalid = strstr(cookiestr, cls->cookie_name);
			if (isvalid != NULL) {
				/* Move past the cookie name and equal sign */
				isvalid += strlen(cls->cookie_name) + 1;
				/* Duplicate it into the pool */
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
				/* Segregate just this cookie out of the string
				 * with a terminating nul at the first semicolon */
			    cookieend = strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return cookiebuf;
			}
		}

	 	cookiestr  = (char *)apr_table_get(r->headers_in,  "cookie");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,r->server,
					"Cookie: [%s]", cookiestr);
			#endif
			isvalid = strstr(cookiestr, cls->cookie_name);
			if (isvalid != NULL) {
				isvalid += strlen(cls->cookie_name) + 1;
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
			    cookieend = strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return cookiebuf;
			}
		}

	 	cookiestr = apr_table_get(r->headers_out,  "set-cookie");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
			     log_error(APLOG_MARK,APLOG_DEBUG,r->server,
					"Set-Cookie: [%s]", cookiestr);
			#endif
			isvalid = strstr(cookiestr, cls->cookie_name);
			if (isvalid != NULL) {
			    isvalid += strlen(cls->cookie_name) + 1;
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
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
		  	log_error(APLOG_MARK,APLOG_DEBUG,
				r->server,"watching for cookie '%s'", a);
		#endif

		/* Fetch out the cookie header */
	 	cookiestr  = (char *)apr_table_get(r->headers_in,  "cookie2");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,r->server,
					"Cookie2: [%s]", cookiestr);
			#endif
			/* Does the cookie string contain one with our name? */
			isvalid = strstr(cookiestr, a);
			if (isvalid != NULL) {
				/* Move past the cookie name and equal sign */
				isvalid += strlen(a) + 1;
				/* Duplicate it into the pool */
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
				/* Segregate just this cookie out of the string
				 * with a terminating nul at the first semicolon */
			    cookieend = strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return cookiebuf;
			}
		}

	 	cookiestr  = (char *)apr_table_get(r->headers_in,  "cookie");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
				log_error(APLOG_MARK,APLOG_DEBUG,r->server,
					"Cookie: [%s]", cookiestr);
			#endif
			isvalid = strstr(cookiestr, a);
			if (isvalid != NULL) {
				isvalid += strlen(a) + 1;
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
			    cookieend = strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return cookiebuf;
			}
		}

	 	cookiestr = apr_table_get(r->headers_out,  "set-cookie");
	    if (cookiestr != NULL) {
			#ifdef DEBUG
			     log_error(APLOG_MARK,APLOG_DEBUG,r->server,
					"Set-Cookie: [%s]", cookiestr);
			#endif
			isvalid = strstr(cookiestr, a);
			if (isvalid != NULL) {
			    isvalid += strlen(a) + 1;
			    cookiebuf = apr_pstrdup(r->pool, isvalid);
			    cookieend = strchr(cookiebuf, ';');
			    if (cookieend != NULL)
			       *cookieend = '\0';
			  	return cookiebuf;
			}
		}
	}

	return "-";
}


/*
static const char *extract_note(request_rec *r, char *a)
{
	return apr_table_get(r->notes, a);

}
*/

static const char *extract_env_var(request_rec *r, char *a)
{
	return apr_table_get(r->subprocess_env, a);
}

static const char *extract_unique_id(request_rec *r, char *a)
{
    const char *tempid;

	tempid = apr_table_get(r->subprocess_env, "UNIQUE_ID");
	if (!tempid)
	  return "-";
	else
	  return tempid;
}

/* End declarations of various extract_ functions */
