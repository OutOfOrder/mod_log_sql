/* $Id$ */

/* Begin the individual functions that, given a request r,
 * extract the needed information from it and return the
 * value to the calling entity.
 */

static const char *extract_remote_host(request_rec *r, char *a)
{
    return (char *) ap_get_useragent_host(r, REMOTE_NAME, NULL);
}

static const char *extract_remote_address(request_rec *r, char *a)
{
    return r->useragent_ip;
}

static const char *extract_local_address(request_rec *r, char *a)
{
    return r->connection->local_ip;
}

static const char *extract_remote_logname(request_rec *r, char *a)
{
    return (char *) ap_get_remote_logname(r);
}

static const char *extract_remote_user(request_rec *r, char *a)
{
    return r->user;
}

static const char *extract_request_line(request_rec *r, char *a)
{
    /* Upddated to mod_log_config logic */
    /* NOTE: If the original request contained a password, we
     * re-write the request line here to contain XXXXXX instead:
     * (note the truncation before the protocol string for HTTP/0.9 requests)
     * (note also that r->the_request contains the unmodified request)
     */
    return (r->parsed_uri.password)
	? apr_pstrcat(r->pool, r->method, " ",
		      apr_uri_unparse(r->pool, &r->parsed_uri, 0), r->assbackwards ? NULL : " ", r->protocol, NULL)
	: r->the_request;
}

static const char *extract_request_file(request_rec *r, char *a)
{
    return r->filename;
}

static const char *extract_request_uri(request_rec *r, char *a)
{
    return r->uri;
}

static const char *extract_request_method(request_rec *r, char *a)
{
    return r->method;
}

static const char *extract_request_protocol(request_rec *r, char *a)
{
    return r->protocol;
}

static const char *extract_request_query(request_rec *r, char *a)
{
    return (r->args) ? apr_pstrcat(r->pool, "?", r->args, NULL)
	: NULL;
}

static const char *extract_status(request_rec *r, char *a)
{
    if (r->status <= 0) {
	return NULL;
    } else {
	return apr_psprintf(r->pool, "%d", r->status);
    }
}

static const char *extract_virtual_host(request_rec *r, char *a)
{
    return r->server->server_hostname;
}

static const char *extract_server_name(request_rec *r, char *a)
{
    return ap_get_server_name(r);
}

static const char *extract_machine_id(request_rec *r, char *a)
{
    return global_config.machid;
}

static const char *extract_server_port(request_rec *r, char *a)
{
    return apr_psprintf(r->pool, "%u", r->server->port ? r->server->port : ap_default_port(r));
}

static const char *extract_child_pid(request_rec *r, char *a)
{
    if (*a == '\0' || !strcmp(a, "pid")) {
	return apr_psprintf(r->pool, "%" APR_PID_T_FMT, getpid());
    } else if (!strcmp(a, "tid")) {
#if APR_HAS_THREADS
	apr_os_thread_t tid = apr_os_thread_current();
#else
	int tid = 0;		/* APR will format "0" anyway but an arg is needed */
#endif
	return apr_psprintf(r->pool, "%pT", &tid);
    }
    return NULL;
}

static const char *extract_referer(request_rec *r, char *a)
{
    return apr_table_get(r->headers_in, "Referer");
}

static const char *extract_agent(request_rec *r, char *a)
{
    return apr_table_get(r->headers_in, "User-Agent");
}


static const char *extract_specific_cookie(request_rec *r, char *a)
{
    const char *cookiestr;
    const char *cookiebuf;

    char *check_cookiestr(void) {
	char *cookieend;
	char *isvalid;
	char *cookie;

	if (cookiestr != NULL) {
	    /* Does the cookie string contain one with our name? */
	    isvalid = ap_strstr_c(cookiestr, a);
	    if (isvalid != NULL) {
		/* Move past the cookie name and equal sign */
		isvalid += strlen(a) + 1;
		/* Duplicate it into the pool */
		cookie = apr_pstrdup(r->pool, isvalid);
		/* Segregate just this cookie out of the string
		 * with a terminating nul at the first semicolon */
		cookieend = ap_strchr(cookie, ';');
		if (cookieend != NULL)
		    *cookieend = '\0';
		return cookie;
	    }
	}
	return NULL;
    }

    if (a != NULL) {
	/* Fetch out the cookie header */
	cookiestr = (char *) apr_table_get(r->headers_in, "cookie2");
	if ((cookiebuf = check_cookiestr()) != NULL)
	    return cookiebuf;

	/* Fetch out the cookie header */
	cookiestr = (char *) apr_table_get(r->headers_in, "cookie");
	if ((cookiebuf = check_cookiestr()) != NULL)
	    return cookiebuf;

	/* Fetch out the cookie header */
	cookiestr = apr_table_get(r->headers_out, "set-cookie");
	if ((cookiebuf = check_cookiestr()) != NULL)
	    return cookiebuf;
    }
    return NULL;
}

static const char *extract_cookie(request_rec *r, char *a)
{
    logsql_state *cls = ap_get_module_config(r->server->module_config, &log_sql_module);

    return extract_specific_cookie(r, (char *)cls->cookie_name);
}

static const char *extract_unique_id(request_rec *r, char *a)
{
    return apr_table_get(r->subprocess_env, "UNIQUE_ID");
}

/* End declarations of various extract_ functions */
