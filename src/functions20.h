/* $Id$ */

#ifndef WITH_LOGIO_MOD
static const char *extract_bytes_sent(request_rec *r, char *a)
{
    if (!r->sent_bodyct || !r->bytes_sent) {
	return "-";
    } else {
	return apr_psprintf(r->pool, "%" APR_OFF_T_FMT, r->bytes_sent);
    }
}
#endif

static const char *extract_request_time(request_rec *r, char *a)
{
    apr_time_exp_t xt;

    ap_explode_recent_gmt(&xt, r->request_time);

    return apr_psprintf(r->pool, "%04d-%02d-%02d %02d:%02d:%02d",
        xt.tm_year + 1900, xt.tm_mon, xt.tm_mday,
        xt.tm_hour, xt.tm_min, xt.tm_sec );
}

static const char *extract_request_duration(request_rec *r, char *a)
{
    apr_time_t duration = apr_time_now() - r->request_time;
    return apr_psprintf(r->pool, "%" APR_TIME_T_FMT, apr_time_sec(duration));
}

static const char *extract_request_timestamp(request_rec *r, char *a)
{
    return apr_psprintf(r->pool, "%" APR_TIME_T_FMT, apr_time_sec(apr_time_now()));
}

static const char *extract_connection_status(request_rec *r, char *a)
{
    if (r->connection->aborted)
	return "X";

    if (r->connection->keepalive == AP_CONN_KEEPALIVE &&
	(!r->server->keep_alive_max || (r->server->keep_alive_max - r->connection->keepalives) > 0)) {
	return "+";
    }
    return NULL;
}
