/* $Id$ */

static const char *extract_bytes_sent(request_rec *r, char *a)
{
    if (!r->sent_bodyct) {
        return "-";
    }
    else {
        long int bs;
        ap_bgetopt(r->connection->client, BO_BYTECT, &bs);
	return ap_psprintf(r->pool, "%ld", bs);
    }
}

static const char *extract_request_time(request_rec *r, char *a)
{
	int timz;
	struct tm *t;
	char tstr[MAX_STRING_LEN];

	t = ap_get_gmtoff(&timz);

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

	return ap_pstrdup(r->pool, tstr);
}

static const char *extract_request_duration(request_rec *r, char *a)
{
	return ap_psprintf(r->pool, "%ld", time(NULL) - r->request_time);
}

static const char *extract_request_timestamp(request_rec *r, char *a)
{
	return ap_psprintf(r->pool, "%ld", (long) time(NULL));
}
static const char *extract_connection_status(request_rec *r, char *a) __attribute__((unused));
static const char *extract_connection_status(request_rec *r, char *a)
{
    if (r->connection->aborted)
        return "X";

    if ((r->connection->keepalive) && 
        ((r->server->keep_alive_max - r->connection->keepalives) > 0)) {
        return "+";
    }
    return "-";
}
