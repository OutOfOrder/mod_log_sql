/* $Header: /home/cvs/mod_log_sql/functions13.h,v 1.2 2004/01/20 19:38:08 urkle Exp $ */
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
	char duration[22];			 /* Long enough for 2^64 */

	ap_snprintf(duration, sizeof(duration), "%ld", (long) time(NULL) - r->request_time);
	return ap_pstrdup(r->pool, duration);
}

static const char *extract_request_timestamp(request_rec *r, char *a)
{
	char tstr[32];

	ap_snprintf(tstr, 32, "%ld", (long) time(NULL));
	return ap_pstrdup(r->pool, tstr);
}
