/* $Header: /home/cvs/mod_log_sql/apache20.h,v 1.2 2004/01/20 19:38:07 urkle Exp $ */
#ifndef APACHE20_H
#define APACHE20_H

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_tables.h"

#include "ap_config.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include "util_time.h"

static void log_error(char *file, int line, int level, const server_rec *s, const char *fmt, ...) __attribute__ ((format (printf, 5,6)));
static inline void log_error(char *file, int line, int level, const server_rec *s, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	ap_log_error(file,line,level,0,s,fmt,args);
	va_end(args);
}

#endif /* APACHE20_H */
