/* $Id: mod_log_sql_ssl.c 140 2004-05-14 03:50:47Z urkle@drip.ws $ */

#if defined(WITH_APACHE20)
#	include "apache20.h"
#else
#	error Unsupported Apache version
#endif

#ifdef HAVE_CONFIG_H
/* Undefine these to prevent conflicts between Apache ap_config_auto.h and
 * my config.h. Only really needed for Apache < 2.0.48, but it can't hurt.
 */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"
#endif

#include "mod_log_sql.h"

module AP_MODULE_DECLARE_DATA log_sql_logio_module;

// From apachge 2.2's mod_logio.c to provide logging ACTUAL incoming and outgoing bytes
static const char logio_filter_name[] = "LOG_SQL_INPUT_OUTPUT";

typedef struct {
    apr_off_t bytes_in;
    apr_off_t bytes_out;
} logio_config_t;

static void ap_logio_add_bytes_out(conn_rec *c, apr_off_t bytes){
    logio_config_t *cf = ap_get_module_config(c->conn_config, &log_sql_logio_module);

    cf->bytes_out += bytes;
}

static const char *log_bytes_in(request_rec *r, char *a)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &log_sql_logio_module);

    return apr_off_t_toa(r->pool, cf->bytes_in);
}

static const char *log_bytes_out(request_rec *r, char *a)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &log_sql_logio_module);

    return apr_off_t_toa(r->pool, cf->bytes_out);
}

static int logio_transaction(request_rec *r)
{
    logio_config_t *cf = ap_get_module_config(r->connection->conn_config,
                                              &log_sql_logio_module);

    cf->bytes_in = cf->bytes_out = 0;

    return OK;
}

static apr_status_t logio_in_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes) {
    apr_off_t length;
    apr_status_t status;
    logio_config_t *cf = ap_get_module_config(f->c->conn_config, &log_sql_logio_module);

    status = ap_get_brigade(f->next, bb, mode, block, readbytes);

    apr_brigade_length (bb, 0, &length);

    if (length > 0)
        cf->bytes_in += length;

    return status;
}

static apr_status_t logio_out_filter(ap_filter_t *f,
                                     apr_bucket_brigade *bb) {
    apr_bucket *b = APR_BRIGADE_LAST(bb);

    /* End of data, make sure we flush */
    if (APR_BUCKET_IS_EOS(b)) {
        APR_BUCKET_INSERT_BEFORE(b,
                                 apr_bucket_flush_create(f->c->bucket_alloc));
    }

    return ap_pass_brigade(f->next, bb);
}

static int logio_pre_conn(conn_rec *c, void *csd) {
    logio_config_t *cf = apr_pcalloc(c->pool, sizeof(*cf));

    ap_set_module_config(c->conn_config, &log_sql_logio_module, cf);

    ap_add_input_filter(logio_filter_name, NULL, NULL, c);
    ap_add_output_filter(logio_filter_name, NULL, NULL, c);

    return OK;
}

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    log_sql_register_item(s,p,'i', log_bytes_in,   "bytes_in",    0, 0);
    log_sql_register_item(s,p,'o', log_bytes_out,  "bytes_out",   0, 0);
    return OK;
}
static void register_hooks(apr_pool_t *p) {
    static const char *pre[] = { "mod_log_sql.c", NULL };

    ap_hook_pre_connection(logio_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(logio_transaction, pre, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);

    ap_register_input_filter(logio_filter_name, logio_in_filter, NULL,
                             AP_FTYPE_NETWORK - 1);
    ap_register_output_filter(logio_filter_name, logio_out_filter, NULL,
                              AP_FTYPE_NETWORK - 1);

    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_out);
}

module AP_MODULE_DECLARE_DATA log_sql_logio_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL,  NULL, NULL,  NULL, register_hooks
};
