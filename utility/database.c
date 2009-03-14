#include "database.h"
#include "apu.h"
#include "apr_dbd.h"
#include "apr_strings.h"

#include "util.h"
#include "autoconfig.h"

struct config_dbd_t {
    const apr_dbd_driver_t *driver;
    apr_dbd_t *dbd;
    apr_dbd_prepared_t *stmt;
    apr_dbd_transaction_t *txn;
    const char **args;
};

void database_init(apr_pool_t *p)
{
    apr_dbd_init(p);
}

/** @todo split this into load and connect */
apr_status_t database_connect(config_t *cfg, config_dbd_t **dbconn)
{
    apr_status_t rv;
    if (!cfg->dbdriver || !cfg->dbparams)
        return APR_EINVAL;
    if (!*dbconn) {
        *dbconn = apr_pcalloc(cfg->pool, sizeof(config_dbd_t));
    }
    rv = apr_dbd_get_driver(cfg->pool, cfg->dbdriver, &((*dbconn)->driver));
    if (rv) {

        logging_log(cfg, LOGLEVEL_ERROR,
                "DB: Could not load database driver %s. Error %s",
                cfg->dbdriver, logging_strerror(rv));
        return rv;
    }

    rv = apr_dbd_open((*dbconn)->driver, cfg->pool, cfg->dbparams,
            &((*dbconn)->dbd));
    if (rv) {
        logging_log(cfg, LOGLEVEL_ERROR,
                "DB: Could not connect to database. Error (%d)%s", rv,
                logging_strerror(rv));
        return rv;
    }

    return APR_SUCCESS;
}

apr_status_t database_disconnect(config_dbd_t *dbconn)
{
    return apr_dbd_close(dbconn->driver, dbconn->dbd);
}

static apr_dbd_prepared_t *database_prepare_insert(config_t *cfg,
        config_dbd_t *dbconn, apr_pool_t *p)
{
    apr_status_t rv;
    char *sql;
    int i, f;
    struct iovec *vec;
    apr_dbd_prepared_t *stmt= NULL;
    int nfs = cfg->output_fields->nelts;
    config_output_field_t *ofields;

    ofields = (config_output_field_t *)cfg->output_fields->elts;

    vec = apr_palloc(p, (nfs*2 + 5) * sizeof(struct iovec));
    sql = apr_palloc(p, (nfs*3));

    vec[0].iov_base = "INSERT INTO ";
    vec[0].iov_len = 12;
    vec[1].iov_base = (void *)cfg->table;
    vec[1].iov_len = strlen(cfg->table);
    vec[2].iov_base = " (";
    vec[2].iov_len = 2;
    for (i=3, f=0; f<nfs; f++, i+=2) {
        vec[i].iov_base = (void *)ofields[f].field;
        vec[i].iov_len = strlen(vec[i].iov_base);
        vec[i+1].iov_base = ",";
        vec[i+1].iov_len = 1;
        memcpy(&sql[f*3], "%s,", 3);
    }
    sql[nfs*3-1] = '\0';
    vec[i-1].iov_base = ") VALUES (";
    vec[i-1].iov_len = 10;
    vec[i].iov_base = sql;
    vec[i].iov_len = nfs*3-1;
    vec[i+1].iov_base = ")";
    vec[i+1].iov_len = 1;

    sql = apr_pstrcatv(p, vec, i+2, NULL);

    logging_log(cfg, LOGLEVEL_DEBUG, "DB: Generated SQL: %s", sql);

    rv = apr_dbd_prepare(dbconn->driver, cfg->pool, dbconn->dbd, sql,
            "INSERT", &stmt);

    if (rv) {
        logging_log(cfg, LOGLEVEL_NOISE,
                "DB: Unable to Prepare SQL insert: %s", apr_dbd_error(
                        dbconn->driver, dbconn->dbd, rv));
        return NULL;
    }
    return stmt;
}

apr_status_t database_insert(config_t *cfg, config_dbd_t *dbconn,
        apr_pool_t *p, apr_table_t *data)
{
    apr_status_t rv;
    int f, nfs;
    config_output_field_t *ofields;
    ofields = (config_output_field_t *)cfg->output_fields->elts;
    nfs = cfg->output_fields->nelts;
    // Prepare statement
    if (!dbconn->stmt) {
        dbconn->stmt = database_prepare_insert(cfg, dbconn, p);
        if (!dbconn->stmt) {
            return APR_EINVAL;
        }
        dbconn->args = apr_palloc(cfg->pool, nfs * sizeof(char *));
    }
    for (f=0; f<nfs; f++) {
        dbconn->args[f] = apr_table_get(data, ofields[f].field);
    }
    rv = apr_dbd_pquery(dbconn->driver, p, dbconn->dbd, &f,
            dbconn->stmt, nfs, dbconn->args);
    if (rv) {
        logging_log(cfg, LOGLEVEL_ERROR, "DB: Unable to Insert SQL: %s",
                apr_dbd_error(dbconn->driver, dbconn->dbd, rv));
        return rv;
    }
    return APR_SUCCESS;
}

apr_status_t database_trans_start(config_t *cfg, config_dbd_t *dbconn,
        apr_pool_t *p)
{
#if HAVE_APR_DBD_TRANSACTION_MODE_GET
    apr_status_t rv;
    if (!cfg->transactions)
        return APR_SUCCESS;
    if (dbconn->txn) {
        logging_log(cfg, LOGLEVEL_NOISE,
                "Transaction Already Started. Something is BROKE");
        return APR_EINVAL;
    }
    logging_log(cfg, LOGLEVEL_DEBUG, "DB: Starting Transaction");
    rv = apr_dbd_transaction_start(dbconn->driver, p, dbconn->dbd,
            &dbconn->txn);
    if (rv)
        logging_log(cfg, LOGLEVEL_NOISE,
                "DB: Error Starting Transaction: (%d)%s", rv, apr_dbd_error(
                        dbconn->driver, dbconn->dbd, rv));
    return rv;
#else
    return APR_SUCCESS;
#endif
}

apr_status_t database_trans_stop(config_t *cfg, config_dbd_t *dbconn,
        apr_pool_t *p)
{
#if HAVE_APR_DBD_TRANSACTION_MODE_GET
    apr_status_t rv;
    if (!cfg->transactions)
        return APR_SUCCESS;
    if (!dbconn->txn) {
        logging_log(cfg, LOGLEVEL_NOISE,
                "No Transaction Started. Something is BROKE");
        return APR_EINVAL;
    }
    logging_log(cfg, LOGLEVEL_DEBUG, "DB: Stopping Transaction");
    rv = apr_dbd_transaction_end(dbconn->driver, p, dbconn->txn);
    if (rv)
        logging_log(cfg, LOGLEVEL_NOISE,
                "DB: Error Stopping Transaction: (%d)%s", rv, apr_dbd_error(
                        dbconn->driver, dbconn->dbd, rv));

    dbconn->txn = NULL;
    return rv;
#else
    return APR_SUCCESS;
#endif
}

apr_status_t database_trans_abort(config_t *cfg, config_dbd_t *dbconn)
{
#if HAVE_APR_DBD_TRANSACTION_MODE_GET
    apr_status_t rv;
    if (!cfg->transactions)
        return APR_SUCCESS;
    if (!dbconn->txn) {
        logging_log(cfg, LOGLEVEL_NOISE,
                "No Transaction Started. Something is BROKE");
        return APR_EINVAL;
    }
    logging_log(cfg, LOGLEVEL_NOTICE, "DB: Aborting Transaction");
    rv = apr_dbd_transaction_mode_set(dbconn->driver, dbconn->txn,
            APR_DBD_TRANSACTION_ROLLBACK);
    if (rv)
        logging_log(cfg, LOGLEVEL_NOISE,
                "DB: Error Aborting Transaction: (%d)%s", rv, apr_dbd_error(
                        dbconn->driver, dbconn->dbd, rv));
    return rv;
#else
    return APR_SUCCESS;
#endif
}
