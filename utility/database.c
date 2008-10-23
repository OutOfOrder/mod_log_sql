#include "database.h"
#include "apu.h"
#include "apr_dbd.h"
#include "apr_strings.h"

struct config_dbd_t {
    const apr_dbd_driver_t *driver;
    apr_dbd_t *dbd;
    apr_dbd_prepared_t *stmt;
    const char **args;
};

void database_init(apr_pool_t *p)
{
    apr_dbd_init(p);
}

apr_status_t database_connect(config_t *cfg)
{
    apr_status_t rv;
    if (!cfg->dbconn) {
        cfg->dbconn = apr_palloc(cfg->pool, sizeof(config_dbd_t));
    }
    rv = apr_dbd_get_driver(cfg->pool, cfg->dbdriver, &(cfg->dbconn->driver));
    if (rv)
        return rv;

    rv = apr_dbd_open(cfg->dbconn->driver, cfg->pool, cfg->dbparams,
            &(cfg->dbconn->dbd));
    if (rv)
        return rv;

    return APR_SUCCESS;
}

apr_status_t database_disconnect(config_t *cfg)
{
    return apr_dbd_close(cfg->dbconn->driver, cfg->dbconn->dbd);
}

apr_status_t database_insert(config_t *cfg, apr_pool_t *p, apr_table_t *data)
{
    apr_status_t rv;
    int f, nfs;
    config_output_field_t *ofields;
    ofields = (config_output_field_t *)cfg->output_fields->elts;
    nfs = cfg->output_fields->nelts;
    // Prepare statement
    if (!cfg->dbconn->stmt) {
        char *sql;
        int i;
        struct iovec *vec;
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
        printf("SQL: %s\n", sql);
        cfg->dbconn->args = apr_palloc(cfg->pool, nfs * sizeof(char *));
        rv = apr_dbd_prepare(cfg->dbconn->driver, cfg->pool, cfg->dbconn->dbd,
                sql, "INSERT", &(cfg->dbconn->stmt));
        if (rv) {
            printf("DB Error: %s\n", apr_dbd_error(cfg->dbconn->driver,
                    cfg->dbconn->dbd, rv));
            return rv;
        }
    }
    for (f=0; f<nfs; f++) {
        cfg->dbconn->args[f] = apr_table_get(data, ofields[f].field);
    }
    rv = apr_dbd_pquery(cfg->dbconn->driver, p, cfg->dbconn->dbd, &f,
            cfg->dbconn->stmt, nfs, cfg->dbconn->args);
    if (rv) {
        printf("DB Error: %s\n", apr_dbd_error(cfg->dbconn->driver,
                cfg->dbconn->dbd, rv));
        return rv;
    }
    return APR_SUCCESS;
}
