#ifndef DATABASE_H_
#define DATABASE_H_

#include "apr_pools.h"

#include "config.h"

void database_init(apr_pool_t *p);

apr_status_t database_connect(config_t *cfg, config_dbd_t **dbconn);

apr_status_t database_disconnect(config_dbd_t *dbconn);

apr_status_t database_insert(config_t *cfg, config_dbd_t *dbconn,
        apr_pool_t *p, apr_table_t *data);

apr_status_t database_trans_start(config_t *cfg, config_dbd_t *dbconn,
        apr_pool_t *p);

apr_status_t database_trans_stop(config_t *cfg, config_dbd_t *dbconn,
        apr_pool_t *p);

apr_status_t database_trans_abort(config_t *cfg, config_dbd_t *dbconn);

#endif /*DATABASE_H_*/
