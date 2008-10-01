#ifndef LOGPARSE_H_
#define LOGPARSE_H_

#include "config.h"

void find_log_files(config_t *cfg);

apr_status_t parse_logfile(config_t *cfg, const char *filename);

#endif /*LOGPARSE_H_*/
