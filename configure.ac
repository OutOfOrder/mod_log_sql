dnl Required initializer
AC_INIT(mod_log_sql, 1.92)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_SRCDIR(mod_log_sql.c)

dnl Add a test for a compiler.
AC_PROG_CC

APACHE_VERSION=2.0.44
CHECK_PATH_APACHE($APACHE_VERSION,
   		:,
   		AC_MSG_ERROR([*** Apache version $APACHE_VERSION not found!])
  		)

CHECK_PATH_MYSQL(:,
		AC_MSG_ERROR([*** Mysql client libraries not found!])
		)

CHECK_PATH_MOD_SSL(
		AC_DEFINE(WANT_SSL_LOGGING,,[Define if we want to compile in SSL support.])
		AC_MSG_WARN([*** Compilng with SSL support!]),
		AC_MSG_WARN([*** Compiling without SSL support!])
		AC_MSG_WARN([*** enable with --enable-ssl to enable])
		AC_MSG_WARN([*** and --with-ssl-inc with the the directory for SSL headers])
		)

AC_CHECK_HEADERS(limits.h)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

dnl Write config.status and the Makefile

AC_OUTPUT(Makefile Documentation/Makefile)
