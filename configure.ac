dnl Required initializer
AC_INIT(mod_log_sql, 1.97)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_SRCDIR(mod_log_sql.c)

dnl Add a test for a compiler.
AC_PROG_CC

APACHE20_VERSION=2.0.44
APACHE13_VERSION=1.3.20
CHECK_PATH_APACHE($APACHE13_VERSION,$APACHE20_VERSION,
		:,
		:,
		AC_MSG_ERROR([*** The correct version Apache was not found!])
		AC_MSG_ERROR([*** You need either Apache 1.3 version $APACHE13_VERSION or greater])
		AC_MSG_ERROR([*** or Apache 2.0/2.1 version $APACHE20_VERSION or greater!])
		)

CHECK_PATH_MYSQL(:,
		AC_MSG_ERROR([*** Mysql client libraries not found!])
		)

CHECK_PATH_MOD_SSL(
		AC_DEFINE(WANT_SSL_LOGGING,,[Define if we want to compile in SSL support.])
		WANT_SSL_MOD=1,
		WANT_SSL_MOD=0
		)

AC_SUBST(WANT_SSL_MOD)

case "$target" in
	*-*-solaris* | *-*-osf* )
		if test $APACHE_VERSION -eq 1.3; then
			RTLIBS=-lrt
		fi
		;;
	*)
		RTLIBS=""
		;;
esac

AC_SUBST(RTLIBS)

AC_CHECK_HEADERS(limits.h)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

dnl Write config.status and the Makefile

AC_OUTPUT(Makefile
Documentation/Makefile
contrib/Makefile)

AC_MSG_RESULT([------------------------------------])
AC_MSG_RESULT([Apache version	: $APACHE_VERSION])
if test $WANT_SSL_MOD -eq 1; then
	AC_MSG_RESULT([SSL Support	: yes])
else
	AC_MSG_RESULT([SSL Support	: no])
	AC_MSG_RESULT([*** Use --enable-ssl to enable SSL support])
fi
