dnl Required initializer
AC_INIT(mod_log_sql, 1.101)
OOO_CONFIG_NICE(config.nice)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_SRCDIR(mod_log_sql.c)

OOO_MAINTAIN_MODE

dnl Add a test for a compiler.
AC_PROG_CC

APACHE20_VERSION=2.0.40
APACHE13_VERSION=1.3.20
CHECK_APACHE($APACHE13_VERSION,$APACHE20_VERSION,
        :,
        :,
        AC_MSG_ERROR([*** The correct version Apache was not found!])
        AC_MSG_ERROR([*** You need either Apache 1.3 version $APACHE13_VERSION or greater])
        AC_MSG_ERROR([*** or Apache 2.0/2.1 version $APACHE20_VERSION or greater!])
        )

if test $AP_VERSION = "2.0"; then
    WANT_LOGIO_MOD=1
else
    WANT_LOGIO_MOD=0
fi
AC_SUBST(WANT_LOGIO_MOD)

CHECK_MYSQL(
        WANT_MYSQL_MOD=1,
        AC_MSG_WARN([*** Mysql client libraries not found!])
        WANT_MYSQL_MOD=0
        )

AC_SUBST(WANT_MYSQL_MOD)

CHECK_LIBDBI(WANT_DBI_MOD=1,
        AC_MSG_WARN([** libDBI client libraries not found!])
        WANT_DBI_MOD=0
        )
AC_SUBST(WANT_DBI_MOD)

dnl to write, checking for pgsql libs
WANT_PGSQL_MOD=0
AC_SUBST(WANT_PGSQL_MOD)


CHECK_MOD_SSL(
        WANT_SSL_MOD=1,
        AC_MSG_WARN([** mod_ssl.h not found or missing SSL headers!])
        WANT_SSL_MOD=0
        )

AC_SUBST(WANT_SSL_MOD)

case "$target" in
    *-*-solaris* | *-*-osf* )
        if test $AP_VERSION = "1.3"; then
            RT_LIBS=-lrt
        fi
        ;;
    *)
        RT_LIBS=""
        ;;
esac

AC_SUBST(RT_LIBS)


AC_CHECK_HEADERS(limits.h)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

dnl Write config.status and the Makefile

AC_OUTPUT(Makefile
docs/Makefile
contrib/Makefile)


AC_MSG_RESULT([------------------------------------])
AC_MSG_RESULT([Apache version  : $AP_VERSION])
if test $WANT_SSL_MOD -eq 1; then
    AC_MSG_RESULT([SSL Support     : yes])
else
    AC_MSG_RESULT([SSL Support     : no])
    AC_MSG_RESULT([*** Make sure OpenSSL headers, and mod_ssl.h are installed.])
fi
if test $WANT_LOGIO_MOD -eq 1; then
    AC_MSG_RESULT([LogIO Module    : yes])
else
    AC_MSG_RESULT([LogIO Module    : no])
    AC_MSG_RESULT([*** Logio does not work with Apache 1.3.])
fi

AC_MSG_RESULT([Enabled drivers :])
if test $WANT_MYSQL_MOD -eq 1; then
    AC_MSG_RESULT([      MySQL Driver])
fi
if test $WANT_PGSQL_MOD -eq 1; then
    AC_MSG_RESULT([      PostgreSQL Driver])
fi
if test $WANT_DBI_MOD -eq 1; then
    AC_MSG_RESULT([      libDBI Driver])
fi
if test $OOO_MAINTAIN -eq 1; then
    AC_MSG_RESULT([Maintainer mode is on. -Werror is in effect])
fi
AC_MSG_RESULT([------------------------------------])
