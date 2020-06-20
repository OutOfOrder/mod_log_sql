dnl Required initializer
AC_INIT(mod_log_sql, 2.0.1)
AC_CONFIG_MACRO_DIRS([m4])
m4_include([m4/acinclude.m4])

AC_PREREQ(2.53)
AC_CONFIG_HEADERS(include/autoconfig.h)
AC_CONFIG_SRCDIR(src/mod_log_sql.c)

LT_INIT

dnl Add a test for a compiler.
AC_PROG_CC
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(PCRE,libpcre)

APACHE_VERSION=2.4.1
CHECK_APACHE($APACHE_VERSION,
        :,
        AC_MSG_ERROR([*** You need Apache version $APACHE_VERSION or greater!])
        )

WANT_LOGIO_MOD=1
AC_ARG_ENABLE(
        [logio],
        AC_HELP_STRING([--disable-logio],[Disable logIO module])
)
AS_IF([test "x$enable_logio" = "xno"], [
  WANT_LOGIO_MOD=0
])

AS_IF([test "x$WANT_LOGIO_MOD" = "x1"], [
  AC_DEFINE(WITH_LOGIO_MOD,1,[Define to 1 if we are including the logio module])
])
AC_SUBST(WANT_LOGIO_MOD)

CHECK_MOD_SSL(
    WANT_SSL_MOD=1
    AC_DEFINE(WITH_SSL_MOD,1,[Define to 1 if we are including the ssl module]),
    WANT_SSL_MOD=0
)
AC_SUBST(WANT_SSL_MOD)

CHECK_MYSQL(
    WANT_MYSQL_MOD=1,
    WANT_MYSQL_MOD=0
)
AC_SUBST(WANT_MYSQL_MOD)

CHECK_PGSQL(
    WANT_PGSQL_MOD=1,
    WANT_PGSQL_MOD=0
)
AC_SUBST(WANT_PGSQL_MOD)

CHECK_LIBDBI(
    WANT_DBI_MOD=1,
    WANT_DBI_MOD=0
)
AC_SUBST(WANT_DBI_MOD)

WANT_DBD_MOD=1
AC_ARG_WITH(
        [dbd],
        AC_HELP_STRING([--without-dbd],[Disable DBD driver])
)
AS_IF([test "x$with_dbd" = "xno"], [
  WANT_DBD_MOD=0
])
AC_SUBST(WANT_DBD_MOD)

AC_CHECK_HEADERS(limits.h)

AC_CONFIG_FILES([Makefile
docs/Makefile
contrib/Makefile
src/Makefile])
AC_OUTPUT

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
if test $WANT_DBD_MOD -eq 1; then
    AC_MSG_RESULT([      DBD Driver])
fi
AC_MSG_RESULT([------------------------------------])
