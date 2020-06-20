# aclocal.m4 generated automatically by aclocal 1.6.3 -*- Autoconf -*-

# Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

m4_include([m4/acpkgconf.m4])

PKG_PROG_PKG_CONFIG

dnl CHECK_APACHE([MINIMUM-VERSION [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for Apache apxs, APR, and APU

AC_DEFUN([CHECK_APACHE],
[dnl
AC_ARG_WITH(
    apxs,
    [AC_HELP_STRING([--with-apxs=PATH],[Path to apxs])],
    apxs_prefix="$withval",
    apxs_prefix="/usr"
    )

AC_ARG_ENABLE(
        apachetest,
        [AC_HELP_STRING([--disable-apxstest],[Do not try to compile and run apache version test program])],
        ,
        enable_apachetest=yes
    )

    if test -x $apxs_prefix -a ! -d $apxs_prefix; then
        APXS_BIN=$apxs_prefix
    else
        test_paths="$apxs_prefix:$apxs_prefix/bin:$apxs_prefix/sbin"
        test_paths="${test_paths}:/usr/bin:/usr/sbin"
        test_paths="${test_paths}:/usr/local/bin:/usr/local/sbin:/usr/local/apache2/bin"
        AC_PATH_PROG(APXS_BIN, apxs, no, [$test_paths])
    fi
    min_apache_version=ifelse([$1], ,no,$1)
    no_apxs=""
    if test "$APXS_BIN" = "no"; then
        AC_MSG_ERROR([*** The apxs binary installed by apache could not be found!])
        AC_MSG_ERROR([*** Use the --with-apxs option with the full path to apxs])
    else
        AP_INCLUDES="-I`$APXS_BIN -q INCLUDEDIR 2>/dev/null`"
        AP_INCLUDEDIR="`$APXS_BIN -q INCLUDEDIR 2>/dev/null`"

        AP_PREFIX="`$APXS_BIN -q prefix 2>/dev/null`"

        AP_BINDIR="`$APXS_BIN -q bindir 2>/dev/null`"
        AP_SBINDIR="`$APXS_BIN -q sbindir 2>/dev/null`"
        AP_SYSCONFDIR="`$APXS_BIN -q sysconfdir 2>/dev/null`"

        APXS_CFLAGS=""
        for flag in CFLAGS EXTRA_CFLAGS EXTRA_CPPFLAGS NOTEST_CFLAGS; do
            APXS_CFLAGS="$APXS_CFLAGS `$APXS_BIN -q $flag 2>/dev/null`"
        done

        AP_CPPFLAGS="$APXS_CPPFLAGS $AP_INCLUDES"
        AP_CFLAGS="$APXS_CFLAGS $AP_INCLUDES"

        AP_LIBEXECDIR=`$APXS_BIN -q LIBEXECDIR 2>/dev/null`

        if test "x$enable_apachetest" = "xyes" ; then
            if test "$min_apache_version" != "no"; then
                APR_CONFIG="`$APXS_BIN -q APR_BINDIR 2>/dev/null`/apr-1-config"
                if test ! -x $APR_CONFIG; then
                    APR_CONFIG="`$APXS_BIN -q APR_BINDIR 2>/dev/null`/apr-config"
                fi
                APR_INCLUDES=`$APR_CONFIG --includes 2>/dev/null`
                APR_VERSION=`$APR_CONFIG --version 2>/dev/null`
                APU_CONFIG="`$APXS_BIN -q APU_BINDIR 2>/dev/null`/apu-1-config"
                if test ! -x $APU_CONFIG; then
                    APU_CONFIG="`$APXS_BIN -q APU_BINDIR 2>/dev/null`/apu-config"
                fi
                APU_INCLUDES=`$APU_CONFIG --includes 2>/dev/null`
                APU_VERSION=`$APU_CONFIG --version 2>/dev/null`

                AC_MSG_CHECKING(for Apache 2.4 version >= $min_apache_version)
                TEST_APACHE_VERSION(24,$min_apache_version,
                    AC_MSG_RESULT(yes)
                    AC_DEFINE(WITH_APACHE20,1,[Define to 1 if we are compiling with Apache 2.4.x])
                    AP_VERSION="2.4"
                    APXS_EXTENSION=.la
                    AP_CFLAGS="$AP_CFLAGS $APU_INCLUDES $APR_INCLUDES"
                    AP_CPPFLAGS="$AP_CPPFLAGS $APU_INCLUDES $APR_INCLUDES"
                    AP_DEFS="-DWITH_APACHE20"
                    ifelse([$2], , , $2),
                    AC_MSG_RESULT(no)
                    ifelse([$3], , , $3)
                )
            fi
        fi
        AC_SUBST(AP_DEFS)
        AC_SUBST(AP_PREFIX)
        AC_SUBST(AP_CFLAGS)
        AC_SUBST(AP_CPPFLAGS)
        AC_SUBST(AP_INCLUDES)
        AC_SUBST(AP_INCLUDEDIR)
        AC_SUBST(AP_LIBEXECDIR)
        AC_SUBST(AP_VERSION)
        AC_SUBST(AP_SYSCONFDIR)
        AC_SUBST(AP_BINDIR)
        AC_SUBST(AP_SBINDIR)
        AC_SUBST(APR_INCLUDES)
        AC_SUBST(APU_INCLUDES)
        AC_SUBST(APXS_EXTENSION)
        AC_SUBST(APXS_BIN)
        AC_SUBST(APXS_CFLAGS)
    fi
])

dnl TEST_APACHE_VERSION(RELEASE, [MINIMUM-VERSION [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for Apache
dnl
AC_DEFUN([TEST_APACHE_VERSION],
[dnl
    AC_REQUIRE([AC_CANONICAL_TARGET])
    releasetest=$1
    min_apache_version="$2"
    no_apache=""
    ac_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $AP_CFLAGS"
    if test $releasetest -eq 24; then
        CFLAGS="$CFLAGS $APU_INCLUDES $APR_INCLUDES"
    fi
    AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "httpd.h"

#ifndef AP_SERVER_BASEREVISION
    #define AP_SERVER_BASEREVISION SERVER_BASEREVISION
#endif

char* my_strdup (char *str)
{
    char *new_str;

    if (str) {
        new_str = (char *)malloc ((strlen (str) + 1) * sizeof(char));
        strcpy (new_str, str);
    } else
        new_str = NULL;

    return new_str;
}

int main (int argc, char *argv[])
{
    int major1, minor1, micro1;
    int major2, minor2, micro2;
    char *tmp_version;

    { FILE *fp = fopen("conf.apachetest", "a"); if ( fp ) fclose(fp); }

    tmp_version = my_strdup("$min_apache_version");
    if (sscanf(tmp_version, "%d.%d.%d", &major1, &minor1, &micro1) != 3) {
        printf("%s, bad version string\n", "$min_apache_version");
        exit(1);
    }
    tmp_version = my_strdup(AP_SERVER_BASEREVISION);
    if (sscanf(tmp_version, "%d.%d.%d", &major2, &minor2, &micro2) != 3) {
        printf("%s, bad version string\n", AP_SERVER_BASEREVISION);
        exit(1);
    }

    if ( (major2 == major1) &&
        ( (minor2 > minor1) ||
        ((minor2 == minor1) && (micro2 >= micro1)) ) ) {
        exit(0);
    } else {
        exit(1);
    }
}

],, no_apache=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
    CFLAGS="$ac_save_CFLAGS"

    if test "x$no_apache" = x ; then
        ifelse([$3], , :, [$3])
       else
        if test -f conf.apachetest ; then
            :
        else
            echo "*** Could not run Apache test program, checking why..."
            CFLAGS="$CFLAGS $AP_CFLAGS"
            if test $releasetest -eq 24; then
                CFLAGS="$CFLAGS $APU_INCLUDES $APR_INCLUDES"
            fi
            AC_TRY_LINK([
#include <stdio.h>
#include "httpd.h"

int main(int argc, char *argv[])
{ return 0; }
#undef main
#define main K_and_R_C_main
],                [ return 0; ],
                [ echo "*** The test program compiled, but failed to run. Check config.log" ],
                [ echo "*** The test program failed to compile or link. Check config.log" ])
            CFLAGS="$ac_save_CFLAGS"
        fi
         ifelse([$4], , :, [$4])
      fi
      rm -f conf.apachetest
])

dnl CHECK_MYSQL([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Check for MySQL Libs
dnl
AC_DEFUN([CHECK_MYSQL],
[dnl
AC_ARG_WITH(
	mysql,
        [AC_HELP_STRING([--with-mysql=PATH],[Path to MySQL client library])],
        mysql_prefix="$withval",
        [with_mysql=yes]
    )

    if test "x$with_mysql" != "xno"; then

	testdirs="/usr /usr/local /usr/local /opt"
        if test "x$mysql_prefix" != "x" && test "x$mysql_prefix" != "xyes"; then
	    testdirs="${testdirs} ${mysql_prefix}"
        fi
	PKG_CHECK_EXISTS(libmariadb,[
	    PKG_CHECK_MODULES(MYSQL, libmariadb,[mysql_library="mariadb"],)
	],[

    	    PKG_CHECK_EXISTS(mysqlclient,[
        	PKG_CHECK_MODULES(MYSQL, mysqlclient,[mysql_library="mysqlclient"],)
    	    ],)
	])

        if test -z $MYSQL_CFLAGS; then
	    AC_MSG_WARN([*** Mysql client libraries not found!])
    	    ifelse([$2], , :, [$2])
	else
    	    ac_save_CFLAGS=$CFLAGS
    	    ac_save_LDFLAGS=$LDFLAGS
    	    ac_save_LIBS=$LIBS
    	    CFLAGS="$CFLAGS $MYSQL_CFLAGS"
	    LDFLAGS="$LDFLAGS $MYSQL_LDFLAGS"
	    LIBS="$LIBS $MYSQL_LIBS"
    	    AC_CHECK_LIB($mysql_library, mysql_init, ,no_mysql=yes)
    	    AC_CHECK_FUNCS(mysql_real_escape_string)
    	    AC_MSG_CHECKING(whether mysql clients can run)
    	    AC_TRY_RUN([
    		#include <stdio.h>
    		#include <mysql.h>    
    		int main(void)
    		{
    		    MYSQL *a = mysql_init(NULL);
    		    return 0;
    		}
    		], , no_mysql=yes,[echo $ac_n "cross compiling; assumed OK.... $ac_c"]
    	    )
	    CFLAGS=$ac_save_CFLAGS
    	    LDFLAGS=$ac_save_LDFLAGS
    	    LIBS=$ac_save_LIBS

	    if test "x$no_mysql" = x; then
    		AC_DEFINE(WITH_MYSQL,1,[Define to 1 if we are compiling with mysql])
	        AC_MSG_RESULT(yes)
	        AC_CHECK_LIB(m, floor)
	        AC_CHECK_LIB(z, gzclose)
    		ifelse([$1], , :, [$1])
    	    else
    		AC_MSG_RESULT(no)
    		echo "*** MySQL could not be found ***"
    		MYSQL_CFLAGS=""
    		MYSQL_LDFLAGS=""
    		MYSQL_LIBS=""
    		ifelse([$2], , :, [$2])
    	    fi

    	    AC_SUBST(MYSQL_LDFLAGS)
    	    AC_SUBST(MYSQL_CFLAGS)
    	    AC_SUBST(MYSQL_LIBS)
	fi
    else
      ifelse([$2], , :, [$2])
    fi
])


dnl CHECK_PGSQL([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Check for Postgres Libs
dnl
AC_DEFUN([CHECK_PGSQL],
[
AC_ARG_WITH(
        pgsql,
        [AC_HELP_STRING([--with-pgsql=PATH],[Path to libpq client library])],
        pgsql_prefix="$withval",
        [with_pgsql=yes]
    )

    if test "x$with_pgsql" != "xno"; then

	testdirs="/usr /usr/local /usr/local /opt"
        if test "x$pgsql_prefix" != "x" && test "x$pgsql_prefix" != "xyes"; then
	    testdirs="${testdirs} ${pgsql_prefix}"
        fi
	PKG_CHECK_EXISTS(libpq,[
	    PKG_CHECK_MODULES(PGSQL, libpq,,)
	],[

        for dir in $testdirs; do
	    if test -e $dir/include/postgresql/libpq-fe.h; then
    		PGSQL_CFLAGS=-I${dir}/include/postgresql
    		PGSQL_LDFLAGS=-L${dir}/lib
    		PGSQL_LIBS="-lpq"
    		break
    	    fi
	done
	])

	if test -z $PGSQL_CFLAGS; then
	    AC_MSG_WARN([*** PostgreSQL client libraries not found!])
    	    ifelse([$2], , :, [$2])
	else
	    ac_save_CFLAGS=$CFLAGS
	    ac_save_LDFLAGS=$LDFLAGS
	    ac_save_LIBS=$LIBS
	    CFLAGS="$CFLAGS $PGSQL_CFLAGS"
	    LDFLAGS="$LDFLAGS $PGSQL_LDFLAGS"
	    LIBS="$LIBS $PGSQL_LIBS"
	    AC_CHECK_LIB(pq, PQsetdbLogin,, [AC_MSG_WARN(libpq is needed for PostgreSQL support)])
	    AC_CHECK_FUNCS(PQescapeString)
	    AC_MSG_CHECKING(whether PostgreSQL clients can run)
	    AC_TRY_RUN([
    		#include <stdio.h>
    		#include <libpq-fe.h>    
    		int main(void)
    		{
        	    char to_str[] = "  ";
        	    char from_str[] = "  ";

        	    int retval = PQescapeString(to_str, from_str, 2);
        	    return 0;
    		}
    		], , no_pgsql=yes,[echo $ac_n "cross compiling; assumed OK.... $ac_c"]
    	    )
	    CFLAGS=$ac_save_CFLAGS
	    LDFLAGS=$ac_save_LDFLAGS
	    LIBS=$ac_save_LIBS

	    if test "x$no_pgsql" = x; then
		AC_DEFINE(WITH_PGSQL,1,[Define to 1 if we are compiling with PostgreSQL])
		AC_MSG_RESULT(yes)
    		ifelse([$1], , :, [$1])
	    else
    		AC_MSG_RESULT(no)
    		echo "*** libpq could not be found ***"
    		PGSQL_CFLAGS=""
    	        PGSQL_LDFLAGS=""
    		PGSQL_LIBS=""
    		ifelse([$2], , :, [$2])
	    fi

	    AC_SUBST(PGSQL_LDFLAGS)
	    AC_SUBST(PGSQL_CFLAGS)
	    AC_SUBST(PGSQL_LIBS)
	fi
    else
        ifelse([$2], , :, [$2])
    fi
])

dnl CHECK_MOD_SSL([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Test for mod_ssl and openssl header directory.
dnl
AC_DEFUN([CHECK_MOD_SSL],
[dnl
AC_ARG_ENABLE(
        ssl,
        [AC_HELP_STRING([--disable-ssl],[Do not compile in SSL support])],
        ssl_val=no,
        ssl_val=yes
    )
AC_ARG_WITH(
        ssl-inc,
        [AC_HELP_STRING([--with-ssl-inc=PATH],[Location of SSL header files])],
        ssl_incdir="$withval",
    )
AC_ARG_WITH(
        db-inc,
        [AC_HELP_STRING([--with-db-inc=PATH],[Location of DB header files])],
        db_incdir="$withval",
        db_incdir="/usr/include/db1"
    )

    if test "x$ssl_val" = "xyes"; then
        ac_save_CFLAGS=$CFLAGS
        ac_save_CPPFLAGS=$CPPFLAGS
        MOD_SSL_CFLAGS="-I/usr/include/openssl"
        if test "x$ssl_incdir" != "x"; then
            MOD_SSL_CFLAGS="-I$ssl_incdir -I$ssl_incdir/openssl $MOD_SSL_CFLAGS"
        fi
        if test "x$db_incdir" != "x"; then
            MOD_SSL_CFLAGS="-I$db_incdir $MOD_SSL_CFLAGS"
        fi
        CFLAGS="$AP_CFLAGS $MOD_SSL_CFLAGS $CFLAGS"
        CPPFLAGS="$AP_CFLAGS $MOD_SSL_CFLAGS $CPPFLAGS"
        AC_CHECK_HEADERS([mod_ssl.h],
            mod_ssl_h=yes
        )
        CFLAGS=$ac_save_CFLAGS
        CPPFLAGS=$ac_save_CPPFLAGS
        if test "x$mod_ssl_h" = "x"; then
            ifelse([$2], , :, [$2])
        else
            AC_SUBST(MOD_SSL_CFLAGS)
            ifelse([$1], , :, [$1])
        fi
    else
        ifelse([$2], , :, [$2])
    fi
])

dnl Check for libdbi libraries
dnl CHECK_LIBDBI(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
AC_DEFUN([CHECK_LIBDBI],
[dnl

AC_ARG_WITH(
	dbi,
	[AC_HELP_STRING([--with-dbi=PATH],[Path libdbi headers and libraries])],
	dbi_path="$withval",
	[with_dbi=yes]
    )

if test "x$with_dbi" != "xno"; then

    # Determine dbi include directory.
    if test -z $dbi_path; then
	test_paths="/usr/include /usr/local/include"
    else
        test_paths="${dbi_path}/include"
    fi

    PKG_CHECK_EXISTS(dbi,[
	PKG_CHECK_MODULES(DBI, dbi,,)
    ],[
	for x in $test_paths ; do
	    AC_MSG_CHECKING([for dbi Includes in ${x}])
	    if test -f ${x}/dbi/dbi.h; then
    		DBI_CFLAGS="-I$x"
    	        AC_MSG_RESULT(yes)
    	        break
	    else
    	        AC_MSG_RESULT(no)        
	    fi
	done
    ])

    if test -z "$DBI_CFLAGS"; then
	ifelse([$2], , :, $2)
    else
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        save_LIBS=$LIBS
            CFLAGS="$DBI_CFLAGS $CFLAGS"
        LDFLAGS="$DBI_LDFLAGS $LDFLAGS"
        LIBS="$DBI_LIBS $LIBS"
        AC_CHECK_LIB(dbi, dbi_version,,)
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        LIBS=$save_LIBS

        if test -z "$DBI_LIBS"; then
            ifelse([$2], , :, $2)
        else
	    AC_DEFINE(WITH_DBI,1,[Define to 1 if we are compiling with libDBI])
	    AC_SUBST(DBI_LDFLAGS)
	    AC_SUBST(DBI_LIBS)
	    AC_SUBST(DBI_CFLAGS)
	    ifelse([$1], , :, $1)
	fi
    fi
else
    ifelse([$2], , :, [$2])
fi
])
