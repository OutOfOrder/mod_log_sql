dnl CHECK_PATH_MYSQL([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUNT]])
dnl Check for MySQL Libs
dnl
AC_DEFUN(CHECK_PATH_MYSQL,
[dnl
AC_ARG_WITH(
		mysql,
		[AC_HELP_STRING([--with-mysql],[Path to MySQL client library])],
		mysql_prefix="$withval",
		
	)
AC_ARG_ENABLE(
		mysqltest,
		[AC_HELP_STRING([--disble-mysqltest],[Do not try to compile and run mysql test program])],
		,
		enable_apachetest=yes)

    AC_REQUIRE([AC_CANONICAL_TARGET])
    ac_save_CFLAGS=$CFLAGS
    ac_save_LDFLAGS=$LDFLAGS
    if test "x$mysql_prefix" != "x" && test "x$mysql_prefix" != "xyes"; then
		MYSQL_LDFLAGS="-L${mysql_prefix}/lib -L${mysql_prefix}/lib/mysql -L${mysql_prefix}/mysql/lib"
		MYSQL_CFLAGS="-I${mysql_prefix}/include -I${mysql_prefix}/include/mysql -I${mysql_prefix}/mysql/include"
    else
		MYSQL_LDFLAGS="-L/usr/local/mysql/lib -L/usr/lib/mysql -L/usr/mysql/lib -L/usr/local/lib/mysql -L/usr/local/mysql/lib/mysql -L/usr/mysql/lib/mysql"
		MYSQL_CFLAGS="-I/usr/local/mysql/include -I/usr/include/mysql -I/usr/mysql/include -I/usr/local/include/mysql -I/usr/local/mysql/include/mysql -I/usr/mysql/include/mysql"
    fi
    CFLAGS="$CFLAGS $MYSQL_CFLAGS"
    LDFLAGS="$LDFLAGS $MYSQL_LDFLAGS"
    AC_CHECK_LIB(m, floor)
    AC_CHECK_LIB(z, gzclose)
    with_mysql="yes"
    AC_DEFINE(WITH_MYSQL,1,[Define to 1 if we are compiling with mysql])
    AC_CHECK_LIB(mysqlclient, mysql_init, ,
      [AC_MSG_ERROR(libmysqlclient is needed for MySQL support)])
    MYSQL_LIBS=$LIBS
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
      ], , no_mysql=yes,[echo $ac_n "cross compiling; assumed OK.... $ac_c"])
      CFLAGS=$ac_save_CFLAGS
      LDFLAGS=$ac_save_LDFLAGS
      if test "x$no_mysql" = x; then
		AC_MSG_RESULT(yes)
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
])
