dnl CHECK_PATH_MOD_SSL([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Test for mod_ssl and openssl header directory.
dnl
AC_DEFUN(CHECK_PATH_MOD_SSL,
[dnl
AC_ARG_ENABLE(
		ssl,
		[AC_HELP_STRING([--enable-ssl],[Compile in SSL support])],
		ssl_val=yes,
		ssl_val=no
	)
AC_ARG_WITH(
		ssl-inc,
		[AC_HELP_STRING([--with-ssl-inc=DIR],[Location of SSL header files])],
		ssl_incdir="$withval",
	)

	if test "$ssl_val" = "yes"; then
		ac_save_CFLAGS=$CFLAGS
		ac_save_CPPFLAGS=$CPPFLAGS
		MOD_SSL_CFLAGS="-I/usr/include/openssl"
		if test "x$ssl_incdir" != "x"; then
			MOD_SSL_CFLAGS="-I$ssl_incdir -I$ssl_incdir/openssl $MOD_SSL_CFLAGS"
		fi
		
		CFLAGS="-I$APACHE_INCDIR  $MOD_SSL_CFLAGS $CFLAGS"
		CPPFLAGS="-I$APACHE_INCDIR  $MOD_SSL_CFLAGS $CPPFLAGS"
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
