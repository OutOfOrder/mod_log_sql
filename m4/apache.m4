dnl CHECK_PATH_APACHE([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for Apache apxs
dnl
AC_DEFUN(CHECK_PATH_APACHE,
[dnl
AC_ARG_WITH(
		apxs,
		[AC_HELP_STRING([--with-apxs=PATH],[Location to APXS binary (default: /usr)])],
		apxs_prefix="$withval",
		apxs_prefix="/usr"
	)
AC_ARG_ENABLE(apachetest,
	[AC_HELP_STRING([--disable-apachetest],[Do not try to compile and run apache version test program])],
	,
	enable_apachetest=yes)


	AC_REQUIRE([AC_CANONICAL_TARGET])
	PATH="$apxs_prefix:$apxs_prefix/bin:$apxs_prefix/sbin:$PATH"
	if test -x $apxs_prefix && test ! -d $apxs_prefix; then
		APXS_BIN=$apxs_prefix
	else
		AC_PATH_PROG(APXS_BIN, apxs, no, [$PATH])
	fi
	min_apache_version=ifelse([$1], ,1.3.1,$1)
	AC_MSG_CHECKING(for Apache - version >= $min_apache_version)
	no_apxs=""
	if test "$APXS_BIN" == "no"; then
		no_apxs=yes
	else
		APACHE_INCDIR=`$APXS_BIN -q INCLUDEDIR`
		APACHE_CFLAGS=-I$APACHE_INCDIR
		APACHE_MODDIR=`$APXS_BIN -q LIBEXECDIR`

		if test "x$enable_apachetest" = "xyes" ; then
			ac_save_CFLAGS="$CFLAGS"
			CFLAGS="$CFLAGS $APACHE_CFLAGS"
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
	if ((major2 > major1) ||
		((major2 == major1) && (minor2 > minor1)) ||
		((major2 == major1) && (minor2 == minor1) && (micro2 >= micro1)))
	{
		return 0;
	} else {
		printf("\n*** This module requires apache version %d.%d.%d or greater\n",
			major1, minor1, micro1);
		printf("*** I found version %d.%d.%d. Please verify the installation directory\n",
			major2, minor2, micro2);
		printf("*** of apache with the --with-apxs configure option.\n");
		return 1;
	}
}

],, no_apxs=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
			CFLAGS="$ac_save_CFLAGS"
   		fi
   	fi
   	if test "x$no_apxs" = x ; then
   		AC_MSG_RESULT(yes)
		ifelse([$2], , :, [$2])
   	else
    	AC_MSG_RESULT(no)
		if test "$APXS_BIN" = "no" ; then
			echo "*** The apxs binary installed by apache could not be found"
			echo "*** If apache is installed in PREFIX, make sure PREFIX/bin is in"
			echo "*** your path, or use the --with-apxs configure option"
		else
			if test -f conf.apachetest ; then
				:
			else
				echo "*** Could not run Apache test program, checking why..."
				CFLAGS="$CFLAGS APACHE_CFLAGS"
				AC_TRY_LINK([
#include <stdio.h>
#include "httpd.h"

int main(int argc, char *argv[])
{ return 0; }
#undef main
#define main K_and_R_C_main
],					[ return 0; ],
					[ echo "*** The test program compiled, but failed to run. Check config.log" ],
					[ echo "*** The test program failed to compile or link. Check config.log" ])
				CFLAGS="$ac_save_CFLAGS"
			fi
		fi
	 	APACHE_CFLAGS=""
	 	ifelse([$3], , :, [$3])
  	fi
  	AC_SUBST(APACHE_CFLAGS)
	AC_SUBST(APACHE_INCDIR)
	AC_SUBST(APACHE_MODDIR)
  	rm -f conf.apachetest
])
