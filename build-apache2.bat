@echo off
rem path to Microsoft SDK installation
SET DIR_MSSDK=C:\Program Files\Microsoft SDK
rem path to apache2 installation
SET DIR_APACHE=C:\Program Files\Apache Group\Apache2
rem path to mysql 4.0 installation
SET DIR_MYSQL=C:\MySQL
rem Can be set to opt or debug
SET LIB_MYSQL=opt
rem path to OpenSSL installation
SET DIR_OPENSSL=C:\OpenSSL
rem Should be set to VC
SET LIB_OPENSSL=VC

copy /Y winconfig.h config.h
mkdir Release
cd Release
Rem Compile all the source code
echo /MD /W3 /Zi /O2 /DNDEBUG /D_WINDOWS /DWIN32 > RESP_c.txt
echo /Fd"mod_log_sql" /FD >> RESP_c.txt
echo /DHAVE_CONFIG_H /DWITH_APACHE20 /DLOGSQL_DECLARE_EXPORT >> RESP_c.txt
echo /I.. >> RESP_c.txt
echo /I"%DIR_MSSDK%\Include" >> RESP_c.txt
echo /I"%DIR_APACHE%\Include" >> RESP_c.txt
echo /I"%DIR_MYSQL%\Include" >> RESP_c.txt
echo /I"%DIR_OPENSSL%\Include" >> RESP_c.txt
echo /I"%DIR_OPENSSL%\Include\openssl" >> RESP_c.txt
cl @RESP_c.txt /c ..\mod_log_sql.c ..\mod_log_sql_mysql.c

if not exist "%DIR_APACHE%\Include\mod_ssl.h" goto nossl
cl @RESP_C.txt /c ..\mod_log_sql_ssl.c
:nossl

rem link main module
echo /MACHINE:I386 /SUBSYSTEM:windows > RESP_l.txt
echo /OUT:mod_log_sql.so /DLL /OPT:REF /DEBUG >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\lib" >> RESP_l.txt
echo libapr.lib libaprutil.lib libhttpd.lib >> RESP_l.txt
link @RESP_l.txt mod_log_sql.obj

rem link mysql module
echo /MACHINE:I386 /SUBSYSTEM:windows > RESP_l.txt
echo /OUT:mod_log_sql_mysql.so /DLL /OPT:REF /DEBUG >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\lib" >> RESP_l.txt
echo /LIBPATH:"%DIR_MYSQL%\lib\%LIB_MYSQL%" >> RESP_l.txt
echo /NODEFAULTLIB:LIBCMT.lib >> RESP_l.txt
echo libapr.lib libaprutil.lib libhttpd.lib >> RESP_l.txt
echo libmysql.lib mod_log_sql.lib >> RESP_l.txt
link @RESP_l.txt mod_log_sql_mysql.obj

if not exist "%DIR_APACHE%\Include\mod_ssl.h" goto done
rem link ssl module
echo /MACHINE:I386 /SUBSYSTEM:windows > RESP_l.txt
echo /OUT:mod_log_sql_ssl.so /DLL /OPT:REF /DEBUG >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\lib" >> RESP_l.txt
echo /LIBPATH:"%DIR_OPENSSL%\lib\%LIB_OPENSSL%" >> RESP_l.txt
echo libapr.lib libaprutil.lib libhttpd.lib >> RESP_l.txt
echo mod_log_sql.lib >> RESP_l.txt
link @RESP_l.txt mod_log_sql_ssl.obj

:done
cd ..
