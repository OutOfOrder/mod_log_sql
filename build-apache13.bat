@echo off
cls
rem path to Microsoft SDK installation
SET DIR_MSSDK=C:\Program Files\Microsoft SDK
rem path to apache2 installation
SET DIR_APACHE=C:\Program Files\Apache Group\Apache
rem path to mysql 4.0 installation
SET DIR_MYSQL=C:\MySQL
rem Can be set to opt or debug
SET LIB_MYSQL=opt

copy /Y winconfig.h config.h
mkdir Release
cd Release
Rem Compile all the source code
echo /MD /W3 /Zi /Ze /O2 > RESP_c.txt
echo /DNDEBUG /D_WINDOWS /DWIN32 >> RESP_c.txt
echo /Fd"mod_log_sql" /FD >> RESP_c.txt
echo /DHAVE_CONFIG_H /DWITH_APACHE13 /DLOGSQL_DECLARE_EXPORT >> RESP_c.txt
echo /DSHARED_MODULE >> RESP_c.txt
echo /I.. >> RESP_c.txt
echo /I"%DIR_MSSDK%\Include" >> RESP_c.txt
echo /I"%DIR_APACHE%\Include" >> RESP_c.txt
echo /I"%DIR_MYSQL%\Include" >> RESP_c.txt
cl @RESP_c.txt /c ..\mod_log_sql.c ..\mod_log_sql_mysql.c

rem link main module
echo /MACHINE:I386 /SUBSYSTEM:windows > RESP_l.txt
echo /OUT:mod_log_sql.so /DLL /OPT:REF /DEBUG >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\lib" >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\libexec" >> RESP_l.txt
echo /LIBPATH:"%DIR_MSSDK%\lib" >> RESP_l.txt
echo ApacheCore.lib >> RESP_l.txt
link @RESP_l.txt mod_log_sql.obj

rem link mysql module
echo /MACHINE:I386 /SUBSYSTEM:windows > RESP_l.txt
echo /OUT:mod_log_sql_mysql.so /DLL /OPT:REF /DEBUG >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\lib" >> RESP_l.txt
echo /LIBPATH:"%DIR_APACHE%\libexec" >> RESP_l.txt
echo /LIBPATH:"%DIR_MYSQL%\lib\%LIB_MYSQL%" >> RESP_l.txt
echo /LIBPATH:"%DIR_MSSDK%\lib" >> RESP_l.txt
echo /NODEFAULTLIB:LIBCMT.lib >> RESP_l.txt
echo ApacheCore.lib >> RESP_l.txt
echo libmysql.lib mod_log_sql.lib >> RESP_l.txt
link @RESP_l.txt mod_log_sql_mysql.obj
cd ..
