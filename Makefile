# $Id: Makefile,v 1.12 2002/11/14 03:51:34 helios Exp $

#####################################
# Important:
# Adjust these values as outlined in the INSTALL file.
# Not all are needed at all times.

APACHEINST = /usr/local/Apache
MYSQLLIBS  = /usr/lib
MYSQLHDRS  = /usr/include/mysql
#MODSSLHDRS = /usr/local/src/apache_1.3.27-dso/src/modules/ssl

APACHESOURCE = /usr/local/src/apache_1.3.27-dso
OPNSSLHDRS   = /usr/include/openssl
DB1HDRS      = /usr/include/db1


#####################################
# Shouldn't have to touch below here.

MLMVERS  = 1.17
APXS     = $(APACHEINST)/bin/apxs
#APXSGDB  = -Wc,-g
APXSOPTS = -Wc,-O2 -Wc,-Wall -Wc,-DEAPI
CC       = gcc
INSTALL  = /usr/bin/install -m 664
RM       = /bin/rm

ifdef MODSSLHDRS
   SSLDEF  = -DWANT_SSL_LOGGING
   CFLAGS  = -fPIC -O2 -Wall -I$(APACHEINST)/include -I$(MYSQLHDRS) -I$(MODSSLHDRS) -I$(OPNSSLHDRS) $(SSLDEF) -I$(DB1HDRS)
else
   CFLAGS  = -fPIC -O2 -Wall -I$(APACHEINST)/include -I$(MYSQLHDRS)
endif

all:
	@echo "You can choose to make mod_log_sql as a static or dynamic module."
	@echo "Either 'make dso' or 'make static'."
	@echo
	@echo "Please read the INSTALL file carefully!"

dso: mod_log_sql.so

static: mod_log_sql.o

mod_log_sql.so: mod_log_sql.c Makefile
	$(APXS) $(APXSGDB) $(APXOPTS) -c -I$(MYSQLHDRS) -I$(MODSSLHDRS) $(SSLDEF) -L$(MYSQLLIBS) -lmysqlclient -lz mod_log_sql.c

mod_log_sql.o:	mod_log_sql.c Makefile
	$(CC) ${CFLAGS} -c mod_log_sql.c

dsoinstall: dso
	$(APXS) -i mod_log_sql.so

statinstall: static
	$(INSTALL) -d -m 755 $(APACHESOURCE)/src/modules/sql
	$(INSTALL) mod_log_sql.c $(APACHESOURCE)/src/modules/sql/mod_log_sql.c
	$(INSTALL) Makefile $(APACHESOURCE)/src/modules/sql/Makefile
	$(INSTALL) mod_log_sql.o $(APACHESOURCE)/src/modules/sql/mod_log_sql.o

clean:
	$(RM) -rf *.o *.so

distro: all
	cp -f INSTALL $(APACHEINST)/html/mod_log_sql/
	cp -f README $(APACHEINST)/html/mod_log_sql/
	cp -f CHANGELOG $(APACHEINST)/html/mod_log_sql/
	cd ..; tar zcf mod_log_sql-$(MLMVERS).tar.gz --exclude mod_log_sql/CVS mod_log_sql/; $(INSTALL) mod_log_sql-$(MLMVERS).tar.gz $(APACHEINST)/html/mod_log_sql/; rm -f mod_log_sql-$(MLMVERS).tar.gz
	rm -f $(APACHEINST)/html/mod_log_sql/mod_log_sql.tar.gz
	ln -s mod_log_sql-$(MLMVERS).tar.gz $(APACHEINST)/html/mod_log_sql/mod_log_sql.tar.gz

