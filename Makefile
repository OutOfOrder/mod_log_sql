# $Id: Makefile,v 1.15 2002/11/17 04:23:57 helios Exp $

#####################################
# Important:
# Adjust these values as outlined in the INSTALL file.
# Not all are needed at all times.

APACHEINST = /usr/local/Apache
MYSQLLIBS  = /usr/lib
MYSQLHDRS  = /usr/include/mysql
MODSSLHDRS = /usr/local/src/apache_1.3.27-dso/src/modules/ssl

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
LYX      = /usr/bin/lyx
LATEX    = /usr/bin/latex
DVIPS    = /usr/bin/dvips
LINKS    = /usr/bin/links
L2H      = /usr/local/bin/latex2html
WEBSERV  = gw0.corp

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
	@echo "Please first read the documentation carefully!"

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
	$(RM) -f Documentation/HTML/*.html Documentation/HTML/*.css
	$(RM) -f Documentation/*.tex
	$(RM) -f Documentation/*.dvi
	$(RM) -f Documentation/*.ps
	$(RM) -f Documentation/*.txt

distro: documentation
	@scp CHANGELOG $(WEBSERV):$(APACHEINST)/html/mod_log_sql/docs
	@scp Documentation/*.ps $(WEBSERV):$(APACHEINST)/html/mod_log_sql/docs
	@scp Documentation/HTML/*.html $(WEBSERV):$(APACHEINST)/html/mod_log_sql/docs/
	@cd ..; tar zcf mod_log_sql-$(MLMVERS).tar.gz --exclude mod_log_sql/CVS --exclude mod_log_sql/Documentation/CVS --exclude mod_log_sql/Documentation/HTML/CVS --exclude ".directory" mod_log_sql/; scp mod_log_sql-$(MLMVERS).tar.gz $(WEBSERV):$(APACHEINST)/html/mod_log_sql/; rm -f mod_log_sql-$(MLMVERS).tar.gz
	@ssh $(WEBSERV) "ln -sf mod_log_sql-$(MLMVERS).tar.gz $(APACHEINST)/html/mod_log_sql/mod_log_sql.tar.gz"

documentation: Documentation/documentation.lyx
	@echo "Creating LaTeX docs..."
	@$(LYX) --export latex Documentation/documentation.lyx 2>/dev/null
	@echo "Creating cross-references...run 1"
	@cd Documentation ; $(LATEX) documentation.tex >/dev/null 2>&1
	@echo "Creating cross-references...run 2"
	@cd Documentation ; $(LATEX) documentation.tex >/dev/null 2>&1
	@echo "Creating cross-references...run 3"
	@cd Documentation ; $(LATEX) documentation.tex >/dev/null 2>&1
	@echo "Creating PostScript docs..."
	@$(DVIPS) Documentation/documentation.dvi -o Documentation/documentation.ps 2>/dev/null
	@echo "Creating HTML docs..."
	@$(L2H) -show_section_numbers -split 4 -navigation -noindex_in_navigation -contents_in_navigation -dir Documentation/HTML Documentation/documentation.tex >/dev/null 2>&1
	@echo "Creating plain text docs..."
	@$(L2H) -show_section_numbers -split 0 -dir Documentation/ Documentation/documentation.tex >/dev/null 2>&1
	@$(LINKS) -dump Documentation/documentation.html > Documentation/documentation.txt 2>/dev/null
	@echo "Cleaning up..."
	@$(RM) -f Documentation/*.html Documentation/WARNINGS Documentation/*.pl Documentation/*.aux Documentation/*.css Documentation/*.toc Documentation/*.log
	@$(RM) -f Documentation/HTML/WARNINGS Documentation/HTML/*.pl
