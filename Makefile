# $Id: Makefile,v 1.21 2002/12/18 22:56:37 helios Exp $

###########################################################################
# Important:
# Adjust these values as outlined in section "Installation" in the docs.
# Not all are needed at all times.

APACHESOURCE    = /usr/local/src/apache_1.3.27-dso
APACHEINSTALLED = /usr/local/Apache
APACHEHEADERS   = /usr/local/Apache/include
APXS            = $(APACHEINSTALLED)/bin/apxs

MYSQLLIBRARIES  = /usr/lib
MYSQLHEADERS    = /usr/include/mysql

#MODSSLHEADERS   = /usr/local/src/apache_1.3.27-dso/src/modules/ssl
#DB1HEADERS      = /usr/include/db1

###########################################################################
# Don't uncomment this without reading the "Optimizing for a busy database"
# section in the documentation (under "Advanced logging scenarios").

#MYSQLDELAYED = -DWANT_DELAYED_MYSQL_INSERT

###########################################################################
# Rarely if ever have to touch below here.

MLMVERS  = 1.18
#APXSGDB  = -Wc,-g
APXSOPTS = -Wc,-O2 -Wc,-Wall
STATOPTS = -fpic -O2 -Wall
CC       = gcc
INSTALL  = /usr/bin/install -m 664
RM       = /bin/rm
LYX      = /usr/bin/lyx
LATEX    = /usr/bin/latex
DVIPS    = /usr/bin/dvips
LINKS    = /usr/bin/lynx
L2H      = /usr/bin/latex2html
WEBSERV  = gw0.corp

STATFLAGS = -I$(APACHEHEADERS)
SOFLAGS   = -L$(MYSQLLIBRARIES) -lmysqlclient -lz
ifdef MODSSLHEADERS
   FLAGS     = -DEAPI -I$(MYSQLHEADERS) $(MYSQLDELAYED) -I$(MODSSLHEADERS) -I$(DB1HEADERS) -DWANT_SSL_LOGGING
else
   FLAGS     = -DEAPI -I$(MYSQLHEADERS) $(MYSQLDELAYED)
endif

all:
	@echo "You can choose to make mod_log_sql as a static or dynamic module."
	@echo "Either 'make dso' or 'make static'."
	@echo
	@echo "Please first read the documentation carefully!"

dso: mod_log_sql.so

static: mod_log_sql.o

mod_log_sql.so: mod_log_sql.c Makefile
	$(APXS) -c $(APXSGDB) $(APXSOPTS) $(FLAGS) $(SOFLAGS) mod_log_sql.c

mod_log_sql.o:	mod_log_sql.c Makefile
	$(CC) $(STATOPTS) $(FLAGS) $(STATFLAGS) -c mod_log_sql.c

dsoinstall: dso
	$(APXS) -i mod_log_sql.so

statinstall: static
	$(INSTALL) -d -m 755 $(APACHESOURCE)/src/modules/sql
	$(INSTALL) mod_log_sql.c $(APACHESOURCE)/src/modules/sql/mod_log_sql.c
	$(INSTALL) Makefile $(APACHESOURCE)/src/modules/sql/Makefile
	$(INSTALL) mod_log_sql.o $(APACHESOURCE)/src/modules/sql/mod_log_sql.o

clean:
	$(RM) -rf *.o *.so
	$(RM) -f Documentation/HTML/*.html Documentation/HTML/*.css Documentation/HTML/*.png
	$(RM) -f Documentation/*.tex
	$(RM) -f Documentation/*.dvi
	$(RM) -f Documentation/*.ps
	$(RM) -f Documentation/*.txt

distro: documentation
	@scp CHANGELOG $(WEBSERV):$(APACHEINSTALLED)/html/mod_log_sql/docs
	@scp Documentation/*.ps $(WEBSERV):$(APACHEINSTALLED)/html/mod_log_sql/docs
	@scp Documentation/HTML/*.html $(WEBSERV):$(APACHEINSTALLED)/html/mod_log_sql/docs/
	@scp Documentation/HTML/*.png $(WEBSERV):$(APACHEINSTALLED)/html/mod_log_sql/docs/
	@cd ..; tar jcf mod_log_sql-$(MLMVERS).tar.bz2 --exclude mod_log_sql/CVS --exclude mod_log_sql/Documentation/CVS --exclude mod_log_sql/Documentation/HTML/CVS --exclude ".directory" mod_log_sql/; scp mod_log_sql-$(MLMVERS).tar.bz2 $(WEBSERV):$(APACHEINSTALLED)/html/mod_log_sql/; rm -f mod_log_sql-$(MLMVERS).tar.bz2
	@ssh $(WEBSERV) "ln -sf mod_log_sql-$(MLMVERS).tar.bz2 $(APACHEINSTALLED)/html/mod_log_sql/mod_log_sql.tar.bz2"

pre-distro: documentation
	@cd ..; tar jcf mod_log_sql-$(MLMVERS).tar.bz2 --exclude mod_log_sql/CVS --exclude mod_log_sql/Documentation/CVS --exclude mod_log_sql/Documentation/HTML/CVS --exclude ".directory" mod_log_sql/; scp mod_log_sql-$(MLMVERS).tar.bz2 $(WEBSERV):$(APACHEINSTALLED)/html/mod_log_sql/; rm -f mod_log_sql-$(MLMVERS).tar.bz2

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
	@$(L2H) -local_icons -show_section_numbers -split 4 -navigation -noindex_in_navigation -contents_in_navigation -dir Documentation/HTML Documentation/documentation.tex >/dev/null 2>&1
	@echo "Creating plain text docs..."
	@$(L2H) -show_section_numbers -split 0 -dir Documentation/ Documentation/documentation.tex >/dev/null 2>&1
	@$(LINKS) -dump -nolist -width=120 -dump Documentation/documentation.html > Documentation/documentation.txt 2>/dev/null
	@echo "Cleaning up..."
	@$(RM) -f Documentation/*.html Documentation/WARNINGS Documentation/*.pl Documentation/*.aux Documentation/*.css Documentation/*.toc Documentation/*.log Documentation/*.old Documentation/*.png Documentation/images.tex
	@$(RM) -f Documentation/HTML/WARNINGS Documentation/HTML/*.pl Documentation/HTML/*.log Documentation/HTML/*.aux Documentation/HTML/*.tex Documentation/HTML/*.old Documentation/HTML/index.html
