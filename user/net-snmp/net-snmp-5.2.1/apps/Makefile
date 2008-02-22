SUBDIRS		=

top_builddir=..

#
# Things to install
#

INSTALLBINPROGS	= snmpget$(EXEEXT) 			\
		snmpgetnext$(EXEEXT) 			\
		snmpset$(EXEEXT) 			\
		snmpusm$(EXEEXT)			\
		snmpwalk$(EXEEXT) 			\
		snmpbulkwalk$(EXEEXT) 			\
		snmptable$(EXEEXT)			\
		snmptrap$(EXEEXT) 			\
		snmpbulkget$(EXEEXT)			\
		snmptranslate$(EXEEXT) 			\
		snmpstatus$(EXEEXT) 			\
		snmpdelta$(EXEEXT) 			\
		snmptest$(EXEEXT)			\
		encode_keychange$(EXEEXT) 		\
		snmpdf$(EXEEXT) 			\
		snmpvacm$(EXEEXT)

INSTALLSBINPROGS = snmptrapd$(EXEEXT)


#
# build variables.
#

USELIBS		= ../snmplib/libnetsnmp.$(LIB_EXTENSION)$(LIB_VERSION) 
USETRAPLIBS	= ../agent/libnetsnmpagent.$(LIB_EXTENSION)$(LIB_VERSION) ../agent/libnetsnmpmibs.$(LIB_EXTENSION)$(LIB_VERSION) ../agent/helpers/libnetsnmphelpers.$(LIB_EXTENSION)$(LIB_VERSION) $(USELIBS)
LOCAL_LIBS	= -L../snmplib -L../agent -L../agent/helpers
LIBS		= $(USELIBS) $(LDLIBS$(LDLIBS_$@))
TRAPLIBS	= $(USETRAPLIBS) $(LDLIBS$(LDLIBS_$@))

CPPFLAGS	= -I$(top_srcdir)/include -I../include \
		  -I.. -I$(srcdir)/.. -I$(srcdir)/../snmplib \
		   -I$(srcdir)/../agent -I../agent/helpers \
		  -I$(srcdir)/../agent/mibgroup
OSUFFIX		= o
TRAPD_OBJECTS   = snmptrapd.$(OSUFFIX) snmptrapd_handlers.$(OSUFFIX) snmptrapd_log.$(OSUFFIX) notification_log.$(OSUFFIX)
OBJS  = *.o

all: standardall

OTHERINSTALL=snmpinforminstall

#
# build rules
#
snmpwalk$(EXEEXT):    snmpwalk.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpwalk.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpbulkwalk$(EXEEXT):    snmpbulkwalk.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpbulkwalk.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpbulkget$(EXEEXT):    snmpbulkget.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpbulkget.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmptranslate$(EXEEXT):    snmptranslate.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmptranslate.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpstatus$(EXEEXT):    snmpstatus.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpstatus.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpget$(EXEEXT):    snmpget.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpget.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpdelta$(EXEEXT):    snmpdelta.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpdelta.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmptable$(EXEEXT):    snmptable.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmptable.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmptest$(EXEEXT):    snmptest.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmptest.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmptrapd$(EXEEXT):    $(TRAPD_OBJECTS) $(USETRAPLIBS) 
	$(LINK) -o $@ $(TRAPD_OBJECTS) $(LOCAL_LIBS) ${LDFLAGS} ${TRAPLIBS} 

snmptrap$(EXEEXT):    snmptrap.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmptrap.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpinform$(EXEEXT): snmptrap$(EXEEXT)
	rm -f snmpinform
	$(LN_S) snmptrap$(EXEEXT) snmpinform$(EXEEXT)

snmpset$(EXEEXT):    snmpset.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpset.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpusm$(EXEEXT):    snmpusm.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpusm.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpvacm$(EXEEXT):    snmpvacm.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpvacm.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpgetnext$(EXEEXT):    snmpgetnext.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpgetnext.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

encode_keychange$(EXEEXT):    encode_keychange.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ encode_keychange.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpdf$(EXEEXT):    snmpdf.$(OSUFFIX) $(USELIBS)
	$(LINK) -o $@ snmpdf.$(OSUFFIX) $(LOCAL_LIBS) ${LDFLAGS} ${LIBS} 

snmpinforminstall:
	rm -f $(bindir)/snmpinform$(EXEEXT)
	$(LN_S) snmptrap$(EXEEXT) $(bindir)/snmpinform$(EXEEXT)

#
# standard target definitions.  Set appropriate variables to make use of them.
#
# note: the strange use of the "it" variable is for shell parsing when
# there is no targets to install for that rule.
#

# the standard items to build: libraries, bins, and sbins
STANDARDTARGETS     =$(INSTALLLIBS) $(INSTALLBINPROGS) $(INSTALLSBINPROGS)
STANDARDCLEANTARGETS=$(INSTALLLIBS) $(INSTALLBINPROGS) $(INSTALLSBINPROGS) $(INSTALLUCDLIBS)

standardall: subdirs $(STANDARDTARGETS)

subdirs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making all in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) ) ; \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

install: installlocalheaders  \
         installlocallibs        \
         installlocalbin      installlocalsbin   \
         installsubdirs      $(OTHERINSTALL)

installprogs: installbin installsbin

#
# headers
#
# set INSTALLHEADERS to a list of things to install in each makefile.
# set INSTALLBUILTHEADERS to a list of things to install from builddir
# set INSTALLSUBDIRHEADERS and INSTALLSUBDIR to subdirectory headers
# set INSTALLSUBDIRHEADERS2 and INSTALLSUBDIR2 to more subdirectory headers
# set INSTALLBUILTSUBDIRHEADERS and INSTALLBUILTSUBDIR to a list from builddir
#
installheaders: installlocalheaders  installsubdirheaders

installlocalheaders:
	@if test "$(INSTALLHEADERS)" != "" ; then \
		echo creating directory $(includedir) ; \
		it="$(INSTALLHEADERS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(includedir) ; \
	        for i in $$it ; do \
			$(INSTALL) $(top_srcdir)/include/net-snmp/$$i $(includedir) ; \
	                echo "installing $$i in $(includedir)" ; \
	        done \
	fi
	@if test "$(INSTALLBUILTHEADERS)" != "" ; then \
		echo creating directory $(includedir) ; \
		it="$(INSTALLBUILTHEADERS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(includedir) ; \
	        for i in $$it ; do \
			$(INSTALL) $$i $(includedir) ; \
	                echo "installing $$i in $(includedir)" ; \
	        done \
	fi
	@if test "$(INCLUDESUBDIRHEADERS)" != "" ; then \
		echo creating directory $(includedir)/$(INCLUDESUBDIR) ; \
		it="$(INCLUDESUBDIRHEADERS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(includedir)/$(INCLUDESUBDIR) ; \
	        for i in $$it ; do \
			$(INSTALL) $(top_srcdir)/include/net-snmp/$(INCLUDESUBDIR)/$$i $(includedir)/$(INCLUDESUBDIR) ; \
	                echo "installing $$i in $(includedir)/$(INCLUDESUBDIR)" ; \
	        done \
	fi
	@if test "$(INCLUDESUBDIRHEADERS2)" != "" ; then \
		echo creating directory $(includedir)/$(INCLUDESUBDIR2) ; \
		it="$(INCLUDESUBDIRHEADERS2)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(includedir)/$(INCLUDESUBDIR2) ; \
	        for i in $$it ; do \
			$(INSTALL) $(top_srcdir)/include/net-snmp/$(INCLUDESUBDIR2)/$$i $(includedir)/$(INCLUDESUBDIR2) ; \
	                echo "installing $$i in $(includedir)/$(INCLUDESUBDIR2)" ; \
	        done \
	fi
	@if test "$(INSTALLBUILTSUBDIRHEADERS)" != "" ; then \
		echo creating directory $(includedir)/$(INSTALLBUILTSUBDIR) ; \
		it="$(INSTALLBUILTSUBDIRHEADERS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(includedir)/$(INSTALLBUILTSUBDIR) ; \
	        for i in $$it ; do \
			$(INSTALL) $$i $(includedir)/$(INSTALLBUILTSUBDIR) ; \
	                echo "installing $$i in $(includedir)/$(INSTALLBUILTSUBDIR)" ; \
	        done \
	fi

installsubdirheaders:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making installheaders in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) installheaders) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

installucdheaders:
	@if test "$(INSTALLUCDHEADERS)" != "" ; then \
		echo creating directory $(ucdincludedir) ; \
		it="$(INSTALLUCDHEADERS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(ucdincludedir) ; \
	        for i in $$it ; do \
			$(INSTALL) $(top_srcdir)/include/ucd-snmp/$$i $(ucdincludedir) ; \
	                echo "installing $$i in $(ucdincludedir)" ; \
	        done \
	fi

#
# libraries
#
# set INSTALLLIBS to a list of things to install in each makefile.
#
installlibs: installlocallibs  installsubdirlibs

installlocallibs: $(INSTALLLIBS)
	@if test "$(INSTALLLIBS)" != ""; then \
		it="$(INSTALLLIBS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(libdir) ; \
                $(INSTALL) $(INSTALLLIBS) $(libdir) ;              \
	        for i in $$it ; do    \
	                echo "installing $$i in $(libdir)"; \
	                $(RANLIB) $(libdir)/$$i ; \
	        done ; \
		$(LIB_LDCONFIG_CMD) ; \
	fi

installucdlibs: $(INSTALLUCDLIBS)
	@if test "$(INSTALLUCDLIBS)" != ""; then \
		it="$(INSTALLUCDLIBS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(libdir) ; \
                $(INSTALL) $(INSTALLUCDLIBS) $(libdir) ;              \
	        for i in $$it ; do    \
	                echo "installing $$i in $(libdir)"; \
	                $(RANLIB) $(libdir)/$$i ; \
	        done ; \
		$(LIB_LDCONFIG_CMD) ; \
	fi

installsubdirlibs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making installlibs in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) installlibs) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

#
# normal bin binaries
#
# set INSTALLBINPROGS to a list of things to install in each makefile.
#
installbin: installlocalbin installsubdirbin

installlocalbin: $(INSTALLBINPROGS)
	@if test "$(INSTALLBINPROGS) $(INSTALLBINSCRIPTS)" != " "; then \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(bindir) ; \
		it="$(INSTALLBINPROGS) $(INSTALLBINSCRIPTS)" ; \
	        $(INSTALL) $(INSTALLBINPROGS) $(INSTALLBINSCRIPTS) $(bindir) ;              \
	        for i in $$it ; do   \
	                echo "installing $$i in $(bindir)"; \
	        done \
	fi

installsubdirbin:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making installbin in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) installbin) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

#
# sbin binaries
#
# set INSTALLSBINPROGS to a list of things to install in each makefile.
#
installsbin: installlocalsbin installsubdirsbin

installlocalsbin: $(INSTALLSBINPROGS)
	@if test "$(INSTALLSBINPROGS)" != ""; then \
		it="$(INSTALLSBINPROGS)" ; \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(sbindir) ; \
	        $(INSTALL) $(INSTALLSBINPROGS) $(sbindir) ;              \
	        for i in $$it ; do   \
	                echo "installing $$i in $(sbindir)"; \
	        done \
	fi

installsubdirsbin:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making installsbin in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) installsbin) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

#
# general make install target for subdirs
#
installsubdirs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making install in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) install) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

#
# cleaning targets
#
clean: cleansubdirs $(OTHERCLEANTODOS)
	rm -f core ${OBJS} ${OBJS} $(STANDARDCLEANTARGETS) $(OTHERCLEANTARGETS)
	rm -rf .libs

cleansubdirs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making clean in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) clean) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

lint:
	lint -nhx $(CSRCS)

#
# wacky dependency building.
#
depend: dependdirs
	@if test -f Makefile.depend ; then \
		makedepend `echo $(CPPFLAGS) | sed 's/-f[-a-z]*//g'` -o .lo $(srcdir)/*.c $(srcdir)/*/*.c ; \
	fi


nosysdepend: nosysdependdirs
	@if test -f Makefile.depend ; then \
		makedepend `echo $(CPPFLAGS) | sed 's/-f[-a-z]*//g'` -o .lo $(srcdir)/*.c $(srcdir)/*/*.c ; \
		perl -n -i.bak $(top_srcdir)/makenosysdepend.pl Makefile ; \
	fi

distdepend: nosysdepend distdependdirs
	@if test -f Makefile.depend ; then \
		perl $(top_srcdir)/makefileindepend.pl ; \
	fi

dependdirs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making depend in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) depend) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

nosysdependdirs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making nosysdepend in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) nosysdepend) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

distdependdirs:
	@if test "$(SUBDIRS)" != ""; then \
		it="$(SUBDIRS)" ; \
		for i in $$it ; do       \
			echo "making distdepend in `pwd`/$$i"; \
	                ( cd $$i ; $(MAKE) distdepend) ;   \
                        if test $$? != 0 ; then \
				exit 1 ; \
			fi  \
	        done \
	fi

# These aren't real targets, let gnu's make know that.
.PHONY: clean cleansubdirs lint \
	install installprogs installheaders installlibs \
	installbin installsbin installsubdirs \
	all subdirs standardall \
	depend nosysdepend distdepend dependdirs nosysdependdirs distdependdirs
