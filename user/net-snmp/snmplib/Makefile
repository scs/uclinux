# Portions of this file are subject to the following copyright.  See
# the Net-SNMP's COPYING file for more details and other copyrights
# that may apply:
#
# Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
# Use is subject to license terms specified in the COPYING file
# distributed with the Net-SNMP package.
#
SUBDIRS=

#
# Makefile for snmplib
#

top_builddir=..

#
# Things to install
#

# headers
INSTALLHEADERS=\
	net-snmp-includes.h \
	config_api.h  \
	mib_api.h     \
	output_api.h  \
	pdu_api.h     \
	session_api.h \
	snmpv3_api.h  \
	varbind_api.h \
	types.h       \
	utilities.h   \
	version.h     \
	definitions.h

INCLUDESUBDIR=library
INCLUDESUBDIRHEADERS=README \
	asn1.h \
	callback.h \
	container.h \
	container_binary_array.h \
	factory.h \
	data_list.h \
	default_store.h \
	int64.h \
	keytools.h \
	mib.h \
	md5.h \
	parse.h \
	read_config.h \
	scapi.h \
	snmp.h \
	snmp_alarm.h \
	snmp_api.h \
	snmp_assert.h \
	snmp_client.h \
	snmp_debug.h \
	snmp_impl.h \
	snmp_logging.h \
	snmp_parse_args.h \
	snmp-tc.h \
	snmpv3.h \
	system.h \
	tools.h \
	transform_oids.h \
	winservice.h \
        cmu_compat.h \
        getopt.h \
        lcd_time.h \
        mt_support.h \
        oid_stash.h \
        snmp_enum.h \
        snmp_locking.h \
        snmp_secmod.h \
        ucd_compat.h \
        vacm.h \
	check_varbind.h \
	snmp_transport.h \
	snmpUDPDomain.h snmpTCPDomain.h snmpCallbackDomain.h  \
	 snmpusm.h

INSTALLBUILTSUBDIRHEADERS=../include/net-snmp/library/snmpv3-security-includes.h
INSTALLBUILTSUBDIR=library


INSTALLUCDHEADERS= asn1.h \
	callback.h	\
	default_store.h	\
	int64.h		\
	keytools.h	\
	mib.h		\
	parse.h		\
	read_config.h	\
	scapi.h		\
	snmp_alarm.h	\
	snmp_api.h	\
	snmp_client.h	\
	snmp_debug.h	\
	snmp.h		\
	snmp_impl.h	\
	snmp_logging.h	\
	snmp_parse_args.h \
	snmp-tc.h	\
	snmpusm.h	\
	snmpv3.h	\
	snmp_vars.h	\
	struct.h	\
	system.h	\
	tools.h		\
	transform_oids.h

# libraries
INSTALLLIBS=libnetsnmp.a
INSTALLUCDLIBS=libsnmp.a

#
# Things to build
#
CSRCS=	snmp_client.c mib.c parse.c snmp_api.c snmp.c 		\
	snmp_auth.c asn1.c md5.c snmp_parse_args.c		\
	system.c vacm.c int64.c read_config.c 			\
	snmp_debug.c tools.c  snmp_logging.c			\
	snmpv3.c lcd_time.c keytools.c		                \
	scapi.c callback.c default_store.c snmp_alarm.c		\
	data_list.c oid_stash.c 				\
	mt_support.c snmp_enum.c snmp-tc.c 			\
	snprintf.c strlcpy.c strtol.c strtoul.c			\
	snmp_transport.c                                        \
	snmpUDPDomain.c snmpTCPDomain.c snmpCallbackDomain.c  \
	snmp_secmod.c snmp_version.c                            \
	 snmpusm.c \
	check_varbind.c container.c container_binary_array.c	\
	cmu_compat.c ucd_compat.c

OBJS=	$(CSRCS:.c=.o)

# just in case someone wants to remove libtool, change this to OBJS.
TOBJS=$(OBJS)

CPPFLAGS = -I$(top_srcdir)/include -I../include \
	-I. -I.. -I$(srcdir) -I$(srcdir)/.. 

all: standardall

# how to build the libraries.
libnetsnmp.a:    ${TOBJS}
	$(LIB_LD_CMD) libnetsnmp.a ${TOBJS}
	$(RANLIB) libnetsnmp.a

libsnmp.a:    ${TOBJS}
	$(LIB_LD_CMD) libsnmp.a ${TOBJS}
	$(RANLIB) libsnmp.a

#
# internal test objects
#
parse:  mib.o parse.c
	$(CC) $(CFLAGS) -DTEST parse.c -o parse \
		`$(top_srcdir)/net-snmp-config --libs`

test_binary_array: test_binary_array.c
	$(CC) $(CFLAGS) test_binary_array.c  -o $@ \
		`$(top_srcdir)/net-snmp-config --libs`

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
	rm -f core ${OBJS} ${LOBJS} $(STANDARDCLEANTARGETS) $(OTHERCLEANTARGETS)
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

romfs:
