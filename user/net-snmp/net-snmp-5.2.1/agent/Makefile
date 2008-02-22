#
# Makefile for snmpd
#

# We need a great, big stack!
FLTFLAGS += -s 40000

top_builddir	= ..

#
# what to install
#
SUBDIRS=helpers mibgroup

INSTALLSBINPROGS= snmpd$(EXEEXT)
INSTALLLIBS	= libnetsnmpagent.$(LIB_EXTENSION)$(LIB_VERSION) \
		libnetsnmpmibs.$(LIB_EXTENSION)$(LIB_VERSION)

INCLUDESUBDIR=agent
INCLUDESUBDIRHEADERS=agent_read_config.h \
	agent_registry.h \
	agent_index.h \
	agent_trap.h \
	auto_nlist.h \
	ds_agent.h \
	snmp_agent.h \
	snmp_vars.h \
	var_struct.h \
	agent_handler.h \
	net-snmp-agent-includes.h \
	agent_callbacks.h

INSTALLBUILTSUBDIRHEADERS=../include/net-snmp/agent/mib_module_config.h \
			mibgroup/mib_module_includes.h
INSTALLBUILTSUBDIR=agent

OTHERINSTALL=

# XXX: need to install these  They're really UCD specific, however.
BROKEINSTALL= \
	mib_modules.h \
	mibgroup/struct.h \
	mibgroup/util_funcs.h \
	mibgroup/mibincl.h \
	mibgroup/header_complex.h

INSTALLUCDHEADERS= \
	agent_index.h	\
	agent_read_config.h \
	agent_registry.h \
	agent_trap.h	\
	auto_nlist.h	\
	ds_agent.h	\
	header_complex.h \
	mibincl.h	\
	snmp_agent.h	\
	ucd-snmp-includes.h	\
	ucd-snmp-agent-includes.h \
	util_funcs.h	\
	var_struct.h

#
# how to build it info
#
USELIBS		= ../snmplib/libnetsnmp.$(LIB_EXTENSION)$(LIB_VERSION)
HELPERLIB	= helpers/libnetsnmphelpers.$(LIB_EXTENSION)$(LIB_VERSION)
LOCAL_LIBS	= 
LIBS		= ../snmplib/libnetsnmp.$(LIB_EXTENSION)$(LIB_VERSION)
WRAPLIBS	= 
OUR_AGENT_LIBS	= $(INSTALLLIBS) $(HELPERLIB) $(WRAPLIBS) $(LIBS) 
CPPFLAGS	= -I../include -I$(top_srcdir)/include \
		  -I.. -I$(srcdir)/.. -I$(srcdir)/../snmplib \
		  -I$(srcdir) -I. -I$(srcdir)/mibgroup -Imibgroup 

#
# Objects
#

# libnetsnmpmib objects.
MIBOBJS		=   mibgroup/mibII/system_mib.o  mibgroup/mibII/sysORTable.o  mibgroup/mibII/at.o  mibgroup/mibII/interfaces.o  mibgroup/mibII/snmp_mib.o  mibgroup/mibII/tcp.o  mibgroup/mibII/icmp.o  mibgroup/mibII/ip.o  mibgroup/mibII/udp.o  mibgroup/mibII/vacm_vars.o  mibgroup/mibII/setSerialNo.o  mibgroup/ucd-snmp/memory.o  mibgroup/ucd-snmp/vmstat.o  mibgroup/ucd-snmp/proc.o  mibgroup/ucd-snmp/versioninfo.o  mibgroup/ucd-snmp/pass.o  mibgroup/ucd-snmp/pass_persist.o  mibgroup/ucd-snmp/disk.o  mibgroup/ucd-snmp/loadave.o  mibgroup/ucd-snmp/extensible.o  mibgroup/ucd-snmp/errormib.o  mibgroup/ucd-snmp/file.o  mibgroup/ucd-snmp/dlmod.o  mibgroup/ucd-snmp/proxy.o  mibgroup/snmpv3/snmpEngine.o  mibgroup/snmpv3/snmpMPDStats.o  mibgroup/snmpv3/usmStats.o  mibgroup/snmpv3/usmUser.o  mibgroup/notification/snmpNotifyTable.o  mibgroup/notification/snmpNotifyFilterTable.o  mibgroup/notification/snmpNotifyFilterProfileTable.o  mibgroup/target/snmpTargetAddrEntry.o  mibgroup/target/snmpTargetParamsEntry.o  mibgroup/target/target.o  mibgroup/target/target_counters.o  mibgroup/utilities/override.o  mibgroup/tunnel/tunnel.o  mibgroup/util_funcs.o  mibgroup/mibII/kernel_linux.o  mibgroup/mibII/tcpTable.o  mibgroup/mibII/ipAddr.o  mibgroup/mibII/var_route.o  mibgroup/mibII/route_write.o  mibgroup/mibII/udpTable.o  mibgroup/mibII/vacm_context.o  mibgroup/header_complex.o    mib_modules.o auto_nlist.o

# libnetsnmpagent objects
LIBAGENTOBJS=snmp_agent.o snmp_vars.o agent_read_config.o agent_registry.o \
	agent_index.o agent_trap.o kernel.o  agent_handler.o \

# The agent objects.
AGENTOBJS=snmpd.o

#
# Define OBJS and OBJS for clean target (just this directory)
#
OBJS		= $(LIBAGENTOBJS)  $(AGENTOBJS)  mib_modules.o  auto_nlist.o

all: standardall

#
# build stuff targets
#
getkstat: getkstat.o
	$(CC) $(CFLAGS) -o $@ $? $(LOCAL_LIBS) $(LIBS)

getkstat.o: mibgroup/kernel_sunos5.c
	$(CC) $(CFLAGS) -o $@ -D_GETKSTAT_TEST -DDODEBUG -c $? 

getmibstat: getmibstat.o
	$(CC) $(CFLAGS) -o $@ $? $(LOCAL_LIBS) $(LIBS)

getmibstat.o: mibgroup/kernel_sunos5.c
	$(CC) $(CFLAGS) -o $@ -D_GETMIBSTAT_TEST -DDODEBUG -c $? 

snmpd$(EXEEXT):	${AGENTOBJS} $(USELIBS) $(HELPERLIB) $(LIBTARG) ${INSTALLLIBS}
	$(LINK) -o $@ ${AGENTOBJS} $(LOCAL_LIBS) ${LDFLAGS} ${OUR_AGENT_LIBS} $(LDLIBS$(LDLIBS_$@))

libnetsnmpagent.$(LIB_EXTENSION)$(LIB_VERSION):    ${LIBAGENTOBJS} libnetsnmpmibs.$(LIB_EXTENSION)$(LIB_VERSION)
	$(LIB_LD_CMD) libnetsnmpagent.$(LIB_EXTENSION)$(LIB_VERSION) ${LIBAGENTOBJS}  $(LIB_LD_LIBS)
	$(RANLIB) libnetsnmpagent.$(LIB_EXTENSION)$(LIB_VERSION)

libnetsnmpmibs.$(LIB_EXTENSION)$(LIB_VERSION):    ${MIBOBJS}
	$(LIB_LD_CMD) libnetsnmpmibs.$(LIB_EXTENSION)$(LIB_VERSION) ${MIBOBJS}  $(LIB_LD_LIBS)
	$(RANLIB) libnetsnmpmibs.$(LIB_EXTENSION)$(LIB_VERSION)

embedperlinstall:
	  @$(SHELL) $(srcdir)/../mkinstalldirs $(snmplibdir)
	  @$(INSTALL) $(srcdir)/snmp_perl.pl $(snmplibdir)/snmp_perl.pl
	  @echo "install:  installed $$i in $(snmplibdir)"

snmp_vars.lo:  mibgroup/mibII.h mibgroup/ucd_snmp.h mibgroup/snmpv3mibs.h mibgroup/notification.h mibgroup/target.h mibgroup/utilities.h mibgroup/tunnel.h mibgroup/mibII/system_mib.h mibgroup/mibII/sysORTable.h mibgroup/mibII/at.h mibgroup/mibII/interfaces.h mibgroup/mibII/snmp_mib.h mibgroup/mibII/tcp.h mibgroup/mibII/icmp.h mibgroup/mibII/ip.h mibgroup/mibII/udp.h mibgroup/mibII/vacm_vars.h mibgroup/mibII/setSerialNo.h mibgroup/ucd-snmp/memory.h mibgroup/ucd-snmp/vmstat.h mibgroup/ucd-snmp/proc.h mibgroup/ucd-snmp/versioninfo.h mibgroup/ucd-snmp/pass.h mibgroup/ucd-snmp/pass_persist.h mibgroup/ucd-snmp/disk.h mibgroup/ucd-snmp/loadave.h mibgroup/ucd-snmp/extensible.h mibgroup/ucd-snmp/errormib.h mibgroup/ucd-snmp/file.h mibgroup/ucd-snmp/dlmod.h mibgroup/ucd-snmp/proxy.h mibgroup/snmpv3/snmpEngine.h mibgroup/snmpv3/snmpMPDStats.h mibgroup/snmpv3/usmStats.h mibgroup/snmpv3/usmUser.h mibgroup/notification/snmpNotifyTable.h mibgroup/notification/snmpNotifyFilterTable.h mibgroup/notification/snmpNotifyFilterProfileTable.h mibgroup/target/snmpTargetAddrEntry.h mibgroup/target/snmpTargetParamsEntry.h mibgroup/target/target.h mibgroup/target/target_counters.h mibgroup/utilities/override.h mibgroup/tunnel/tunnel.h mibgroup/util_funcs.h mibgroup/mibII/kernel_linux.h mibgroup/mibII/tcpTable.h mibgroup/mibII/ipAddr.h mibgroup/mibII/var_route.h mibgroup/mibII/route_write.h mibgroup/mibII/udpTable.h mibgroup/mibII/vacm_context.h mibgroup/header_complex.h
read_config.lo:  mibgroup/mibII.h mibgroup/ucd_snmp.h mibgroup/snmpv3mibs.h mibgroup/notification.h mibgroup/target.h mibgroup/utilities.h mibgroup/tunnel.h mibgroup/mibII/system_mib.h mibgroup/mibII/sysORTable.h mibgroup/mibII/at.h mibgroup/mibII/interfaces.h mibgroup/mibII/snmp_mib.h mibgroup/mibII/tcp.h mibgroup/mibII/icmp.h mibgroup/mibII/ip.h mibgroup/mibII/udp.h mibgroup/mibII/vacm_vars.h mibgroup/mibII/setSerialNo.h mibgroup/ucd-snmp/memory.h mibgroup/ucd-snmp/vmstat.h mibgroup/ucd-snmp/proc.h mibgroup/ucd-snmp/versioninfo.h mibgroup/ucd-snmp/pass.h mibgroup/ucd-snmp/pass_persist.h mibgroup/ucd-snmp/disk.h mibgroup/ucd-snmp/loadave.h mibgroup/ucd-snmp/extensible.h mibgroup/ucd-snmp/errormib.h mibgroup/ucd-snmp/file.h mibgroup/ucd-snmp/dlmod.h mibgroup/ucd-snmp/proxy.h mibgroup/snmpv3/snmpEngine.h mibgroup/snmpv3/snmpMPDStats.h mibgroup/snmpv3/usmStats.h mibgroup/snmpv3/usmUser.h mibgroup/notification/snmpNotifyTable.h mibgroup/notification/snmpNotifyFilterTable.h mibgroup/notification/snmpNotifyFilterProfileTable.h mibgroup/target/snmpTargetAddrEntry.h mibgroup/target/snmpTargetParamsEntry.h mibgroup/target/target.h mibgroup/target/target_counters.h mibgroup/utilities/override.h mibgroup/tunnel/tunnel.h mibgroup/util_funcs.h mibgroup/mibII/kernel_linux.h mibgroup/mibII/tcpTable.h mibgroup/mibII/ipAddr.h mibgroup/mibII/var_route.h mibgroup/mibII/route_write.h mibgroup/mibII/udpTable.h mibgroup/mibII/vacm_context.h mibgroup/header_complex.h
mib_modules.lo: mibgroup/mib_module_inits.h

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

romfs:
	$(ROMFSINST) /bin/snmpd
