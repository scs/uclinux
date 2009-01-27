# $Id: Makefile.am,v 1.10 2007/03/23 15:32:54 asuraparaju Exp $
#

TESTSUITE_AT = testsuite.at colourbars.at unittests.at samples.at
TESTSUITE = $(srcdir)/testsuite

EXTRA_DIST = $(TESTSUITE_AT) testsuite package.m4 colourbars_420.yuv create_dirac_testfile.pl

DISTCLEANFILES = atconfig $(check_SCRIPTS)

CLEANFILES = *.imt *enc.drc *enc.hdr *enc.yuv *dec.yuv *dec.hdr *instr.yuv *instr.hdr

MAINTAINERCLEANFILES = Makefile.in $(TESTSUITE)

# scripts needed only when running make check
check_SCRIPTS = at_wrap

# scripts that have to be instlalled
bin_SCRIPTS =  create_dirac_testfile.pl

$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	{					\
	  echo '# Signature of the current package.'; \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])'; \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])'; \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])'; \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])'; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$(srcdir)/package.m4

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): package.m4 $(TESTSUITE_AT)
	$(AUTOTEST) -I $(srcdir) testsuite.at -o $@.tmp
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && ./config.status tests/$@

clean-local:
	if test -f $(TESTSUITE); then \
		$(SHELL) $(TESTSUITE) --clean; \
	fi

check-local: atconfig $(TESTSUITE)
	$(SHELL) $(TESTSUITE);

check-valgrind: check-local
	env AT_EXEC_OPTS='valgrind -q --tool=memcheck --leak-check=yes' $(SHELL) $(TESTSUITE);

installcheck-local:
	if test -f $(TESTSUITE); then \
		$(SHELL) $(TESTSUITE) AUTOTEST_PATH=$(exec_prefix)/bin; \
	fi

valgrind-check: atconfig $(TESTSUITE)
	$(SHELL) $(TESTSUITE) AT_EXEC_OPTS="$(VALGRIND) -q --error-limit=no --num-callers=50"
