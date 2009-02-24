testdir = $(exec_prefix)/share/xenomai/testsuite/switchtest

bin_PROGRAMS = switchtest

switchtest_SOURCES = switchtest.c

switchtest_CPPFLAGS = -I$(top_srcdir)/include/posix $(XENO_USER_CFLAGS) -g -I$(top_srcdir)/include

switchtest_LDFLAGS =  $(XENO_POSIX_WRAPPERS) $(XENO_USER_LDFLAGS)

switchtest_LDADD = \
	-lpthread -lrt ../../skins/posix/libpthread_rt.la

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(testdir)
	@sed -e's,@exec_prefix\@,$(exec_prefix),g' $(srcdir)/runinfo.in > $(DESTDIR)$(testdir)/.runinfo
	@echo "#!/bin/sh" > $(DESTDIR)$(testdir)/run
	@echo "\$${DESTDIR}$(exec_prefix)/bin/xeno-load \`dirname \$$0\` \$$*" >> $(DESTDIR)$(testdir)/run
	@chmod +x $(DESTDIR)$(testdir)/run

uninstall-local:
	$(RM) $(DESTDIR)$(testdir)/.runinfo $(DESTDIR)$(testdir)/run

run: all
	@$(top_srcdir)/scripts/xeno-load --verbose

EXTRA_DIST = runinfo.in
