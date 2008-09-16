testdir = $(exec_prefix)/share/xenomai/testsuite/irqbench

bin_PROGRAMS = irqloop

if XENO_LINUX_ARCH_I386
bin_PROGRAMS += irqbench
endif


irqloop_SOURCES = irqloop.c

irqloop_CPPFLAGS = \
	-I$(top_srcdir)/include/posix \
	$(XENO_USER_CFLAGS) \
	-I$(top_srcdir)/include

irqloop_LDFLAGS = \
	$(XENO_POSIX_WRAPPERS) \
	$(XENO_USER_LDFLAGS)

irqloop_LDADD = \
	-lpthread -lrt ../../skins/posix/libpthread_rt.la


irqbench_SOURCES = irqbench.c

irqbench_CPPFLAGS = \
	$(XENO_USER_CFLAGS) \
	-I$(top_srcdir)/include

irqbench_LDFLAGS = $(XENO_USER_LDFLAGS)


install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(testdir)
	@sed -e's,@exec_prefix\@,$(exec_prefix),g' $(srcdir)/runinfo.in > $(DESTDIR)$(testdir)/.runinfo
	@echo "\$${DESTDIR}$(exec_prefix)/bin/xeno-load \`dirname \$$0\` \$$*" > $(DESTDIR)$(testdir)/run
	@chmod +x $(DESTDIR)$(testdir)/run

uninstall-local:
	$(RM) $(DESTDIR)$(testdir)/.runinfo $(DESTDIR)$(testdir)/run

run: all
	@$(top_srcdir)/scripts/xeno-load --verbose

EXTRA_DIST = runinfo.in
