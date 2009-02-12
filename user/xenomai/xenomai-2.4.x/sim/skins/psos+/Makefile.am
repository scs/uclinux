vpath %.c $(top_srcdir)/../ksrc/skins/psos+

CC = $(top_builddir)/gcic/gcic

override CFLAGS = -g

if CONFIG_XENO_MVM_ATOMIC_CORE
atomic_core := --no-inst -O2
endif

AM_CPPFLAGS = \
	-D__IN_XENO__ \
	--gcic-backend=$(prefix)/libexec/gcic \
	--skin-code \
	$(atomic_core) \
	-I$(srcdir)/../include \
	-I$(top_srcdir)/../include

lib_LIBRARIES = libpsos_sim.a

nodist_libpsos_sim_a_SOURCES = \
	module.c \
	asr.c \
	event.c \
	pt.c \
	queue.c \
	rn.c \
	task.c \
	tm.c \
	sem.c \
	vmctl.c

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)/tcl/psos
	$(INSTALL_DATA) $(srcdir)/*.tcl $(DESTDIR)$(pkgdatadir)/tcl/psos
	echo "auto_mkindex $(DESTDIR)$(pkgdatadir)/tcl/psos" | @TCL_SCRIPT@

uninstall-local:
	$(RM) -r $(DESTDIR)$(pkgdatadir)/tcl/psos

EXTRA_DIST = queue.tcl task.tcl vmctl.c
