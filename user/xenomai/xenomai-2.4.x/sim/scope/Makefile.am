bin_PROGRAMS = xenoscope

xenoscope_SOURCES = \
	bridge.cc \
	debugger.cc \
	drawable.cc \
	gdbhelper.cc \
	inspector.cc \
	main.cc \
	monitor.cc \
	plotter.cc \
	postscript.cc \
	workspace.cc \
	bridge.h \
	debugger.h \
	drawable.h \
	gdbhelper.h \
	inspector.h \
	monitor.h \
	plotter.h \
	postscript.h \
	workspace.h

xenoscope_CPPFLAGS = \
	 $(TCLWRAP_SWITCH) \
	$(X_CFLAGS) \
	@MVM_CXXFLAGS@ \
	-DTIX_TCL_LIB="\"@TIX_TCL_LIB@\"" \
	-D__XENO_SIM__ \
	-I$(srcdir)/.. \
	@TCL_INCLUDES@ \
	-DUSE_COMPAT_CONST

xenoscope_LDFLAGS = \
	../vmutils/libmvmutils.la \
	@TIX_LIB_SPEC@ \
	@TK_LIB_SPEC@ \
	@TCL_LIB_SPEC@ \
	$(X_LIBS) \
	$(X_PRE_LIBS) $(X11_LIBS) $(X_EXTRA_LIBS) \
	@MVM_LDADD@ \
	-lpng \
	-lz \
	-lm

TCL_FILES = \
	tcl/breakpoints.tcl \
	tcl/datawatch.tcl \
	tcl/debugger.tcl \
	tcl/examiner.tcl \
	tcl/gdb.tcl \
	tcl/inspector.tcl \
	tcl/main.tcl \
	tcl/monitor.tcl \
	tcl/plotter.tcl \
	tcl/session.tcl \
	tcl/timers.tcl \
	tcl/tooltips.tcl \
	tcl/trace.tcl \
	tcl/utils.tcl \
	tcl/watchpoints.tcl \
	tcl/workspace.tcl

if CONFIG_XENO_MVM_TCLWRAP
TCLWRAP_SWITCH = -DTCLWRAP
BUILT_SOURCES =	scope.tcc
TCL_DEPS = $(TCL_FILES:%=$(srcdir)/%)
CLEANFILES = scope.tcc

GNUmakefile: scope.tcc

scope.tcc: $(TCL_DEPS)
	test -x ../vmutils/tclpack && \
	../vmutils/tclpack $(TCL_DEPS) > $@ || true

install-tcl:
else
TCLSOFTDIR = `cd $(srcdir)/tcl && pwd`
TCLWRAP_SWITCH = -DTCLSOFTDIR=\"$(TCLSOFTDIR)\"

install-tcl:
	echo "auto_mkindex $(srcdir)/tcl" | @TCL_SCRIPT@
endif

pkgdata_DATA = plotter.ps

install-data-local: install-tcl
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)/icons
	cd $(srcdir)/icons ; \
	for i in *.png ; do \
	$(INSTALL_DATA) $$i $(DESTDIR)$(pkgdatadir)/icons/$$i ; \
	done
	$(mkinstalldirs) $(DESTDIR)$(pkgdatadir)/images
	cd $(srcdir)/images ; \
	for i in *.png ; do \
	$(INSTALL_DATA) $$i $(DESTDIR)$(pkgdatadir)/images/$$i ; \
	done

uninstall-local:
	cd $(srcdir)/icons ; \
	for i in *.png ; do \
	$(RM) $(DESTDIR)$(pkgdatadir)/icons/$$i ; \
	done
	cd $(srcdir)/images ; \
	for i in *.png ; do \
	$(RM) $(DESTDIR)$(pkgdatadir)/images/$$i ; \
	done

EXTRA_DIST = $(TCL_FILES) $(pkgdata_DATA) tcl/tclIndex icons images

dist-hook:
	find $(distdir)/icons $(distdir)/images -name .svn -depth -exec rm -fr \{\} \;
