
# modules/visualization/Makefile.am automatically generated from modules/visualization/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = visualization
mods = goom xosd

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = visual galaktos
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libgoom_plugin.a libgoom.a libxosd_plugin.a libxosd.a
EXTRA_LTLIBRARIES =  libgoom_plugin.la libgoom_builtin.la libxosd_plugin.la libxosd_builtin.la

include Modules.am

LTLIBVLC = $(top_builddir)/src/libvlc.la

if BUILD_SHARED
LIBVLC = $(top_builddir)/src/libvlc$(LIBEXT)
LIBADD = $(LIBVLC)
endif

all: all-modules

# Find out which modules were enabled and tell make to build them
all-modules:
if USE_LIBTOOL
	@set fnord $$MAKEFLAGS; amf=$$2; targets=`\
	if test "$(plugin)" != "no"; then z=$$($(VLC_CONFIG) --list plugin); for mod in $(mods); do case "$$z " in *\ $${mod}\ *) echo lib$${mod}_plugin.la;; esac; done; fi; \
	if test "$(builtin)" != "no"; then z=$$($(VLC_CONFIG) --list builtin); for mod in $(mods); do case "$$z " in *\ $${mod}\ *) echo lib$${mod}_builtin.la;; esac; done; fi; \
	`; case "$$targets" in *lib*) $(MAKE) $(AM_MAKEFLAGS) $$targets || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; ;; esac; \
	test -z "$$fail"
else
	@set fnord $$MAKEFLAGS; amf=$$2; targets=`\
	if test "$(plugin)" != "no"; then z=$$($(VLC_CONFIG) --list plugin); for mod in $(mods); do case "$$z " in *\ $${mod}\ *) echo lib$${mod}_plugin$(LIBEXT);; esac; done; fi; \
	if test "$(builtin)" != "no"; then z=$$($(VLC_CONFIG) --list builtin); for mod in $(mods); do case "$$z " in *\ $${mod}\ *) echo lib$${mod}.a;; esac; done; fi; \
	`; case "$$targets" in *lib*) $(MAKE) $(AM_MAKEFLAGS) $$targets || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; ;; esac; \
	test -z "$$fail"
endif

# Build a plugin with the adequate linker and linker's flags
_plugin.a_plugin$(LIBEXT):
	@mod="$*" ; mod=$${mod#lib} ; 	ldfl="`$(VLC_CONFIG) --libs plugin $$mod` $(LIBADD) -u $(SYMPREF)$(VLC_ENTRY)" ; 	case `$(VLC_CONFIG) --linkage $$mod` in \
	  c++)  ld="$(CXXLINK)" ;; 	  objc) ld="$(OBJCLINK)" ;; 	  c|*)  ld="$(LINK)" ;; 	esac ; 	echo $$ld $< $$ldfl ; 	$$ld $< $$ldfl
#ifneq (,$(findstring cygwin,$(host)))
#	mv -f "$@.exe" "$@"
#endif
	@if test -f "$@.exe"; then mv -f "$@.exe" "$@"; fi

if MAINTAINER_MODE
$(srcdir)/Makefile.am: $(srcdir)/Modules.am $(top_srcdir)/bootstrap
	cd $(top_srcdir) && $(SHELL) ./bootstrap
endif

mostlyclean-local:
if USE_LIBTOOL
	-rm -f *.la
else
	-rm -f *.a *$(LIBEXT)
endif

clean-local: $(clean_modules)

### automake creates libvlcdir after running install-*-local
### so we have to create it ourselves first
install-exec-local: all-modules
if USE_LIBTOOL
	@if test -z "$(libvlc_LTLIBRARIES)"; then 	  z=$$($(VLC_CONFIG) --list plugin); 	  m=`for mod in $(mods); do case "$$z " in *\ $${mod}\ *) echo -n " lib$${mod}_plugin.la" ;; esac; done` ; 	  test -z "$$m" ||   	    $(MAKE) $(AM_MAKEFLAGS) libvlc_LTLIBRARIES="$$m" install-libvlcLTLIBRARIES || exit $$? ; 	fi
else
	mkdir -p -- "$(DESTDIR)$(libvlcdir)"
	@z=$$($(VLC_CONFIG) --list plugin); 	for mod in $(mods); do 	  case "$$z " 	    in *\ $${mod}\ *) 	      echo $(INSTALL_PROGRAM) "lib$${mod}_plugin$(LIBEXT)" "$(DESTDIR)$(libvlcdir)/" ; 	      $(INSTALL_PROGRAM) "lib$${mod}_plugin$(LIBEXT)" "$(DESTDIR)$(libvlcdir)/" || exit $$?; 	      ;; 	  esac; 	done
	@z=$$($(VLC_CONFIG) --list builtin); 	for mod in $(mods); do 	  case "$$z " 	    in *\ $${mod}\ *) 	      echo $(INSTALL_DATA) "lib$${mod}.a" "$(DESTDIR)$(libdir)/vlc/" ; 	      $(INSTALL_DATA) "lib$${mod}.a" "$(DESTDIR)$(libdir)/vlc/" || exit $$?; 	      ;; 	  esac; 	done
endif

uninstall-local:
if USE_LIBTOOL
	@if test -z "$(libvlc_LTLIBRARIES)"; then 	  z=$$($(VLC_CONFIG) --list plugin); 	  m=`for mod in $(mods); do case "$$z " in *\ $${mod}\ *) echo -n " lib$${mod}_plugin.la" ;; esac; done` ; 	  test -z "$$m" || 	    $(MAKE) $(AM_MAKEFLAGS) libvlc_LTLIBRARIES="$$m" uninstall-libvlcLTLIBRARIES || exit $$?; 	fi
else
	@z=$$($(VLC_CONFIG) --list plugin); 	for mod in $(mods); do 	  case "$$z " 	    in *\ $${mod}\ *) 	      echo rm -f "$(DESTDIR)$(libvlcdir)/lib$${mod}_plugin$(LIBEXT)" ; 	      rm -f "$(DESTDIR)$(libvlcdir)/lib$${mod}_plugin$(LIBEXT)" || true; 	      ;; 	  esac; 	done
	@z=$$($(VLC_CONFIG) --list builtin); 	for mod in $(mods); do 	  case "$$z " 	    in *\ $${mod}\ *) 	      echo rm -f "$(DESTDIR)$(libdir)/vlc/lib$${mod}.a" ; 	      rm -f "$(DESTDIR)$(libdir)/vlc/lib$${mod}.a" || true; 	      ;; 	  esac; 	done
endif

# The goom plugin

libgoom_plugin_a_SOURCES = $(SOURCES_goom)
libgoom_plugin_la_SOURCES = $(SOURCES_goom)
libgoom_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin goom`
libgoom_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin goom`
libgoom_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin goom`
libgoom_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin goom`
libgoom_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin goom`
libgoom_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin goom`
libgoom_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin goom` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libgoom_plugin_la_LIBADD = $(LTLIBVLC)

libgoom_a_SOURCES = $(SOURCES_goom)
libgoom_builtin_la_SOURCES = $(SOURCES_goom)
libgoom_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic goom`
libgoom_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic goom`
libgoom_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic goom`
libgoom_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin goom`
libgoom_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin goom`
libgoom_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin goom`

# The xosd plugin

libxosd_plugin_a_SOURCES = $(SOURCES_xosd)
libxosd_plugin_la_SOURCES = $(SOURCES_xosd)
libxosd_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin xosd`
libxosd_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin xosd`
libxosd_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin xosd`
libxosd_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin xosd`
libxosd_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin xosd`
libxosd_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin xosd`
libxosd_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin xosd` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libxosd_plugin_la_LIBADD = $(LTLIBVLC)

libxosd_a_SOURCES = $(SOURCES_xosd)
libxosd_builtin_la_SOURCES = $(SOURCES_xosd)
libxosd_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic xosd`
libxosd_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic xosd`
libxosd_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic xosd`
libxosd_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin xosd`
libxosd_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin xosd`
libxosd_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin xosd`

