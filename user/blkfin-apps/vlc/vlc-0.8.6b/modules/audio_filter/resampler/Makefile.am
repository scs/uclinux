
# modules/audio_filter/resampler/Makefile.am automatically generated from modules/audio_filter/resampler/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = audio_filter
mods = trivial_resampler ugly_resampler linear_resampler bandlimited_resampler

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libtrivial_resampler_plugin.a libtrivial_resampler.a libugly_resampler_plugin.a libugly_resampler.a liblinear_resampler_plugin.a liblinear_resampler.a libbandlimited_resampler_plugin.a libbandlimited_resampler.a
EXTRA_LTLIBRARIES =  libtrivial_resampler_plugin.la libtrivial_resampler_builtin.la libugly_resampler_plugin.la libugly_resampler_builtin.la liblinear_resampler_plugin.la liblinear_resampler_builtin.la libbandlimited_resampler_plugin.la libbandlimited_resampler_builtin.la

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

# The trivial_resampler plugin

libtrivial_resampler_plugin_a_SOURCES = $(SOURCES_trivial_resampler)
libtrivial_resampler_plugin_la_SOURCES = $(SOURCES_trivial_resampler)
libtrivial_resampler_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin trivial_resampler`
libtrivial_resampler_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin trivial_resampler`
libtrivial_resampler_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin trivial_resampler`
libtrivial_resampler_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin trivial_resampler`
libtrivial_resampler_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin trivial_resampler`
libtrivial_resampler_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin trivial_resampler`
libtrivial_resampler_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin trivial_resampler` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtrivial_resampler_plugin_la_LIBADD = $(LTLIBVLC)

libtrivial_resampler_a_SOURCES = $(SOURCES_trivial_resampler)
libtrivial_resampler_builtin_la_SOURCES = $(SOURCES_trivial_resampler)
libtrivial_resampler_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic trivial_resampler`
libtrivial_resampler_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic trivial_resampler`
libtrivial_resampler_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic trivial_resampler`
libtrivial_resampler_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin trivial_resampler`
libtrivial_resampler_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin trivial_resampler`
libtrivial_resampler_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin trivial_resampler`

# The ugly_resampler plugin

libugly_resampler_plugin_a_SOURCES = $(SOURCES_ugly_resampler)
libugly_resampler_plugin_la_SOURCES = $(SOURCES_ugly_resampler)
libugly_resampler_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ugly_resampler`
libugly_resampler_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ugly_resampler`
libugly_resampler_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ugly_resampler`
libugly_resampler_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ugly_resampler`
libugly_resampler_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ugly_resampler`
libugly_resampler_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ugly_resampler`
libugly_resampler_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ugly_resampler` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libugly_resampler_plugin_la_LIBADD = $(LTLIBVLC)

libugly_resampler_a_SOURCES = $(SOURCES_ugly_resampler)
libugly_resampler_builtin_la_SOURCES = $(SOURCES_ugly_resampler)
libugly_resampler_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ugly_resampler`
libugly_resampler_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ugly_resampler`
libugly_resampler_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ugly_resampler`
libugly_resampler_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ugly_resampler`
libugly_resampler_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ugly_resampler`
libugly_resampler_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ugly_resampler`

# The linear_resampler plugin

liblinear_resampler_plugin_a_SOURCES = $(SOURCES_linear_resampler)
liblinear_resampler_plugin_la_SOURCES = $(SOURCES_linear_resampler)
liblinear_resampler_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin linear_resampler`
liblinear_resampler_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin linear_resampler`
liblinear_resampler_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin linear_resampler`
liblinear_resampler_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin linear_resampler`
liblinear_resampler_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin linear_resampler`
liblinear_resampler_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin linear_resampler`
liblinear_resampler_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin linear_resampler` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liblinear_resampler_plugin_la_LIBADD = $(LTLIBVLC)

liblinear_resampler_a_SOURCES = $(SOURCES_linear_resampler)
liblinear_resampler_builtin_la_SOURCES = $(SOURCES_linear_resampler)
liblinear_resampler_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic linear_resampler`
liblinear_resampler_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic linear_resampler`
liblinear_resampler_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic linear_resampler`
liblinear_resampler_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin linear_resampler`
liblinear_resampler_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin linear_resampler`
liblinear_resampler_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin linear_resampler`

# The bandlimited_resampler plugin

libbandlimited_resampler_plugin_a_SOURCES = $(SOURCES_bandlimited_resampler)
libbandlimited_resampler_plugin_la_SOURCES = $(SOURCES_bandlimited_resampler)
libbandlimited_resampler_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin bandlimited_resampler`
libbandlimited_resampler_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin bandlimited_resampler`
libbandlimited_resampler_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin bandlimited_resampler`
libbandlimited_resampler_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin bandlimited_resampler`
libbandlimited_resampler_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin bandlimited_resampler`
libbandlimited_resampler_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin bandlimited_resampler`
libbandlimited_resampler_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin bandlimited_resampler` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libbandlimited_resampler_plugin_la_LIBADD = $(LTLIBVLC)

libbandlimited_resampler_a_SOURCES = $(SOURCES_bandlimited_resampler)
libbandlimited_resampler_builtin_la_SOURCES = $(SOURCES_bandlimited_resampler)
libbandlimited_resampler_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic bandlimited_resampler`
libbandlimited_resampler_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic bandlimited_resampler`
libbandlimited_resampler_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic bandlimited_resampler`
libbandlimited_resampler_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin bandlimited_resampler`
libbandlimited_resampler_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin bandlimited_resampler`
libbandlimited_resampler_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin bandlimited_resampler`

