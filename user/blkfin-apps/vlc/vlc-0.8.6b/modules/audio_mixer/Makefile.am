
# modules/audio_mixer/Makefile.am automatically generated from modules/audio_mixer/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = audio_mixer
mods = trivial_mixer float32_mixer spdif_mixer

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libtrivial_mixer_plugin.a libtrivial_mixer.a libfloat32_mixer_plugin.a libfloat32_mixer.a libspdif_mixer_plugin.a libspdif_mixer.a
EXTRA_LTLIBRARIES =  libtrivial_mixer_plugin.la libtrivial_mixer_builtin.la libfloat32_mixer_plugin.la libfloat32_mixer_builtin.la libspdif_mixer_plugin.la libspdif_mixer_builtin.la

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

# The trivial_mixer plugin

libtrivial_mixer_plugin_a_SOURCES = $(SOURCES_trivial_mixer)
libtrivial_mixer_plugin_la_SOURCES = $(SOURCES_trivial_mixer)
libtrivial_mixer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin trivial_mixer`
libtrivial_mixer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin trivial_mixer`
libtrivial_mixer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin trivial_mixer`
libtrivial_mixer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin trivial_mixer`
libtrivial_mixer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin trivial_mixer`
libtrivial_mixer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin trivial_mixer`
libtrivial_mixer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin trivial_mixer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtrivial_mixer_plugin_la_LIBADD = $(LTLIBVLC)

libtrivial_mixer_a_SOURCES = $(SOURCES_trivial_mixer)
libtrivial_mixer_builtin_la_SOURCES = $(SOURCES_trivial_mixer)
libtrivial_mixer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic trivial_mixer`
libtrivial_mixer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic trivial_mixer`
libtrivial_mixer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic trivial_mixer`
libtrivial_mixer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin trivial_mixer`
libtrivial_mixer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin trivial_mixer`
libtrivial_mixer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin trivial_mixer`

# The float32_mixer plugin

libfloat32_mixer_plugin_a_SOURCES = $(SOURCES_float32_mixer)
libfloat32_mixer_plugin_la_SOURCES = $(SOURCES_float32_mixer)
libfloat32_mixer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin float32_mixer`
libfloat32_mixer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin float32_mixer`
libfloat32_mixer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin float32_mixer`
libfloat32_mixer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin float32_mixer`
libfloat32_mixer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin float32_mixer`
libfloat32_mixer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin float32_mixer`
libfloat32_mixer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin float32_mixer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libfloat32_mixer_plugin_la_LIBADD = $(LTLIBVLC)

libfloat32_mixer_a_SOURCES = $(SOURCES_float32_mixer)
libfloat32_mixer_builtin_la_SOURCES = $(SOURCES_float32_mixer)
libfloat32_mixer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic float32_mixer`
libfloat32_mixer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic float32_mixer`
libfloat32_mixer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic float32_mixer`
libfloat32_mixer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin float32_mixer`
libfloat32_mixer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin float32_mixer`
libfloat32_mixer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin float32_mixer`

# The spdif_mixer plugin

libspdif_mixer_plugin_a_SOURCES = $(SOURCES_spdif_mixer)
libspdif_mixer_plugin_la_SOURCES = $(SOURCES_spdif_mixer)
libspdif_mixer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin spdif_mixer`
libspdif_mixer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin spdif_mixer`
libspdif_mixer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin spdif_mixer`
libspdif_mixer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin spdif_mixer`
libspdif_mixer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin spdif_mixer`
libspdif_mixer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin spdif_mixer`
libspdif_mixer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin spdif_mixer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libspdif_mixer_plugin_la_LIBADD = $(LTLIBVLC)

libspdif_mixer_a_SOURCES = $(SOURCES_spdif_mixer)
libspdif_mixer_builtin_la_SOURCES = $(SOURCES_spdif_mixer)
libspdif_mixer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic spdif_mixer`
libspdif_mixer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic spdif_mixer`
libspdif_mixer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic spdif_mixer`
libspdif_mixer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin spdif_mixer`
libspdif_mixer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin spdif_mixer`
libspdif_mixer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin spdif_mixer`

