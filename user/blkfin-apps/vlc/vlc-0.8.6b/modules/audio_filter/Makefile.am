
# modules/audio_filter/Makefile.am automatically generated from modules/audio_filter/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = audio_filter
mods = equalizer normvol audio_format param_eq

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = channel_mixer converter resampler
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libequalizer_plugin.a libequalizer.a libnormvol_plugin.a libnormvol.a libaudio_format_plugin.a libaudio_format.a libparam_eq_plugin.a libparam_eq.a
EXTRA_LTLIBRARIES =  libequalizer_plugin.la libequalizer_builtin.la libnormvol_plugin.la libnormvol_builtin.la libaudio_format_plugin.la libaudio_format_builtin.la libparam_eq_plugin.la libparam_eq_builtin.la

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

# The equalizer plugin

libequalizer_plugin_a_SOURCES = $(SOURCES_equalizer)
libequalizer_plugin_la_SOURCES = $(SOURCES_equalizer)
libequalizer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin equalizer`
libequalizer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin equalizer`
libequalizer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin equalizer`
libequalizer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin equalizer`
libequalizer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin equalizer`
libequalizer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin equalizer`
libequalizer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin equalizer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libequalizer_plugin_la_LIBADD = $(LTLIBVLC)

libequalizer_a_SOURCES = $(SOURCES_equalizer)
libequalizer_builtin_la_SOURCES = $(SOURCES_equalizer)
libequalizer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic equalizer`
libequalizer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic equalizer`
libequalizer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic equalizer`
libequalizer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin equalizer`
libequalizer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin equalizer`
libequalizer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin equalizer`

# The normvol plugin

libnormvol_plugin_a_SOURCES = $(SOURCES_normvol)
libnormvol_plugin_la_SOURCES = $(SOURCES_normvol)
libnormvol_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin normvol`
libnormvol_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin normvol`
libnormvol_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin normvol`
libnormvol_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin normvol`
libnormvol_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin normvol`
libnormvol_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin normvol`
libnormvol_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin normvol` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libnormvol_plugin_la_LIBADD = $(LTLIBVLC)

libnormvol_a_SOURCES = $(SOURCES_normvol)
libnormvol_builtin_la_SOURCES = $(SOURCES_normvol)
libnormvol_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic normvol`
libnormvol_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic normvol`
libnormvol_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic normvol`
libnormvol_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin normvol`
libnormvol_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin normvol`
libnormvol_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin normvol`

# The audio_format plugin

libaudio_format_plugin_a_SOURCES = $(SOURCES_audio_format)
libaudio_format_plugin_la_SOURCES = $(SOURCES_audio_format)
libaudio_format_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin audio_format`
libaudio_format_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin audio_format`
libaudio_format_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin audio_format`
libaudio_format_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin audio_format`
libaudio_format_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin audio_format`
libaudio_format_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin audio_format`
libaudio_format_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin audio_format` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaudio_format_plugin_la_LIBADD = $(LTLIBVLC)

libaudio_format_a_SOURCES = $(SOURCES_audio_format)
libaudio_format_builtin_la_SOURCES = $(SOURCES_audio_format)
libaudio_format_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic audio_format`
libaudio_format_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic audio_format`
libaudio_format_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic audio_format`
libaudio_format_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin audio_format`
libaudio_format_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin audio_format`
libaudio_format_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin audio_format`

# The param_eq plugin

libparam_eq_plugin_a_SOURCES = $(SOURCES_param_eq)
libparam_eq_plugin_la_SOURCES = $(SOURCES_param_eq)
libparam_eq_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin param_eq`
libparam_eq_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin param_eq`
libparam_eq_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin param_eq`
libparam_eq_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin param_eq`
libparam_eq_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin param_eq`
libparam_eq_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin param_eq`
libparam_eq_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin param_eq` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libparam_eq_plugin_la_LIBADD = $(LTLIBVLC)

libparam_eq_a_SOURCES = $(SOURCES_param_eq)
libparam_eq_builtin_la_SOURCES = $(SOURCES_param_eq)
libparam_eq_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic param_eq`
libparam_eq_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic param_eq`
libparam_eq_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic param_eq`
libparam_eq_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin param_eq`
libparam_eq_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin param_eq`
libparam_eq_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin param_eq`

