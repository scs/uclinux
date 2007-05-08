
# modules/audio_filter/channel_mixer/Makefile.am automatically generated from modules/audio_filter/channel_mixer/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = audio_filter
mods = trivial_channel_mixer simple_channel_mixer headphone_channel_mixer dolby_surround_decoder

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libtrivial_channel_mixer_plugin.a libtrivial_channel_mixer.a libsimple_channel_mixer_plugin.a libsimple_channel_mixer.a libheadphone_channel_mixer_plugin.a libheadphone_channel_mixer.a libdolby_surround_decoder_plugin.a libdolby_surround_decoder.a
EXTRA_LTLIBRARIES =  libtrivial_channel_mixer_plugin.la libtrivial_channel_mixer_builtin.la libsimple_channel_mixer_plugin.la libsimple_channel_mixer_builtin.la libheadphone_channel_mixer_plugin.la libheadphone_channel_mixer_builtin.la libdolby_surround_decoder_plugin.la libdolby_surround_decoder_builtin.la

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

# The trivial_channel_mixer plugin

libtrivial_channel_mixer_plugin_a_SOURCES = $(SOURCES_trivial_channel_mixer)
libtrivial_channel_mixer_plugin_la_SOURCES = $(SOURCES_trivial_channel_mixer)
libtrivial_channel_mixer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin trivial_channel_mixer`
libtrivial_channel_mixer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin trivial_channel_mixer`
libtrivial_channel_mixer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin trivial_channel_mixer`
libtrivial_channel_mixer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin trivial_channel_mixer`
libtrivial_channel_mixer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin trivial_channel_mixer`
libtrivial_channel_mixer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin trivial_channel_mixer`
libtrivial_channel_mixer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin trivial_channel_mixer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtrivial_channel_mixer_plugin_la_LIBADD = $(LTLIBVLC)

libtrivial_channel_mixer_a_SOURCES = $(SOURCES_trivial_channel_mixer)
libtrivial_channel_mixer_builtin_la_SOURCES = $(SOURCES_trivial_channel_mixer)
libtrivial_channel_mixer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic trivial_channel_mixer`
libtrivial_channel_mixer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic trivial_channel_mixer`
libtrivial_channel_mixer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic trivial_channel_mixer`
libtrivial_channel_mixer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin trivial_channel_mixer`
libtrivial_channel_mixer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin trivial_channel_mixer`
libtrivial_channel_mixer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin trivial_channel_mixer`

# The simple_channel_mixer plugin

libsimple_channel_mixer_plugin_a_SOURCES = $(SOURCES_simple_channel_mixer)
libsimple_channel_mixer_plugin_la_SOURCES = $(SOURCES_simple_channel_mixer)
libsimple_channel_mixer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin simple_channel_mixer`
libsimple_channel_mixer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin simple_channel_mixer`
libsimple_channel_mixer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin simple_channel_mixer`
libsimple_channel_mixer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin simple_channel_mixer`
libsimple_channel_mixer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin simple_channel_mixer`
libsimple_channel_mixer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin simple_channel_mixer`
libsimple_channel_mixer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin simple_channel_mixer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsimple_channel_mixer_plugin_la_LIBADD = $(LTLIBVLC)

libsimple_channel_mixer_a_SOURCES = $(SOURCES_simple_channel_mixer)
libsimple_channel_mixer_builtin_la_SOURCES = $(SOURCES_simple_channel_mixer)
libsimple_channel_mixer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic simple_channel_mixer`
libsimple_channel_mixer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic simple_channel_mixer`
libsimple_channel_mixer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic simple_channel_mixer`
libsimple_channel_mixer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin simple_channel_mixer`
libsimple_channel_mixer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin simple_channel_mixer`
libsimple_channel_mixer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin simple_channel_mixer`

# The headphone_channel_mixer plugin

libheadphone_channel_mixer_plugin_a_SOURCES = $(SOURCES_headphone_channel_mixer)
libheadphone_channel_mixer_plugin_la_SOURCES = $(SOURCES_headphone_channel_mixer)
libheadphone_channel_mixer_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin headphone_channel_mixer`
libheadphone_channel_mixer_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin headphone_channel_mixer`
libheadphone_channel_mixer_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin headphone_channel_mixer`
libheadphone_channel_mixer_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin headphone_channel_mixer`
libheadphone_channel_mixer_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin headphone_channel_mixer`
libheadphone_channel_mixer_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin headphone_channel_mixer`
libheadphone_channel_mixer_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin headphone_channel_mixer` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libheadphone_channel_mixer_plugin_la_LIBADD = $(LTLIBVLC)

libheadphone_channel_mixer_a_SOURCES = $(SOURCES_headphone_channel_mixer)
libheadphone_channel_mixer_builtin_la_SOURCES = $(SOURCES_headphone_channel_mixer)
libheadphone_channel_mixer_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic headphone_channel_mixer`
libheadphone_channel_mixer_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic headphone_channel_mixer`
libheadphone_channel_mixer_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic headphone_channel_mixer`
libheadphone_channel_mixer_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin headphone_channel_mixer`
libheadphone_channel_mixer_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin headphone_channel_mixer`
libheadphone_channel_mixer_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin headphone_channel_mixer`

# The dolby_surround_decoder plugin

libdolby_surround_decoder_plugin_a_SOURCES = $(SOURCES_dolby_surround_decoder)
libdolby_surround_decoder_plugin_la_SOURCES = $(SOURCES_dolby_surround_decoder)
libdolby_surround_decoder_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dolby_surround_decoder`
libdolby_surround_decoder_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dolby_surround_decoder`
libdolby_surround_decoder_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dolby_surround_decoder`
libdolby_surround_decoder_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dolby_surround_decoder`
libdolby_surround_decoder_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dolby_surround_decoder`
libdolby_surround_decoder_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dolby_surround_decoder`
libdolby_surround_decoder_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dolby_surround_decoder` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdolby_surround_decoder_plugin_la_LIBADD = $(LTLIBVLC)

libdolby_surround_decoder_a_SOURCES = $(SOURCES_dolby_surround_decoder)
libdolby_surround_decoder_builtin_la_SOURCES = $(SOURCES_dolby_surround_decoder)
libdolby_surround_decoder_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dolby_surround_decoder`
libdolby_surround_decoder_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dolby_surround_decoder`
libdolby_surround_decoder_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dolby_surround_decoder`
libdolby_surround_decoder_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dolby_surround_decoder`
libdolby_surround_decoder_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dolby_surround_decoder`
libdolby_surround_decoder_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dolby_surround_decoder`

