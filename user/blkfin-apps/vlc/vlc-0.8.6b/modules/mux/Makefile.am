
# modules/mux/Makefile.am automatically generated from modules/mux/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = mux
mods = mux_dummy mux_avi mux_ogg mux_mp4 mux_asf mux_wav mux_mpjpeg

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = mpeg rtp
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libmux_dummy_plugin.a libmux_dummy.a libmux_avi_plugin.a libmux_avi.a libmux_ogg_plugin.a libmux_ogg.a libmux_mp4_plugin.a libmux_mp4.a libmux_asf_plugin.a libmux_asf.a libmux_wav_plugin.a libmux_wav.a libmux_mpjpeg_plugin.a libmux_mpjpeg.a
EXTRA_LTLIBRARIES =  libmux_dummy_plugin.la libmux_dummy_builtin.la libmux_avi_plugin.la libmux_avi_builtin.la libmux_ogg_plugin.la libmux_ogg_builtin.la libmux_mp4_plugin.la libmux_mp4_builtin.la libmux_asf_plugin.la libmux_asf_builtin.la libmux_wav_plugin.la libmux_wav_builtin.la libmux_mpjpeg_plugin.la libmux_mpjpeg_builtin.la

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

# The mux_dummy plugin

libmux_dummy_plugin_a_SOURCES = $(SOURCES_mux_dummy)
libmux_dummy_plugin_la_SOURCES = $(SOURCES_mux_dummy)
libmux_dummy_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_dummy`
libmux_dummy_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_dummy`
libmux_dummy_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_dummy`
libmux_dummy_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_dummy`
libmux_dummy_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_dummy`
libmux_dummy_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_dummy`
libmux_dummy_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_dummy` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_dummy_plugin_la_LIBADD = $(LTLIBVLC)

libmux_dummy_a_SOURCES = $(SOURCES_mux_dummy)
libmux_dummy_builtin_la_SOURCES = $(SOURCES_mux_dummy)
libmux_dummy_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_dummy`
libmux_dummy_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_dummy`
libmux_dummy_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_dummy`
libmux_dummy_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_dummy`
libmux_dummy_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_dummy`
libmux_dummy_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_dummy`

# The mux_avi plugin

libmux_avi_plugin_a_SOURCES = $(SOURCES_mux_avi)
libmux_avi_plugin_la_SOURCES = $(SOURCES_mux_avi)
libmux_avi_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_avi`
libmux_avi_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_avi`
libmux_avi_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_avi`
libmux_avi_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_avi`
libmux_avi_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_avi`
libmux_avi_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_avi`
libmux_avi_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_avi` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_avi_plugin_la_LIBADD = $(LTLIBVLC)

libmux_avi_a_SOURCES = $(SOURCES_mux_avi)
libmux_avi_builtin_la_SOURCES = $(SOURCES_mux_avi)
libmux_avi_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_avi`
libmux_avi_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_avi`
libmux_avi_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_avi`
libmux_avi_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_avi`
libmux_avi_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_avi`
libmux_avi_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_avi`

# The mux_ogg plugin

libmux_ogg_plugin_a_SOURCES = $(SOURCES_mux_ogg)
libmux_ogg_plugin_la_SOURCES = $(SOURCES_mux_ogg)
libmux_ogg_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_ogg`
libmux_ogg_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_ogg`
libmux_ogg_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_ogg`
libmux_ogg_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_ogg`
libmux_ogg_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_ogg`
libmux_ogg_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_ogg`
libmux_ogg_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_ogg` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_ogg_plugin_la_LIBADD = $(LTLIBVLC)

libmux_ogg_a_SOURCES = $(SOURCES_mux_ogg)
libmux_ogg_builtin_la_SOURCES = $(SOURCES_mux_ogg)
libmux_ogg_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_ogg`
libmux_ogg_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_ogg`
libmux_ogg_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_ogg`
libmux_ogg_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_ogg`
libmux_ogg_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_ogg`
libmux_ogg_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_ogg`

# The mux_mp4 plugin

libmux_mp4_plugin_a_SOURCES = $(SOURCES_mux_mp4)
libmux_mp4_plugin_la_SOURCES = $(SOURCES_mux_mp4)
libmux_mp4_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_mp4`
libmux_mp4_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_mp4`
libmux_mp4_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_mp4`
libmux_mp4_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_mp4`
libmux_mp4_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_mp4`
libmux_mp4_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_mp4`
libmux_mp4_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_mp4` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_mp4_plugin_la_LIBADD = $(LTLIBVLC)

libmux_mp4_a_SOURCES = $(SOURCES_mux_mp4)
libmux_mp4_builtin_la_SOURCES = $(SOURCES_mux_mp4)
libmux_mp4_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_mp4`
libmux_mp4_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_mp4`
libmux_mp4_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_mp4`
libmux_mp4_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_mp4`
libmux_mp4_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_mp4`
libmux_mp4_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_mp4`

# The mux_asf plugin

libmux_asf_plugin_a_SOURCES = $(SOURCES_mux_asf)
libmux_asf_plugin_la_SOURCES = $(SOURCES_mux_asf)
libmux_asf_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_asf`
libmux_asf_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_asf`
libmux_asf_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_asf`
libmux_asf_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_asf`
libmux_asf_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_asf`
libmux_asf_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_asf`
libmux_asf_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_asf` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_asf_plugin_la_LIBADD = $(LTLIBVLC)

libmux_asf_a_SOURCES = $(SOURCES_mux_asf)
libmux_asf_builtin_la_SOURCES = $(SOURCES_mux_asf)
libmux_asf_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_asf`
libmux_asf_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_asf`
libmux_asf_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_asf`
libmux_asf_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_asf`
libmux_asf_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_asf`
libmux_asf_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_asf`

# The mux_wav plugin

libmux_wav_plugin_a_SOURCES = $(SOURCES_mux_wav)
libmux_wav_plugin_la_SOURCES = $(SOURCES_mux_wav)
libmux_wav_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_wav`
libmux_wav_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_wav`
libmux_wav_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_wav`
libmux_wav_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_wav`
libmux_wav_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_wav`
libmux_wav_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_wav`
libmux_wav_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_wav` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_wav_plugin_la_LIBADD = $(LTLIBVLC)

libmux_wav_a_SOURCES = $(SOURCES_mux_wav)
libmux_wav_builtin_la_SOURCES = $(SOURCES_mux_wav)
libmux_wav_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_wav`
libmux_wav_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_wav`
libmux_wav_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_wav`
libmux_wav_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_wav`
libmux_wav_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_wav`
libmux_wav_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_wav`

# The mux_mpjpeg plugin

libmux_mpjpeg_plugin_a_SOURCES = $(SOURCES_mux_mpjpeg)
libmux_mpjpeg_plugin_la_SOURCES = $(SOURCES_mux_mpjpeg)
libmux_mpjpeg_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_mpjpeg`
libmux_mpjpeg_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_mpjpeg`
libmux_mpjpeg_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_mpjpeg`
libmux_mpjpeg_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mux_mpjpeg`
libmux_mpjpeg_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mux_mpjpeg`
libmux_mpjpeg_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mux_mpjpeg`
libmux_mpjpeg_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mux_mpjpeg` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmux_mpjpeg_plugin_la_LIBADD = $(LTLIBVLC)

libmux_mpjpeg_a_SOURCES = $(SOURCES_mux_mpjpeg)
libmux_mpjpeg_builtin_la_SOURCES = $(SOURCES_mux_mpjpeg)
libmux_mpjpeg_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mux_mpjpeg`
libmux_mpjpeg_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mux_mpjpeg`
libmux_mpjpeg_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mux_mpjpeg`
libmux_mpjpeg_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mux_mpjpeg`
libmux_mpjpeg_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mux_mpjpeg`
libmux_mpjpeg_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mux_mpjpeg`

