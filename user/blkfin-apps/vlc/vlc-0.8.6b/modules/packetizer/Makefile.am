
# modules/packetizer/Makefile.am automatically generated from modules/packetizer/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = packetizer
mods = packetizer_copy packetizer_mpegvideo packetizer_mpeg4video packetizer_mpeg4audio packetizer_h264

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libpacketizer_copy_plugin.a libpacketizer_copy.a libpacketizer_mpegvideo_plugin.a libpacketizer_mpegvideo.a libpacketizer_mpeg4video_plugin.a libpacketizer_mpeg4video.a libpacketizer_mpeg4audio_plugin.a libpacketizer_mpeg4audio.a libpacketizer_h264_plugin.a libpacketizer_h264.a
EXTRA_LTLIBRARIES =  libpacketizer_copy_plugin.la libpacketizer_copy_builtin.la libpacketizer_mpegvideo_plugin.la libpacketizer_mpegvideo_builtin.la libpacketizer_mpeg4video_plugin.la libpacketizer_mpeg4video_builtin.la libpacketizer_mpeg4audio_plugin.la libpacketizer_mpeg4audio_builtin.la libpacketizer_h264_plugin.la libpacketizer_h264_builtin.la

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

# The packetizer_copy plugin

libpacketizer_copy_plugin_a_SOURCES = $(SOURCES_packetizer_copy)
libpacketizer_copy_plugin_la_SOURCES = $(SOURCES_packetizer_copy)
libpacketizer_copy_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_copy`
libpacketizer_copy_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_copy`
libpacketizer_copy_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_copy`
libpacketizer_copy_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_copy`
libpacketizer_copy_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_copy`
libpacketizer_copy_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_copy`
libpacketizer_copy_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin packetizer_copy` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpacketizer_copy_plugin_la_LIBADD = $(LTLIBVLC)

libpacketizer_copy_a_SOURCES = $(SOURCES_packetizer_copy)
libpacketizer_copy_builtin_la_SOURCES = $(SOURCES_packetizer_copy)
libpacketizer_copy_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic packetizer_copy`
libpacketizer_copy_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic packetizer_copy`
libpacketizer_copy_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic packetizer_copy`
libpacketizer_copy_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin packetizer_copy`
libpacketizer_copy_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin packetizer_copy`
libpacketizer_copy_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin packetizer_copy`

# The packetizer_mpegvideo plugin

libpacketizer_mpegvideo_plugin_a_SOURCES = $(SOURCES_packetizer_mpegvideo)
libpacketizer_mpegvideo_plugin_la_SOURCES = $(SOURCES_packetizer_mpegvideo)
libpacketizer_mpegvideo_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_mpegvideo`
libpacketizer_mpegvideo_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_mpegvideo`
libpacketizer_mpegvideo_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_mpegvideo`
libpacketizer_mpegvideo_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_mpegvideo`
libpacketizer_mpegvideo_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_mpegvideo`
libpacketizer_mpegvideo_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_mpegvideo`
libpacketizer_mpegvideo_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin packetizer_mpegvideo` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpacketizer_mpegvideo_plugin_la_LIBADD = $(LTLIBVLC)

libpacketizer_mpegvideo_a_SOURCES = $(SOURCES_packetizer_mpegvideo)
libpacketizer_mpegvideo_builtin_la_SOURCES = $(SOURCES_packetizer_mpegvideo)
libpacketizer_mpegvideo_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic packetizer_mpegvideo`
libpacketizer_mpegvideo_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic packetizer_mpegvideo`
libpacketizer_mpegvideo_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic packetizer_mpegvideo`
libpacketizer_mpegvideo_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin packetizer_mpegvideo`
libpacketizer_mpegvideo_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin packetizer_mpegvideo`
libpacketizer_mpegvideo_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin packetizer_mpegvideo`

# The packetizer_mpeg4video plugin

libpacketizer_mpeg4video_plugin_a_SOURCES = $(SOURCES_packetizer_mpeg4video)
libpacketizer_mpeg4video_plugin_la_SOURCES = $(SOURCES_packetizer_mpeg4video)
libpacketizer_mpeg4video_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_mpeg4video`
libpacketizer_mpeg4video_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_mpeg4video`
libpacketizer_mpeg4video_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_mpeg4video`
libpacketizer_mpeg4video_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_mpeg4video`
libpacketizer_mpeg4video_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_mpeg4video`
libpacketizer_mpeg4video_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_mpeg4video`
libpacketizer_mpeg4video_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin packetizer_mpeg4video` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpacketizer_mpeg4video_plugin_la_LIBADD = $(LTLIBVLC)

libpacketizer_mpeg4video_a_SOURCES = $(SOURCES_packetizer_mpeg4video)
libpacketizer_mpeg4video_builtin_la_SOURCES = $(SOURCES_packetizer_mpeg4video)
libpacketizer_mpeg4video_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic packetizer_mpeg4video`
libpacketizer_mpeg4video_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic packetizer_mpeg4video`
libpacketizer_mpeg4video_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic packetizer_mpeg4video`
libpacketizer_mpeg4video_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin packetizer_mpeg4video`
libpacketizer_mpeg4video_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin packetizer_mpeg4video`
libpacketizer_mpeg4video_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin packetizer_mpeg4video`

# The packetizer_mpeg4audio plugin

libpacketizer_mpeg4audio_plugin_a_SOURCES = $(SOURCES_packetizer_mpeg4audio)
libpacketizer_mpeg4audio_plugin_la_SOURCES = $(SOURCES_packetizer_mpeg4audio)
libpacketizer_mpeg4audio_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin packetizer_mpeg4audio` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpacketizer_mpeg4audio_plugin_la_LIBADD = $(LTLIBVLC)

libpacketizer_mpeg4audio_a_SOURCES = $(SOURCES_packetizer_mpeg4audio)
libpacketizer_mpeg4audio_builtin_la_SOURCES = $(SOURCES_packetizer_mpeg4audio)
libpacketizer_mpeg4audio_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic packetizer_mpeg4audio`
libpacketizer_mpeg4audio_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic packetizer_mpeg4audio`
libpacketizer_mpeg4audio_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic packetizer_mpeg4audio`
libpacketizer_mpeg4audio_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin packetizer_mpeg4audio`
libpacketizer_mpeg4audio_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin packetizer_mpeg4audio`

# The packetizer_h264 plugin

libpacketizer_h264_plugin_a_SOURCES = $(SOURCES_packetizer_h264)
libpacketizer_h264_plugin_la_SOURCES = $(SOURCES_packetizer_h264)
libpacketizer_h264_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_h264`
libpacketizer_h264_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_h264`
libpacketizer_h264_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_h264`
libpacketizer_h264_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin packetizer_h264`
libpacketizer_h264_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin packetizer_h264`
libpacketizer_h264_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin packetizer_h264`
libpacketizer_h264_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin packetizer_h264` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpacketizer_h264_plugin_la_LIBADD = $(LTLIBVLC)

libpacketizer_h264_a_SOURCES = $(SOURCES_packetizer_h264)
libpacketizer_h264_builtin_la_SOURCES = $(SOURCES_packetizer_h264)
libpacketizer_h264_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic packetizer_h264`
libpacketizer_h264_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic packetizer_h264`
libpacketizer_h264_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic packetizer_h264`
libpacketizer_h264_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin packetizer_h264`
libpacketizer_h264_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin packetizer_h264`
libpacketizer_h264_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin packetizer_h264`

