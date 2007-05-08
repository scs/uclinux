
# modules/codec/Makefile.am automatically generated from modules/codec/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = codec
mods = a52 cinepak dts flacdec lpcm araw vorbis tarkin theora tremor speex adpcm mpeg_audio libmpeg2 rawvideo quicktime subsdec faad dvbsub telx mash x264 twolame dirac png svcdsub cvdsub fake realaudio sdl_image

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = cmml dmo ffmpeg spudec
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  liba52_plugin.a liba52.a libcinepak_plugin.a libcinepak.a libdts_plugin.a libdts.a libflacdec_plugin.a libflacdec.a liblpcm_plugin.a liblpcm.a libaraw_plugin.a libaraw.a libvorbis_plugin.a libvorbis.a libtarkin_plugin.a libtarkin.a libtheora_plugin.a libtheora.a libtremor_plugin.a libtremor.a libspeex_plugin.a libspeex.a libadpcm_plugin.a libadpcm.a libmpeg_audio_plugin.a libmpeg_audio.a liblibmpeg2_plugin.a liblibmpeg2.a librawvideo_plugin.a librawvideo.a libquicktime_plugin.a libquicktime.a libsubsdec_plugin.a libsubsdec.a libfaad_plugin.a libfaad.a libdvbsub_plugin.a libdvbsub.a libtelx_plugin.a libtelx.a libmash_plugin.a libmash.a libx264_plugin.a libx264.a libtwolame_plugin.a libtwolame.a libdirac_plugin.a libdirac.a libpng_plugin.a libpng.a libsvcdsub_plugin.a libsvcdsub.a libcvdsub_plugin.a libcvdsub.a libfake_plugin.a libfake.a librealaudio_plugin.a librealaudio.a libsdl_image_plugin.a libsdl_image.a
EXTRA_LTLIBRARIES =  liba52_plugin.la liba52_builtin.la libcinepak_plugin.la libcinepak_builtin.la libdts_plugin.la libdts_builtin.la libflacdec_plugin.la libflacdec_builtin.la liblpcm_plugin.la liblpcm_builtin.la libaraw_plugin.la libaraw_builtin.la libvorbis_plugin.la libvorbis_builtin.la libtarkin_plugin.la libtarkin_builtin.la libtheora_plugin.la libtheora_builtin.la libtremor_plugin.la libtremor_builtin.la libspeex_plugin.la libspeex_builtin.la libadpcm_plugin.la libadpcm_builtin.la libmpeg_audio_plugin.la libmpeg_audio_builtin.la liblibmpeg2_plugin.la liblibmpeg2_builtin.la librawvideo_plugin.la librawvideo_builtin.la libquicktime_plugin.la libquicktime_builtin.la libsubsdec_plugin.la libsubsdec_builtin.la libfaad_plugin.la libfaad_builtin.la libdvbsub_plugin.la libdvbsub_builtin.la libtelx_plugin.la libtelx_builtin.la libmash_plugin.la libmash_builtin.la libx264_plugin.la libx264_builtin.la libtwolame_plugin.la libtwolame_builtin.la libdirac_plugin.la libdirac_builtin.la libpng_plugin.la libpng_builtin.la libsvcdsub_plugin.la libsvcdsub_builtin.la libcvdsub_plugin.la libcvdsub_builtin.la libfake_plugin.la libfake_builtin.la librealaudio_plugin.la librealaudio_builtin.la libsdl_image_plugin.la libsdl_image_builtin.la

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

# The a52 plugin

liba52_plugin_a_SOURCES = $(SOURCES_a52)
liba52_plugin_la_SOURCES = $(SOURCES_a52)
liba52_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin a52`
liba52_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin a52`
liba52_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin a52`
liba52_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin a52`
liba52_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin a52`
liba52_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin a52`
liba52_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin a52` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liba52_plugin_la_LIBADD = $(LTLIBVLC)

liba52_a_SOURCES = $(SOURCES_a52)
liba52_builtin_la_SOURCES = $(SOURCES_a52)
liba52_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic a52`
liba52_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic a52`
liba52_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic a52`
liba52_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin a52`
liba52_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin a52`
liba52_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin a52`

# The cinepak plugin

libcinepak_plugin_a_SOURCES = $(SOURCES_cinepak)
libcinepak_plugin_la_SOURCES = $(SOURCES_cinepak)
libcinepak_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin cinepak`
libcinepak_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin cinepak`
libcinepak_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin cinepak`
libcinepak_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin cinepak`
libcinepak_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin cinepak`
libcinepak_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin cinepak`
libcinepak_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin cinepak` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libcinepak_plugin_la_LIBADD = $(LTLIBVLC)

libcinepak_a_SOURCES = $(SOURCES_cinepak)
libcinepak_builtin_la_SOURCES = $(SOURCES_cinepak)
libcinepak_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic cinepak`
libcinepak_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic cinepak`
libcinepak_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic cinepak`
libcinepak_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin cinepak`
libcinepak_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin cinepak`
libcinepak_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin cinepak`

# The dts plugin

libdts_plugin_a_SOURCES = $(SOURCES_dts)
libdts_plugin_la_SOURCES = $(SOURCES_dts)
libdts_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dts`
libdts_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dts`
libdts_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dts`
libdts_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dts`
libdts_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dts`
libdts_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dts`
libdts_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dts` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdts_plugin_la_LIBADD = $(LTLIBVLC)

libdts_a_SOURCES = $(SOURCES_dts)
libdts_builtin_la_SOURCES = $(SOURCES_dts)
libdts_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dts`
libdts_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dts`
libdts_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dts`
libdts_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dts`
libdts_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dts`
libdts_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dts`

# The flacdec plugin

libflacdec_plugin_a_SOURCES = $(SOURCES_flacdec)
libflacdec_plugin_la_SOURCES = $(SOURCES_flacdec)
libflacdec_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin flacdec`
libflacdec_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin flacdec`
libflacdec_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin flacdec`
libflacdec_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin flacdec`
libflacdec_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin flacdec`
libflacdec_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin flacdec`
libflacdec_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin flacdec` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libflacdec_plugin_la_LIBADD = $(LTLIBVLC)

libflacdec_a_SOURCES = $(SOURCES_flacdec)
libflacdec_builtin_la_SOURCES = $(SOURCES_flacdec)
libflacdec_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic flacdec`
libflacdec_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic flacdec`
libflacdec_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic flacdec`
libflacdec_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin flacdec`
libflacdec_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin flacdec`
libflacdec_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin flacdec`

# The lpcm plugin

liblpcm_plugin_a_SOURCES = $(SOURCES_lpcm)
liblpcm_plugin_la_SOURCES = $(SOURCES_lpcm)
liblpcm_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin lpcm`
liblpcm_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin lpcm`
liblpcm_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin lpcm`
liblpcm_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin lpcm`
liblpcm_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin lpcm`
liblpcm_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin lpcm`
liblpcm_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin lpcm` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liblpcm_plugin_la_LIBADD = $(LTLIBVLC)

liblpcm_a_SOURCES = $(SOURCES_lpcm)
liblpcm_builtin_la_SOURCES = $(SOURCES_lpcm)
liblpcm_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic lpcm`
liblpcm_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic lpcm`
liblpcm_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic lpcm`
liblpcm_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin lpcm`
liblpcm_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin lpcm`
liblpcm_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin lpcm`

# The araw plugin

libaraw_plugin_a_SOURCES = $(SOURCES_araw)
libaraw_plugin_la_SOURCES = $(SOURCES_araw)
libaraw_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin araw`
libaraw_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin araw`
libaraw_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin araw`
libaraw_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin araw`
libaraw_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin araw`
libaraw_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin araw`
libaraw_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin araw` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaraw_plugin_la_LIBADD = $(LTLIBVLC)

libaraw_a_SOURCES = $(SOURCES_araw)
libaraw_builtin_la_SOURCES = $(SOURCES_araw)
libaraw_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic araw`
libaraw_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic araw`
libaraw_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic araw`
libaraw_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin araw`
libaraw_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin araw`
libaraw_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin araw`

# The vorbis plugin

libvorbis_plugin_a_SOURCES = $(SOURCES_vorbis)
libvorbis_plugin_la_SOURCES = $(SOURCES_vorbis)
libvorbis_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin vorbis`
libvorbis_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin vorbis`
libvorbis_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin vorbis`
libvorbis_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin vorbis`
libvorbis_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin vorbis`
libvorbis_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin vorbis`
libvorbis_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin vorbis` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libvorbis_plugin_la_LIBADD = $(LTLIBVLC)

libvorbis_a_SOURCES = $(SOURCES_vorbis)
libvorbis_builtin_la_SOURCES = $(SOURCES_vorbis)
libvorbis_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic vorbis`
libvorbis_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic vorbis`
libvorbis_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic vorbis`
libvorbis_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin vorbis`
libvorbis_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin vorbis`
libvorbis_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin vorbis`

# The tarkin plugin

libtarkin_plugin_a_SOURCES = $(SOURCES_tarkin)
libtarkin_plugin_la_SOURCES = $(SOURCES_tarkin)
libtarkin_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin tarkin`
libtarkin_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin tarkin`
libtarkin_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin tarkin`
libtarkin_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin tarkin`
libtarkin_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin tarkin`
libtarkin_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin tarkin`
libtarkin_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin tarkin` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtarkin_plugin_la_LIBADD = $(LTLIBVLC)

libtarkin_a_SOURCES = $(SOURCES_tarkin)
libtarkin_builtin_la_SOURCES = $(SOURCES_tarkin)
libtarkin_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic tarkin`
libtarkin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic tarkin`
libtarkin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic tarkin`
libtarkin_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin tarkin`
libtarkin_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin tarkin`
libtarkin_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin tarkin`

# The theora plugin

libtheora_plugin_a_SOURCES = $(SOURCES_theora)
libtheora_plugin_la_SOURCES = $(SOURCES_theora)
libtheora_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin theora`
libtheora_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin theora`
libtheora_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin theora`
libtheora_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin theora`
libtheora_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin theora`
libtheora_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin theora`
libtheora_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin theora` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtheora_plugin_la_LIBADD = $(LTLIBVLC)

libtheora_a_SOURCES = $(SOURCES_theora)
libtheora_builtin_la_SOURCES = $(SOURCES_theora)
libtheora_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic theora`
libtheora_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic theora`
libtheora_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic theora`
libtheora_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin theora`
libtheora_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin theora`
libtheora_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin theora`

# The tremor plugin

libtremor_plugin_a_SOURCES = $(SOURCES_tremor)
libtremor_plugin_la_SOURCES = $(SOURCES_tremor)
libtremor_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin tremor`
libtremor_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin tremor`
libtremor_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin tremor`
libtremor_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin tremor`
libtremor_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin tremor`
libtremor_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin tremor`
libtremor_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin tremor` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtremor_plugin_la_LIBADD = $(LTLIBVLC)

libtremor_a_SOURCES = $(SOURCES_tremor)
libtremor_builtin_la_SOURCES = $(SOURCES_tremor)
libtremor_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic tremor`
libtremor_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic tremor`
libtremor_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic tremor`
libtremor_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin tremor`
libtremor_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin tremor`
libtremor_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin tremor`

# The speex plugin

libspeex_plugin_a_SOURCES = $(SOURCES_speex)
libspeex_plugin_la_SOURCES = $(SOURCES_speex)
libspeex_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin speex`
libspeex_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin speex`
libspeex_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin speex`
libspeex_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin speex`
libspeex_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin speex`
libspeex_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin speex`
libspeex_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin speex` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libspeex_plugin_la_LIBADD = $(LTLIBVLC)

libspeex_a_SOURCES = $(SOURCES_speex)
libspeex_builtin_la_SOURCES = $(SOURCES_speex)
libspeex_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic speex`
libspeex_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic speex`
libspeex_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic speex`
libspeex_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin speex`
libspeex_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin speex`
libspeex_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin speex`

# The adpcm plugin

libadpcm_plugin_a_SOURCES = $(SOURCES_adpcm)
libadpcm_plugin_la_SOURCES = $(SOURCES_adpcm)
libadpcm_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin adpcm`
libadpcm_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin adpcm`
libadpcm_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin adpcm`
libadpcm_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin adpcm`
libadpcm_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin adpcm`
libadpcm_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin adpcm`
libadpcm_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin adpcm` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libadpcm_plugin_la_LIBADD = $(LTLIBVLC)

libadpcm_a_SOURCES = $(SOURCES_adpcm)
libadpcm_builtin_la_SOURCES = $(SOURCES_adpcm)
libadpcm_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic adpcm`
libadpcm_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic adpcm`
libadpcm_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic adpcm`
libadpcm_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin adpcm`
libadpcm_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin adpcm`
libadpcm_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin adpcm`

# The mpeg_audio plugin

libmpeg_audio_plugin_a_SOURCES = $(SOURCES_mpeg_audio)
libmpeg_audio_plugin_la_SOURCES = $(SOURCES_mpeg_audio)
libmpeg_audio_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mpeg_audio`
libmpeg_audio_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mpeg_audio`
libmpeg_audio_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mpeg_audio`
libmpeg_audio_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mpeg_audio`
libmpeg_audio_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mpeg_audio`
libmpeg_audio_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mpeg_audio`
libmpeg_audio_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mpeg_audio` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmpeg_audio_plugin_la_LIBADD = $(LTLIBVLC)

libmpeg_audio_a_SOURCES = $(SOURCES_mpeg_audio)
libmpeg_audio_builtin_la_SOURCES = $(SOURCES_mpeg_audio)
libmpeg_audio_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mpeg_audio`
libmpeg_audio_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mpeg_audio`
libmpeg_audio_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mpeg_audio`
libmpeg_audio_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mpeg_audio`
libmpeg_audio_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mpeg_audio`
libmpeg_audio_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mpeg_audio`

# The libmpeg2 plugin

liblibmpeg2_plugin_a_SOURCES = $(SOURCES_libmpeg2)
liblibmpeg2_plugin_la_SOURCES = $(SOURCES_libmpeg2)
liblibmpeg2_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin libmpeg2`
liblibmpeg2_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin libmpeg2`
liblibmpeg2_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin libmpeg2`
liblibmpeg2_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin libmpeg2`
liblibmpeg2_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin libmpeg2`
liblibmpeg2_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin libmpeg2`
liblibmpeg2_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin libmpeg2` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liblibmpeg2_plugin_la_LIBADD = $(LTLIBVLC)

liblibmpeg2_a_SOURCES = $(SOURCES_libmpeg2)
liblibmpeg2_builtin_la_SOURCES = $(SOURCES_libmpeg2)
liblibmpeg2_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic libmpeg2`
liblibmpeg2_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic libmpeg2`
liblibmpeg2_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic libmpeg2`
liblibmpeg2_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin libmpeg2`
liblibmpeg2_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin libmpeg2`
liblibmpeg2_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin libmpeg2`

# The rawvideo plugin

librawvideo_plugin_a_SOURCES = $(SOURCES_rawvideo)
librawvideo_plugin_la_SOURCES = $(SOURCES_rawvideo)
librawvideo_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin rawvideo`
librawvideo_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rawvideo`
librawvideo_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rawvideo`
librawvideo_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin rawvideo`
librawvideo_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rawvideo`
librawvideo_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rawvideo`
librawvideo_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin rawvideo` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
librawvideo_plugin_la_LIBADD = $(LTLIBVLC)

librawvideo_a_SOURCES = $(SOURCES_rawvideo)
librawvideo_builtin_la_SOURCES = $(SOURCES_rawvideo)
librawvideo_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic rawvideo`
librawvideo_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic rawvideo`
librawvideo_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic rawvideo`
librawvideo_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin rawvideo`
librawvideo_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin rawvideo`
librawvideo_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin rawvideo`

# The quicktime plugin

libquicktime_plugin_a_SOURCES = $(SOURCES_quicktime)
libquicktime_plugin_la_SOURCES = $(SOURCES_quicktime)
libquicktime_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin quicktime`
libquicktime_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin quicktime`
libquicktime_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin quicktime`
libquicktime_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin quicktime`
libquicktime_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin quicktime`
libquicktime_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin quicktime`
libquicktime_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin quicktime` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libquicktime_plugin_la_LIBADD = $(LTLIBVLC)

libquicktime_a_SOURCES = $(SOURCES_quicktime)
libquicktime_builtin_la_SOURCES = $(SOURCES_quicktime)
libquicktime_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic quicktime`
libquicktime_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic quicktime`
libquicktime_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic quicktime`
libquicktime_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin quicktime`
libquicktime_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin quicktime`
libquicktime_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin quicktime`

# The subsdec plugin

libsubsdec_plugin_a_SOURCES = $(SOURCES_subsdec)
libsubsdec_plugin_la_SOURCES = $(SOURCES_subsdec)
libsubsdec_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin subsdec`
libsubsdec_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin subsdec`
libsubsdec_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin subsdec`
libsubsdec_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin subsdec`
libsubsdec_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin subsdec`
libsubsdec_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin subsdec`
libsubsdec_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin subsdec` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsubsdec_plugin_la_LIBADD = $(LTLIBVLC)

libsubsdec_a_SOURCES = $(SOURCES_subsdec)
libsubsdec_builtin_la_SOURCES = $(SOURCES_subsdec)
libsubsdec_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic subsdec`
libsubsdec_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic subsdec`
libsubsdec_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic subsdec`
libsubsdec_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin subsdec`
libsubsdec_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin subsdec`
libsubsdec_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin subsdec`

# The faad plugin

libfaad_plugin_a_SOURCES = $(SOURCES_faad)
libfaad_plugin_la_SOURCES = $(SOURCES_faad)
libfaad_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin faad`
libfaad_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin faad`
libfaad_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin faad`
libfaad_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin faad`
libfaad_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin faad`
libfaad_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin faad`
libfaad_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin faad` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libfaad_plugin_la_LIBADD = $(LTLIBVLC)

libfaad_a_SOURCES = $(SOURCES_faad)
libfaad_builtin_la_SOURCES = $(SOURCES_faad)
libfaad_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic faad`
libfaad_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic faad`
libfaad_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic faad`
libfaad_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin faad`
libfaad_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin faad`
libfaad_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin faad`

# The dvbsub plugin

libdvbsub_plugin_a_SOURCES = $(SOURCES_dvbsub)
libdvbsub_plugin_la_SOURCES = $(SOURCES_dvbsub)
libdvbsub_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dvbsub`
libdvbsub_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dvbsub`
libdvbsub_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dvbsub`
libdvbsub_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dvbsub`
libdvbsub_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dvbsub`
libdvbsub_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dvbsub`
libdvbsub_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dvbsub` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdvbsub_plugin_la_LIBADD = $(LTLIBVLC)

libdvbsub_a_SOURCES = $(SOURCES_dvbsub)
libdvbsub_builtin_la_SOURCES = $(SOURCES_dvbsub)
libdvbsub_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dvbsub`
libdvbsub_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dvbsub`
libdvbsub_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dvbsub`
libdvbsub_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dvbsub`
libdvbsub_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dvbsub`
libdvbsub_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dvbsub`

# The telx plugin

libtelx_plugin_a_SOURCES = $(SOURCES_telx)
libtelx_plugin_la_SOURCES = $(SOURCES_telx)
libtelx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin telx`
libtelx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin telx`
libtelx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin telx`
libtelx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin telx`
libtelx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin telx`
libtelx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin telx`
libtelx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin telx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtelx_plugin_la_LIBADD = $(LTLIBVLC)

libtelx_a_SOURCES = $(SOURCES_telx)
libtelx_builtin_la_SOURCES = $(SOURCES_telx)
libtelx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic telx`
libtelx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic telx`
libtelx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic telx`
libtelx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin telx`
libtelx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin telx`
libtelx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin telx`

# The mash plugin

libmash_plugin_a_SOURCES = $(SOURCES_mash)
libmash_plugin_la_SOURCES = $(SOURCES_mash)
libmash_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mash`
libmash_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mash`
libmash_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mash`
libmash_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mash`
libmash_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mash`
libmash_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mash`
libmash_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mash` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmash_plugin_la_LIBADD = $(LTLIBVLC)

libmash_a_SOURCES = $(SOURCES_mash)
libmash_builtin_la_SOURCES = $(SOURCES_mash)
libmash_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mash`
libmash_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mash`
libmash_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mash`
libmash_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mash`
libmash_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mash`
libmash_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mash`

# The x264 plugin

libx264_plugin_a_SOURCES = $(SOURCES_x264)
libx264_plugin_la_SOURCES = $(SOURCES_x264)
libx264_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin x264`
libx264_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin x264`
libx264_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin x264`
libx264_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin x264`
libx264_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin x264`
libx264_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin x264`
libx264_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin x264` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libx264_plugin_la_LIBADD = $(LTLIBVLC)

libx264_a_SOURCES = $(SOURCES_x264)
libx264_builtin_la_SOURCES = $(SOURCES_x264)
libx264_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic x264`
libx264_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic x264`
libx264_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic x264`
libx264_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin x264`
libx264_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin x264`
libx264_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin x264`

# The twolame plugin

libtwolame_plugin_a_SOURCES = $(SOURCES_twolame)
libtwolame_plugin_la_SOURCES = $(SOURCES_twolame)
libtwolame_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin twolame`
libtwolame_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin twolame`
libtwolame_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin twolame`
libtwolame_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin twolame`
libtwolame_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin twolame`
libtwolame_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin twolame`
libtwolame_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin twolame` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtwolame_plugin_la_LIBADD = $(LTLIBVLC)

libtwolame_a_SOURCES = $(SOURCES_twolame)
libtwolame_builtin_la_SOURCES = $(SOURCES_twolame)
libtwolame_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic twolame`
libtwolame_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic twolame`
libtwolame_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic twolame`
libtwolame_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin twolame`
libtwolame_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin twolame`
libtwolame_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin twolame`

# The dirac plugin

libdirac_plugin_a_SOURCES = $(SOURCES_dirac)
libdirac_plugin_la_SOURCES = $(SOURCES_dirac)
libdirac_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dirac`
libdirac_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dirac`
libdirac_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dirac`
libdirac_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dirac`
libdirac_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dirac`
libdirac_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dirac`
libdirac_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dirac` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdirac_plugin_la_LIBADD = $(LTLIBVLC)

libdirac_a_SOURCES = $(SOURCES_dirac)
libdirac_builtin_la_SOURCES = $(SOURCES_dirac)
libdirac_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dirac`
libdirac_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dirac`
libdirac_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dirac`
libdirac_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dirac`
libdirac_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dirac`
libdirac_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dirac`

# The png plugin

libpng_plugin_a_SOURCES = $(SOURCES_png)
libpng_plugin_la_SOURCES = $(SOURCES_png)
libpng_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin png`
libpng_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin png`
libpng_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin png`
libpng_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin png`
libpng_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin png`
libpng_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin png`
libpng_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin png` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpng_plugin_la_LIBADD = $(LTLIBVLC)

libpng_a_SOURCES = $(SOURCES_png)
libpng_builtin_la_SOURCES = $(SOURCES_png)
libpng_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic png`
libpng_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic png`
libpng_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic png`
libpng_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin png`
libpng_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin png`
libpng_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin png`

# The svcdsub plugin

libsvcdsub_plugin_a_SOURCES = $(SOURCES_svcdsub)
libsvcdsub_plugin_la_SOURCES = $(SOURCES_svcdsub)
libsvcdsub_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin svcdsub`
libsvcdsub_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin svcdsub`
libsvcdsub_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin svcdsub`
libsvcdsub_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin svcdsub`
libsvcdsub_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin svcdsub`
libsvcdsub_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin svcdsub`
libsvcdsub_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin svcdsub` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsvcdsub_plugin_la_LIBADD = $(LTLIBVLC)

libsvcdsub_a_SOURCES = $(SOURCES_svcdsub)
libsvcdsub_builtin_la_SOURCES = $(SOURCES_svcdsub)
libsvcdsub_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic svcdsub`
libsvcdsub_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic svcdsub`
libsvcdsub_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic svcdsub`
libsvcdsub_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin svcdsub`
libsvcdsub_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin svcdsub`
libsvcdsub_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin svcdsub`

# The cvdsub plugin

libcvdsub_plugin_a_SOURCES = $(SOURCES_cvdsub)
libcvdsub_plugin_la_SOURCES = $(SOURCES_cvdsub)
libcvdsub_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin cvdsub`
libcvdsub_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin cvdsub`
libcvdsub_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin cvdsub`
libcvdsub_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin cvdsub`
libcvdsub_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin cvdsub`
libcvdsub_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin cvdsub`
libcvdsub_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin cvdsub` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libcvdsub_plugin_la_LIBADD = $(LTLIBVLC)

libcvdsub_a_SOURCES = $(SOURCES_cvdsub)
libcvdsub_builtin_la_SOURCES = $(SOURCES_cvdsub)
libcvdsub_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic cvdsub`
libcvdsub_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic cvdsub`
libcvdsub_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic cvdsub`
libcvdsub_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin cvdsub`
libcvdsub_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin cvdsub`
libcvdsub_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin cvdsub`

# The fake plugin

libfake_plugin_a_SOURCES = $(SOURCES_fake)
libfake_plugin_la_SOURCES = $(SOURCES_fake)
libfake_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin fake`
libfake_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin fake`
libfake_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin fake`
libfake_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin fake`
libfake_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin fake`
libfake_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin fake`
libfake_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin fake` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libfake_plugin_la_LIBADD = $(LTLIBVLC)

libfake_a_SOURCES = $(SOURCES_fake)
libfake_builtin_la_SOURCES = $(SOURCES_fake)
libfake_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic fake`
libfake_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic fake`
libfake_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic fake`
libfake_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin fake`
libfake_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin fake`
libfake_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin fake`

# The realaudio plugin

librealaudio_plugin_a_SOURCES = $(SOURCES_realaudio)
librealaudio_plugin_la_SOURCES = $(SOURCES_realaudio)
librealaudio_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin realaudio`
librealaudio_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin realaudio`
librealaudio_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin realaudio`
librealaudio_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin realaudio`
librealaudio_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin realaudio`
librealaudio_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin realaudio`
librealaudio_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin realaudio` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
librealaudio_plugin_la_LIBADD = $(LTLIBVLC)

librealaudio_a_SOURCES = $(SOURCES_realaudio)
librealaudio_builtin_la_SOURCES = $(SOURCES_realaudio)
librealaudio_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic realaudio`
librealaudio_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic realaudio`
librealaudio_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic realaudio`
librealaudio_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin realaudio`
librealaudio_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin realaudio`
librealaudio_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin realaudio`

# The sdl_image plugin

libsdl_image_plugin_a_SOURCES = $(SOURCES_sdl_image)
libsdl_image_plugin_la_SOURCES = $(SOURCES_sdl_image)
libsdl_image_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin sdl_image`
libsdl_image_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin sdl_image`
libsdl_image_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin sdl_image`
libsdl_image_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin sdl_image`
libsdl_image_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin sdl_image`
libsdl_image_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin sdl_image`
libsdl_image_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin sdl_image` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsdl_image_plugin_la_LIBADD = $(LTLIBVLC)

libsdl_image_a_SOURCES = $(SOURCES_sdl_image)
libsdl_image_builtin_la_SOURCES = $(SOURCES_sdl_image)
libsdl_image_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic sdl_image`
libsdl_image_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic sdl_image`
libsdl_image_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic sdl_image`
libsdl_image_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin sdl_image`
libsdl_image_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin sdl_image`
libsdl_image_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin sdl_image`

