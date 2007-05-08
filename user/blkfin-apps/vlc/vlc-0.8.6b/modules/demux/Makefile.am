
# modules/demux/Makefile.am automatically generated from modules/demux/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = demux
mods = a52sys dtssys flac ogg m3u demuxdump rawdv au wav mkv live555 nsv real ts ps mod pva aiff sgimb mjpeg subtitle ty vobsub voc xa nuv nsc mpc tta

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = asf avi mp4 mpeg playlist util
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  liba52sys_plugin.a liba52sys.a libdtssys_plugin.a libdtssys.a libflac_plugin.a libflac.a libogg_plugin.a libogg.a libm3u_plugin.a libm3u.a libdemuxdump_plugin.a libdemuxdump.a librawdv_plugin.a librawdv.a libau_plugin.a libau.a libwav_plugin.a libwav.a libmkv_plugin.a libmkv.a liblive555_plugin.a liblive555.a libnsv_plugin.a libnsv.a libreal_plugin.a libreal.a libts_plugin.a libts.a libps_plugin.a libps.a libmod_plugin.a libmod.a libpva_plugin.a libpva.a libaiff_plugin.a libaiff.a libsgimb_plugin.a libsgimb.a libmjpeg_plugin.a libmjpeg.a libsubtitle_plugin.a libsubtitle.a libty_plugin.a libty.a libvobsub_plugin.a libvobsub.a libvoc_plugin.a libvoc.a libxa_plugin.a libxa.a libnuv_plugin.a libnuv.a libnsc_plugin.a libnsc.a libmpc_plugin.a libmpc.a libtta_plugin.a libtta.a
EXTRA_LTLIBRARIES =  liba52sys_plugin.la liba52sys_builtin.la libdtssys_plugin.la libdtssys_builtin.la libflac_plugin.la libflac_builtin.la libogg_plugin.la libogg_builtin.la libm3u_plugin.la libm3u_builtin.la libdemuxdump_plugin.la libdemuxdump_builtin.la librawdv_plugin.la librawdv_builtin.la libau_plugin.la libau_builtin.la libwav_plugin.la libwav_builtin.la libmkv_plugin.la libmkv_builtin.la liblive555_plugin.la liblive555_builtin.la libnsv_plugin.la libnsv_builtin.la libreal_plugin.la libreal_builtin.la libts_plugin.la libts_builtin.la libps_plugin.la libps_builtin.la libmod_plugin.la libmod_builtin.la libpva_plugin.la libpva_builtin.la libaiff_plugin.la libaiff_builtin.la libsgimb_plugin.la libsgimb_builtin.la libmjpeg_plugin.la libmjpeg_builtin.la libsubtitle_plugin.la libsubtitle_builtin.la libty_plugin.la libty_builtin.la libvobsub_plugin.la libvobsub_builtin.la libvoc_plugin.la libvoc_builtin.la libxa_plugin.la libxa_builtin.la libnuv_plugin.la libnuv_builtin.la libnsc_plugin.la libnsc_builtin.la libmpc_plugin.la libmpc_builtin.la libtta_plugin.la libtta_builtin.la

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

# The a52sys plugin

liba52sys_plugin_a_SOURCES = $(SOURCES_a52sys)
liba52sys_plugin_la_SOURCES = $(SOURCES_a52sys)
liba52sys_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin a52sys`
liba52sys_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin a52sys`
liba52sys_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin a52sys`
liba52sys_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin a52sys`
liba52sys_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin a52sys`
liba52sys_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin a52sys`
liba52sys_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin a52sys` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liba52sys_plugin_la_LIBADD = $(LTLIBVLC)

liba52sys_a_SOURCES = $(SOURCES_a52sys)
liba52sys_builtin_la_SOURCES = $(SOURCES_a52sys)
liba52sys_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic a52sys`
liba52sys_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic a52sys`
liba52sys_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic a52sys`
liba52sys_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin a52sys`
liba52sys_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin a52sys`
liba52sys_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin a52sys`

# The dtssys plugin

libdtssys_plugin_a_SOURCES = $(SOURCES_dtssys)
libdtssys_plugin_la_SOURCES = $(SOURCES_dtssys)
libdtssys_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dtssys`
libdtssys_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dtssys`
libdtssys_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dtssys`
libdtssys_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dtssys`
libdtssys_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dtssys`
libdtssys_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dtssys`
libdtssys_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dtssys` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdtssys_plugin_la_LIBADD = $(LTLIBVLC)

libdtssys_a_SOURCES = $(SOURCES_dtssys)
libdtssys_builtin_la_SOURCES = $(SOURCES_dtssys)
libdtssys_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dtssys`
libdtssys_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dtssys`
libdtssys_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dtssys`
libdtssys_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dtssys`
libdtssys_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dtssys`
libdtssys_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dtssys`

# The flac plugin

libflac_plugin_a_SOURCES = $(SOURCES_flac)
libflac_plugin_la_SOURCES = $(SOURCES_flac)
libflac_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin flac`
libflac_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin flac`
libflac_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin flac`
libflac_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin flac`
libflac_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin flac`
libflac_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin flac`
libflac_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin flac` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libflac_plugin_la_LIBADD = $(LTLIBVLC)

libflac_a_SOURCES = $(SOURCES_flac)
libflac_builtin_la_SOURCES = $(SOURCES_flac)
libflac_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic flac`
libflac_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic flac`
libflac_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic flac`
libflac_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin flac`
libflac_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin flac`
libflac_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin flac`

# The ogg plugin

libogg_plugin_a_SOURCES = $(SOURCES_ogg)
libogg_plugin_la_SOURCES = $(SOURCES_ogg)
libogg_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ogg`
libogg_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ogg`
libogg_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ogg`
libogg_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ogg`
libogg_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ogg`
libogg_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ogg`
libogg_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ogg` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libogg_plugin_la_LIBADD = $(LTLIBVLC)

libogg_a_SOURCES = $(SOURCES_ogg)
libogg_builtin_la_SOURCES = $(SOURCES_ogg)
libogg_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ogg`
libogg_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ogg`
libogg_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ogg`
libogg_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ogg`
libogg_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ogg`
libogg_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ogg`

# The m3u plugin

libm3u_plugin_a_SOURCES = $(SOURCES_m3u)
libm3u_plugin_la_SOURCES = $(SOURCES_m3u)
libm3u_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin m3u`
libm3u_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin m3u`
libm3u_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin m3u`
libm3u_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin m3u`
libm3u_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin m3u`
libm3u_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin m3u`
libm3u_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin m3u` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libm3u_plugin_la_LIBADD = $(LTLIBVLC)

libm3u_a_SOURCES = $(SOURCES_m3u)
libm3u_builtin_la_SOURCES = $(SOURCES_m3u)
libm3u_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic m3u`
libm3u_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic m3u`
libm3u_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic m3u`
libm3u_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin m3u`
libm3u_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin m3u`
libm3u_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin m3u`

# The demuxdump plugin

libdemuxdump_plugin_a_SOURCES = $(SOURCES_demuxdump)
libdemuxdump_plugin_la_SOURCES = $(SOURCES_demuxdump)
libdemuxdump_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin demuxdump`
libdemuxdump_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin demuxdump`
libdemuxdump_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin demuxdump`
libdemuxdump_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin demuxdump`
libdemuxdump_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin demuxdump`
libdemuxdump_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin demuxdump`
libdemuxdump_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin demuxdump` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdemuxdump_plugin_la_LIBADD = $(LTLIBVLC)

libdemuxdump_a_SOURCES = $(SOURCES_demuxdump)
libdemuxdump_builtin_la_SOURCES = $(SOURCES_demuxdump)
libdemuxdump_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic demuxdump`
libdemuxdump_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic demuxdump`
libdemuxdump_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic demuxdump`
libdemuxdump_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin demuxdump`
libdemuxdump_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin demuxdump`
libdemuxdump_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin demuxdump`

# The rawdv plugin

librawdv_plugin_a_SOURCES = $(SOURCES_rawdv)
librawdv_plugin_la_SOURCES = $(SOURCES_rawdv)
librawdv_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin rawdv`
librawdv_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rawdv`
librawdv_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rawdv`
librawdv_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin rawdv`
librawdv_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rawdv`
librawdv_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rawdv`
librawdv_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin rawdv` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
librawdv_plugin_la_LIBADD = $(LTLIBVLC)

librawdv_a_SOURCES = $(SOURCES_rawdv)
librawdv_builtin_la_SOURCES = $(SOURCES_rawdv)
librawdv_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic rawdv`
librawdv_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic rawdv`
librawdv_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic rawdv`
librawdv_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin rawdv`
librawdv_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin rawdv`
librawdv_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin rawdv`

# The au plugin

libau_plugin_a_SOURCES = $(SOURCES_au)
libau_plugin_la_SOURCES = $(SOURCES_au)
libau_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin au`
libau_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin au`
libau_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin au`
libau_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin au`
libau_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin au`
libau_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin au`
libau_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin au` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libau_plugin_la_LIBADD = $(LTLIBVLC)

libau_a_SOURCES = $(SOURCES_au)
libau_builtin_la_SOURCES = $(SOURCES_au)
libau_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic au`
libau_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic au`
libau_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic au`
libau_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin au`
libau_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin au`
libau_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin au`

# The wav plugin

libwav_plugin_a_SOURCES = $(SOURCES_wav)
libwav_plugin_la_SOURCES = $(SOURCES_wav)
libwav_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin wav`
libwav_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wav`
libwav_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wav`
libwav_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin wav`
libwav_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wav`
libwav_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wav`
libwav_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin wav` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libwav_plugin_la_LIBADD = $(LTLIBVLC)

libwav_a_SOURCES = $(SOURCES_wav)
libwav_builtin_la_SOURCES = $(SOURCES_wav)
libwav_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic wav`
libwav_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic wav`
libwav_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic wav`
libwav_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin wav`
libwav_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin wav`
libwav_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin wav`

# The mkv plugin

libmkv_plugin_a_SOURCES = $(SOURCES_mkv)
libmkv_plugin_la_SOURCES = $(SOURCES_mkv)
libmkv_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mkv`
libmkv_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mkv`
libmkv_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mkv`
libmkv_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mkv`
libmkv_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mkv`
libmkv_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mkv`
libmkv_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mkv` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmkv_plugin_la_LIBADD = $(LTLIBVLC)

libmkv_a_SOURCES = $(SOURCES_mkv)
libmkv_builtin_la_SOURCES = $(SOURCES_mkv)
libmkv_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mkv`
libmkv_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mkv`
libmkv_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mkv`
libmkv_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mkv`
libmkv_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mkv`
libmkv_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mkv`

# The live555 plugin

liblive555_plugin_a_SOURCES = $(SOURCES_live555)
liblive555_plugin_la_SOURCES = $(SOURCES_live555)
liblive555_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin live555`
liblive555_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin live555`
liblive555_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin live555`
liblive555_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin live555`
liblive555_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin live555`
liblive555_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin live555`
liblive555_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin live555` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liblive555_plugin_la_LIBADD = $(LTLIBVLC)

liblive555_a_SOURCES = $(SOURCES_live555)
liblive555_builtin_la_SOURCES = $(SOURCES_live555)
liblive555_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic live555`
liblive555_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic live555`
liblive555_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic live555`
liblive555_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin live555`
liblive555_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin live555`
liblive555_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin live555`

# The nsv plugin

libnsv_plugin_a_SOURCES = $(SOURCES_nsv)
libnsv_plugin_la_SOURCES = $(SOURCES_nsv)
libnsv_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin nsv`
libnsv_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin nsv`
libnsv_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin nsv`
libnsv_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin nsv`
libnsv_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin nsv`
libnsv_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin nsv`
libnsv_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin nsv` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libnsv_plugin_la_LIBADD = $(LTLIBVLC)

libnsv_a_SOURCES = $(SOURCES_nsv)
libnsv_builtin_la_SOURCES = $(SOURCES_nsv)
libnsv_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic nsv`
libnsv_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic nsv`
libnsv_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic nsv`
libnsv_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin nsv`
libnsv_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin nsv`
libnsv_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin nsv`

# The real plugin

libreal_plugin_a_SOURCES = $(SOURCES_real)
libreal_plugin_la_SOURCES = $(SOURCES_real)
libreal_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin real`
libreal_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin real`
libreal_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin real`
libreal_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin real`
libreal_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin real`
libreal_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin real`
libreal_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin real` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libreal_plugin_la_LIBADD = $(LTLIBVLC)

libreal_a_SOURCES = $(SOURCES_real)
libreal_builtin_la_SOURCES = $(SOURCES_real)
libreal_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic real`
libreal_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic real`
libreal_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic real`
libreal_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin real`
libreal_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin real`
libreal_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin real`

# The ts plugin

libts_plugin_a_SOURCES = $(SOURCES_ts)
libts_plugin_la_SOURCES = $(SOURCES_ts)
libts_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ts`
libts_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ts`
libts_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ts`
libts_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ts`
libts_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ts`
libts_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ts`
libts_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ts` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libts_plugin_la_LIBADD = $(LTLIBVLC)

libts_a_SOURCES = $(SOURCES_ts)
libts_builtin_la_SOURCES = $(SOURCES_ts)
libts_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ts`
libts_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ts`
libts_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ts`
libts_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ts`
libts_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ts`
libts_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ts`

# The ps plugin

libps_plugin_a_SOURCES = $(SOURCES_ps)
libps_plugin_la_SOURCES = $(SOURCES_ps)
libps_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ps`
libps_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ps`
libps_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ps`
libps_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ps`
libps_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ps`
libps_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ps`
libps_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ps` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libps_plugin_la_LIBADD = $(LTLIBVLC)

libps_a_SOURCES = $(SOURCES_ps)
libps_builtin_la_SOURCES = $(SOURCES_ps)
libps_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ps`
libps_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ps`
libps_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ps`
libps_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ps`
libps_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ps`
libps_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ps`

# The mod plugin

libmod_plugin_a_SOURCES = $(SOURCES_mod)
libmod_plugin_la_SOURCES = $(SOURCES_mod)
libmod_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mod`
libmod_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mod`
libmod_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mod`
libmod_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mod`
libmod_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mod`
libmod_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mod`
libmod_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mod` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmod_plugin_la_LIBADD = $(LTLIBVLC)

libmod_a_SOURCES = $(SOURCES_mod)
libmod_builtin_la_SOURCES = $(SOURCES_mod)
libmod_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mod`
libmod_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mod`
libmod_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mod`
libmod_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mod`
libmod_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mod`
libmod_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mod`

# The pva plugin

libpva_plugin_a_SOURCES = $(SOURCES_pva)
libpva_plugin_la_SOURCES = $(SOURCES_pva)
libpva_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin pva`
libpva_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin pva`
libpva_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin pva`
libpva_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin pva`
libpva_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin pva`
libpva_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin pva`
libpva_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin pva` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpva_plugin_la_LIBADD = $(LTLIBVLC)

libpva_a_SOURCES = $(SOURCES_pva)
libpva_builtin_la_SOURCES = $(SOURCES_pva)
libpva_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic pva`
libpva_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic pva`
libpva_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic pva`
libpva_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin pva`
libpva_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pva`
libpva_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pva`

# The aiff plugin

libaiff_plugin_a_SOURCES = $(SOURCES_aiff)
libaiff_plugin_la_SOURCES = $(SOURCES_aiff)
libaiff_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin aiff`
libaiff_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aiff`
libaiff_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aiff`
libaiff_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin aiff`
libaiff_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aiff`
libaiff_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aiff`
libaiff_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin aiff` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaiff_plugin_la_LIBADD = $(LTLIBVLC)

libaiff_a_SOURCES = $(SOURCES_aiff)
libaiff_builtin_la_SOURCES = $(SOURCES_aiff)
libaiff_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic aiff`
libaiff_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic aiff`
libaiff_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic aiff`
libaiff_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin aiff`
libaiff_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin aiff`
libaiff_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin aiff`

# The sgimb plugin

libsgimb_plugin_a_SOURCES = $(SOURCES_sgimb)
libsgimb_plugin_la_SOURCES = $(SOURCES_sgimb)
libsgimb_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin sgimb`
libsgimb_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin sgimb`
libsgimb_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin sgimb`
libsgimb_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin sgimb`
libsgimb_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin sgimb`
libsgimb_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin sgimb`
libsgimb_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin sgimb` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsgimb_plugin_la_LIBADD = $(LTLIBVLC)

libsgimb_a_SOURCES = $(SOURCES_sgimb)
libsgimb_builtin_la_SOURCES = $(SOURCES_sgimb)
libsgimb_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic sgimb`
libsgimb_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic sgimb`
libsgimb_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic sgimb`
libsgimb_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin sgimb`
libsgimb_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin sgimb`
libsgimb_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin sgimb`

# The mjpeg plugin

libmjpeg_plugin_a_SOURCES = $(SOURCES_mjpeg)
libmjpeg_plugin_la_SOURCES = $(SOURCES_mjpeg)
libmjpeg_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mjpeg`
libmjpeg_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mjpeg`
libmjpeg_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mjpeg`
libmjpeg_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mjpeg`
libmjpeg_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mjpeg`
libmjpeg_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mjpeg`
libmjpeg_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mjpeg` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmjpeg_plugin_la_LIBADD = $(LTLIBVLC)

libmjpeg_a_SOURCES = $(SOURCES_mjpeg)
libmjpeg_builtin_la_SOURCES = $(SOURCES_mjpeg)
libmjpeg_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mjpeg`
libmjpeg_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mjpeg`
libmjpeg_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mjpeg`
libmjpeg_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mjpeg`
libmjpeg_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mjpeg`
libmjpeg_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mjpeg`

# The subtitle plugin

libsubtitle_plugin_a_SOURCES = $(SOURCES_subtitle)
libsubtitle_plugin_la_SOURCES = $(SOURCES_subtitle)
libsubtitle_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin subtitle`
libsubtitle_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin subtitle`
libsubtitle_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin subtitle`
libsubtitle_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin subtitle`
libsubtitle_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin subtitle`
libsubtitle_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin subtitle`
libsubtitle_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin subtitle` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsubtitle_plugin_la_LIBADD = $(LTLIBVLC)

libsubtitle_a_SOURCES = $(SOURCES_subtitle)
libsubtitle_builtin_la_SOURCES = $(SOURCES_subtitle)
libsubtitle_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic subtitle`
libsubtitle_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic subtitle`
libsubtitle_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic subtitle`
libsubtitle_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin subtitle`
libsubtitle_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin subtitle`
libsubtitle_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin subtitle`

# The ty plugin

libty_plugin_a_SOURCES = $(SOURCES_ty)
libty_plugin_la_SOURCES = $(SOURCES_ty)
libty_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ty`
libty_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ty`
libty_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ty`
libty_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ty`
libty_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ty`
libty_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ty`
libty_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ty` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libty_plugin_la_LIBADD = $(LTLIBVLC)

libty_a_SOURCES = $(SOURCES_ty)
libty_builtin_la_SOURCES = $(SOURCES_ty)
libty_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ty`
libty_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ty`
libty_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ty`
libty_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ty`
libty_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ty`
libty_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ty`

# The vobsub plugin

libvobsub_plugin_a_SOURCES = $(SOURCES_vobsub)
libvobsub_plugin_la_SOURCES = $(SOURCES_vobsub)
libvobsub_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin vobsub`
libvobsub_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin vobsub`
libvobsub_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin vobsub`
libvobsub_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin vobsub`
libvobsub_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin vobsub`
libvobsub_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin vobsub`
libvobsub_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin vobsub` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libvobsub_plugin_la_LIBADD = $(LTLIBVLC)

libvobsub_a_SOURCES = $(SOURCES_vobsub)
libvobsub_builtin_la_SOURCES = $(SOURCES_vobsub)
libvobsub_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic vobsub`
libvobsub_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic vobsub`
libvobsub_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic vobsub`
libvobsub_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin vobsub`
libvobsub_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin vobsub`
libvobsub_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin vobsub`

# The voc plugin

libvoc_plugin_a_SOURCES = $(SOURCES_voc)
libvoc_plugin_la_SOURCES = $(SOURCES_voc)
libvoc_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin voc`
libvoc_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin voc`
libvoc_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin voc`
libvoc_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin voc`
libvoc_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin voc`
libvoc_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin voc`
libvoc_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin voc` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libvoc_plugin_la_LIBADD = $(LTLIBVLC)

libvoc_a_SOURCES = $(SOURCES_voc)
libvoc_builtin_la_SOURCES = $(SOURCES_voc)
libvoc_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic voc`
libvoc_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic voc`
libvoc_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic voc`
libvoc_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin voc`
libvoc_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin voc`
libvoc_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin voc`

# The xa plugin

libxa_plugin_a_SOURCES = $(SOURCES_xa)
libxa_plugin_la_SOURCES = $(SOURCES_xa)
libxa_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin xa`
libxa_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin xa`
libxa_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin xa`
libxa_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin xa`
libxa_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin xa`
libxa_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin xa`
libxa_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin xa` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libxa_plugin_la_LIBADD = $(LTLIBVLC)

libxa_a_SOURCES = $(SOURCES_xa)
libxa_builtin_la_SOURCES = $(SOURCES_xa)
libxa_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic xa`
libxa_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic xa`
libxa_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic xa`
libxa_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin xa`
libxa_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin xa`
libxa_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin xa`

# The nuv plugin

libnuv_plugin_a_SOURCES = $(SOURCES_nuv)
libnuv_plugin_la_SOURCES = $(SOURCES_nuv)
libnuv_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin nuv`
libnuv_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin nuv`
libnuv_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin nuv`
libnuv_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin nuv`
libnuv_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin nuv`
libnuv_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin nuv`
libnuv_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin nuv` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libnuv_plugin_la_LIBADD = $(LTLIBVLC)

libnuv_a_SOURCES = $(SOURCES_nuv)
libnuv_builtin_la_SOURCES = $(SOURCES_nuv)
libnuv_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic nuv`
libnuv_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic nuv`
libnuv_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic nuv`
libnuv_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin nuv`
libnuv_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin nuv`
libnuv_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin nuv`

# The nsc plugin

libnsc_plugin_a_SOURCES = $(SOURCES_nsc)
libnsc_plugin_la_SOURCES = $(SOURCES_nsc)
libnsc_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin nsc`
libnsc_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin nsc`
libnsc_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin nsc`
libnsc_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin nsc`
libnsc_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin nsc`
libnsc_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin nsc`
libnsc_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin nsc` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libnsc_plugin_la_LIBADD = $(LTLIBVLC)

libnsc_a_SOURCES = $(SOURCES_nsc)
libnsc_builtin_la_SOURCES = $(SOURCES_nsc)
libnsc_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic nsc`
libnsc_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic nsc`
libnsc_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic nsc`
libnsc_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin nsc`
libnsc_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin nsc`
libnsc_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin nsc`

# The mpc plugin

libmpc_plugin_a_SOURCES = $(SOURCES_mpc)
libmpc_plugin_la_SOURCES = $(SOURCES_mpc)
libmpc_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mpc`
libmpc_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mpc`
libmpc_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mpc`
libmpc_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mpc`
libmpc_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mpc`
libmpc_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mpc`
libmpc_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mpc` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmpc_plugin_la_LIBADD = $(LTLIBVLC)

libmpc_a_SOURCES = $(SOURCES_mpc)
libmpc_builtin_la_SOURCES = $(SOURCES_mpc)
libmpc_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mpc`
libmpc_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mpc`
libmpc_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mpc`
libmpc_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mpc`
libmpc_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mpc`
libmpc_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mpc`

# The tta plugin

libtta_plugin_a_SOURCES = $(SOURCES_tta)
libtta_plugin_la_SOURCES = $(SOURCES_tta)
libtta_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin tta`
libtta_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin tta`
libtta_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin tta`
libtta_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin tta`
libtta_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin tta`
libtta_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin tta`
libtta_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin tta` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtta_plugin_la_LIBADD = $(LTLIBVLC)

libtta_a_SOURCES = $(SOURCES_tta)
libtta_builtin_la_SOURCES = $(SOURCES_tta)
libtta_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic tta`
libtta_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic tta`
libtta_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic tta`
libtta_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin tta`
libtta_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin tta`
libtta_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin tta`

