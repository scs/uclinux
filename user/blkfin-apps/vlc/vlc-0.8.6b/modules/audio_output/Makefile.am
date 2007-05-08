
# modules/audio_output/Makefile.am automatically generated from modules/audio_output/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = audio_output
mods = alsa arts aout_directx esd aout_file oss aout_sdl waveout hd1000a portaudio auhal jack

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libalsa_plugin.a libalsa.a libarts_plugin.a libarts.a libaout_directx_plugin.a libaout_directx.a libesd_plugin.a libesd.a libaout_file_plugin.a libaout_file.a liboss_plugin.a liboss.a libaout_sdl_plugin.a libaout_sdl.a libwaveout_plugin.a libwaveout.a libhd1000a_plugin.a libhd1000a.a libportaudio_plugin.a libportaudio.a libauhal_plugin.a libauhal.a libjack_plugin.a libjack.a
EXTRA_LTLIBRARIES =  libalsa_plugin.la libalsa_builtin.la libarts_plugin.la libarts_builtin.la libaout_directx_plugin.la libaout_directx_builtin.la libesd_plugin.la libesd_builtin.la libaout_file_plugin.la libaout_file_builtin.la liboss_plugin.la liboss_builtin.la libaout_sdl_plugin.la libaout_sdl_builtin.la libwaveout_plugin.la libwaveout_builtin.la libhd1000a_plugin.la libhd1000a_builtin.la libportaudio_plugin.la libportaudio_builtin.la libauhal_plugin.la libauhal_builtin.la libjack_plugin.la libjack_builtin.la

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

# The alsa plugin

libalsa_plugin_a_SOURCES = $(SOURCES_alsa)
libalsa_plugin_la_SOURCES = $(SOURCES_alsa)
libalsa_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin alsa`
libalsa_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin alsa`
libalsa_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin alsa`
libalsa_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin alsa`
libalsa_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin alsa`
libalsa_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin alsa`
libalsa_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin alsa` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libalsa_plugin_la_LIBADD = $(LTLIBVLC)

libalsa_a_SOURCES = $(SOURCES_alsa)
libalsa_builtin_la_SOURCES = $(SOURCES_alsa)
libalsa_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic alsa`
libalsa_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic alsa`
libalsa_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic alsa`
libalsa_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin alsa`
libalsa_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin alsa`
libalsa_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin alsa`

# The arts plugin

libarts_plugin_a_SOURCES = $(SOURCES_arts)
libarts_plugin_la_SOURCES = $(SOURCES_arts)
libarts_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin arts`
libarts_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin arts`
libarts_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin arts`
libarts_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin arts`
libarts_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin arts`
libarts_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin arts`
libarts_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin arts` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libarts_plugin_la_LIBADD = $(LTLIBVLC)

libarts_a_SOURCES = $(SOURCES_arts)
libarts_builtin_la_SOURCES = $(SOURCES_arts)
libarts_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic arts`
libarts_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic arts`
libarts_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic arts`
libarts_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin arts`
libarts_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin arts`
libarts_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin arts`

# The aout_directx plugin

libaout_directx_plugin_a_SOURCES = $(SOURCES_aout_directx)
libaout_directx_plugin_la_SOURCES = $(SOURCES_aout_directx)
libaout_directx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin aout_directx`
libaout_directx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aout_directx`
libaout_directx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aout_directx`
libaout_directx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin aout_directx`
libaout_directx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aout_directx`
libaout_directx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aout_directx`
libaout_directx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin aout_directx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaout_directx_plugin_la_LIBADD = $(LTLIBVLC)

libaout_directx_a_SOURCES = $(SOURCES_aout_directx)
libaout_directx_builtin_la_SOURCES = $(SOURCES_aout_directx)
libaout_directx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic aout_directx`
libaout_directx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic aout_directx`
libaout_directx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic aout_directx`
libaout_directx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin aout_directx`
libaout_directx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin aout_directx`
libaout_directx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin aout_directx`

# The esd plugin

libesd_plugin_a_SOURCES = $(SOURCES_esd)
libesd_plugin_la_SOURCES = $(SOURCES_esd)
libesd_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin esd`
libesd_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin esd`
libesd_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin esd`
libesd_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin esd`
libesd_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin esd`
libesd_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin esd`
libesd_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin esd` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libesd_plugin_la_LIBADD = $(LTLIBVLC)

libesd_a_SOURCES = $(SOURCES_esd)
libesd_builtin_la_SOURCES = $(SOURCES_esd)
libesd_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic esd`
libesd_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic esd`
libesd_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic esd`
libesd_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin esd`
libesd_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin esd`
libesd_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin esd`

# The aout_file plugin

libaout_file_plugin_a_SOURCES = $(SOURCES_aout_file)
libaout_file_plugin_la_SOURCES = $(SOURCES_aout_file)
libaout_file_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin aout_file`
libaout_file_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aout_file`
libaout_file_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aout_file`
libaout_file_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin aout_file`
libaout_file_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aout_file`
libaout_file_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aout_file`
libaout_file_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin aout_file` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaout_file_plugin_la_LIBADD = $(LTLIBVLC)

libaout_file_a_SOURCES = $(SOURCES_aout_file)
libaout_file_builtin_la_SOURCES = $(SOURCES_aout_file)
libaout_file_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic aout_file`
libaout_file_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic aout_file`
libaout_file_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic aout_file`
libaout_file_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin aout_file`
libaout_file_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin aout_file`
libaout_file_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin aout_file`

# The oss plugin

liboss_plugin_a_SOURCES = $(SOURCES_oss)
liboss_plugin_la_SOURCES = $(SOURCES_oss)
liboss_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin oss`
liboss_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin oss`
liboss_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin oss`
liboss_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin oss`
liboss_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin oss`
liboss_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin oss`
liboss_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin oss` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liboss_plugin_la_LIBADD = $(LTLIBVLC)

liboss_a_SOURCES = $(SOURCES_oss)
liboss_builtin_la_SOURCES = $(SOURCES_oss)
liboss_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic oss`
liboss_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic oss`
liboss_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic oss`
liboss_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin oss`
liboss_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin oss`
liboss_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin oss`

# The aout_sdl plugin

libaout_sdl_plugin_a_SOURCES = $(SOURCES_aout_sdl)
libaout_sdl_plugin_la_SOURCES = $(SOURCES_aout_sdl)
libaout_sdl_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin aout_sdl`
libaout_sdl_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aout_sdl`
libaout_sdl_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aout_sdl`
libaout_sdl_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin aout_sdl`
libaout_sdl_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aout_sdl`
libaout_sdl_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aout_sdl`
libaout_sdl_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin aout_sdl` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaout_sdl_plugin_la_LIBADD = $(LTLIBVLC)

libaout_sdl_a_SOURCES = $(SOURCES_aout_sdl)
libaout_sdl_builtin_la_SOURCES = $(SOURCES_aout_sdl)
libaout_sdl_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic aout_sdl`
libaout_sdl_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic aout_sdl`
libaout_sdl_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic aout_sdl`
libaout_sdl_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin aout_sdl`
libaout_sdl_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin aout_sdl`
libaout_sdl_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin aout_sdl`

# The waveout plugin

libwaveout_plugin_a_SOURCES = $(SOURCES_waveout)
libwaveout_plugin_la_SOURCES = $(SOURCES_waveout)
libwaveout_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin waveout`
libwaveout_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin waveout`
libwaveout_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin waveout`
libwaveout_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin waveout`
libwaveout_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin waveout`
libwaveout_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin waveout`
libwaveout_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin waveout` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libwaveout_plugin_la_LIBADD = $(LTLIBVLC)

libwaveout_a_SOURCES = $(SOURCES_waveout)
libwaveout_builtin_la_SOURCES = $(SOURCES_waveout)
libwaveout_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic waveout`
libwaveout_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic waveout`
libwaveout_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic waveout`
libwaveout_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin waveout`
libwaveout_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin waveout`
libwaveout_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin waveout`

# The hd1000a plugin

libhd1000a_plugin_a_SOURCES = $(SOURCES_hd1000a)
libhd1000a_plugin_la_SOURCES = $(SOURCES_hd1000a)
libhd1000a_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin hd1000a`
libhd1000a_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hd1000a`
libhd1000a_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hd1000a`
libhd1000a_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin hd1000a`
libhd1000a_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hd1000a`
libhd1000a_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hd1000a`
libhd1000a_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin hd1000a` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libhd1000a_plugin_la_LIBADD = $(LTLIBVLC)

libhd1000a_a_SOURCES = $(SOURCES_hd1000a)
libhd1000a_builtin_la_SOURCES = $(SOURCES_hd1000a)
libhd1000a_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic hd1000a`
libhd1000a_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic hd1000a`
libhd1000a_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic hd1000a`
libhd1000a_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin hd1000a`
libhd1000a_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin hd1000a`
libhd1000a_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin hd1000a`

# The portaudio plugin

libportaudio_plugin_a_SOURCES = $(SOURCES_portaudio)
libportaudio_plugin_la_SOURCES = $(SOURCES_portaudio)
libportaudio_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin portaudio`
libportaudio_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin portaudio`
libportaudio_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin portaudio`
libportaudio_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin portaudio`
libportaudio_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin portaudio`
libportaudio_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin portaudio`
libportaudio_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin portaudio` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libportaudio_plugin_la_LIBADD = $(LTLIBVLC)

libportaudio_a_SOURCES = $(SOURCES_portaudio)
libportaudio_builtin_la_SOURCES = $(SOURCES_portaudio)
libportaudio_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic portaudio`
libportaudio_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic portaudio`
libportaudio_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic portaudio`
libportaudio_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin portaudio`
libportaudio_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin portaudio`
libportaudio_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin portaudio`

# The auhal plugin

libauhal_plugin_a_SOURCES = $(SOURCES_auhal)
libauhal_plugin_la_SOURCES = $(SOURCES_auhal)
libauhal_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin auhal`
libauhal_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin auhal`
libauhal_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin auhal`
libauhal_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin auhal`
libauhal_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin auhal`
libauhal_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin auhal`
libauhal_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin auhal` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libauhal_plugin_la_LIBADD = $(LTLIBVLC)

libauhal_a_SOURCES = $(SOURCES_auhal)
libauhal_builtin_la_SOURCES = $(SOURCES_auhal)
libauhal_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic auhal`
libauhal_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic auhal`
libauhal_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic auhal`
libauhal_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin auhal`
libauhal_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin auhal`
libauhal_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin auhal`

# The jack plugin

libjack_plugin_a_SOURCES = $(SOURCES_jack)
libjack_plugin_la_SOURCES = $(SOURCES_jack)
libjack_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin jack`
libjack_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin jack`
libjack_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin jack`
libjack_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin jack`
libjack_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin jack`
libjack_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin jack`
libjack_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin jack` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libjack_plugin_la_LIBADD = $(LTLIBVLC)

libjack_a_SOURCES = $(SOURCES_jack)
libjack_builtin_la_SOURCES = $(SOURCES_jack)
libjack_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic jack`
libjack_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic jack`
libjack_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic jack`
libjack_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin jack`
libjack_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin jack`
libjack_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin jack`

