
# modules/video_output/Makefile.am automatically generated from modules/video_output/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = video_output
mods = aa caca fb ggi glide vout_sdl svgalib wingdi wingapi mga hd1000v snapshot opengl image directfb

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = directx qte x11
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libaa_plugin.a libaa.a libcaca_plugin.a libcaca.a libfb_plugin.a libfb.a libggi_plugin.a libggi.a libglide_plugin.a libglide.a libvout_sdl_plugin.a libvout_sdl.a libsvgalib_plugin.a libsvgalib.a libwingdi_plugin.a libwingdi.a libwingapi_plugin.a libwingapi.a libmga_plugin.a libmga.a libhd1000v_plugin.a libhd1000v.a libsnapshot_plugin.a libsnapshot.a libopengl_plugin.a libopengl.a libimage_plugin.a libimage.a libdirectfb_plugin.a libdirectfb.a
EXTRA_LTLIBRARIES =  libaa_plugin.la libaa_builtin.la libcaca_plugin.la libcaca_builtin.la libfb_plugin.la libfb_builtin.la libggi_plugin.la libggi_builtin.la libglide_plugin.la libglide_builtin.la libvout_sdl_plugin.la libvout_sdl_builtin.la libsvgalib_plugin.la libsvgalib_builtin.la libwingdi_plugin.la libwingdi_builtin.la libwingapi_plugin.la libwingapi_builtin.la libmga_plugin.la libmga_builtin.la libhd1000v_plugin.la libhd1000v_builtin.la libsnapshot_plugin.la libsnapshot_builtin.la libopengl_plugin.la libopengl_builtin.la libimage_plugin.la libimage_builtin.la libdirectfb_plugin.la libdirectfb_builtin.la

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

# The aa plugin

libaa_plugin_a_SOURCES = $(SOURCES_aa)
libaa_plugin_la_SOURCES = $(SOURCES_aa)
libaa_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin aa`
libaa_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aa`
libaa_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aa`
libaa_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin aa`
libaa_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin aa`
libaa_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin aa`
libaa_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin aa` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaa_plugin_la_LIBADD = $(LTLIBVLC)

libaa_a_SOURCES = $(SOURCES_aa)
libaa_builtin_la_SOURCES = $(SOURCES_aa)
libaa_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic aa`
libaa_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic aa`
libaa_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic aa`
libaa_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin aa`
libaa_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin aa`
libaa_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin aa`

# The caca plugin

libcaca_plugin_a_SOURCES = $(SOURCES_caca)
libcaca_plugin_la_SOURCES = $(SOURCES_caca)
libcaca_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin caca`
libcaca_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin caca`
libcaca_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin caca`
libcaca_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin caca`
libcaca_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin caca`
libcaca_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin caca`
libcaca_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin caca` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libcaca_plugin_la_LIBADD = $(LTLIBVLC)

libcaca_a_SOURCES = $(SOURCES_caca)
libcaca_builtin_la_SOURCES = $(SOURCES_caca)
libcaca_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic caca`
libcaca_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic caca`
libcaca_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic caca`
libcaca_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin caca`
libcaca_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin caca`
libcaca_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin caca`

# The fb plugin

libfb_plugin_a_SOURCES = $(SOURCES_fb)
libfb_plugin_la_SOURCES = $(SOURCES_fb)
libfb_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin fb`
libfb_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin fb`
libfb_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin fb`
libfb_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin fb`
libfb_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin fb`
libfb_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin fb`
libfb_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin fb` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libfb_plugin_la_LIBADD = $(LTLIBVLC)

libfb_a_SOURCES = $(SOURCES_fb)
libfb_builtin_la_SOURCES = $(SOURCES_fb)
libfb_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic fb`
libfb_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic fb`
libfb_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic fb`
libfb_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin fb`
libfb_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin fb`
libfb_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin fb`

# The ggi plugin

libggi_plugin_a_SOURCES = $(SOURCES_ggi)
libggi_plugin_la_SOURCES = $(SOURCES_ggi)
libggi_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ggi`
libggi_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ggi`
libggi_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ggi`
libggi_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ggi`
libggi_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ggi`
libggi_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ggi`
libggi_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ggi` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libggi_plugin_la_LIBADD = $(LTLIBVLC)

libggi_a_SOURCES = $(SOURCES_ggi)
libggi_builtin_la_SOURCES = $(SOURCES_ggi)
libggi_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ggi`
libggi_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ggi`
libggi_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ggi`
libggi_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ggi`
libggi_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ggi`
libggi_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ggi`

# The glide plugin

libglide_plugin_a_SOURCES = $(SOURCES_glide)
libglide_plugin_la_SOURCES = $(SOURCES_glide)
libglide_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin glide`
libglide_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin glide`
libglide_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin glide`
libglide_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin glide`
libglide_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin glide`
libglide_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin glide`
libglide_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin glide` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libglide_plugin_la_LIBADD = $(LTLIBVLC)

libglide_a_SOURCES = $(SOURCES_glide)
libglide_builtin_la_SOURCES = $(SOURCES_glide)
libglide_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic glide`
libglide_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic glide`
libglide_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic glide`
libglide_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin glide`
libglide_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin glide`
libglide_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin glide`

# The vout_sdl plugin

libvout_sdl_plugin_a_SOURCES = $(SOURCES_vout_sdl)
libvout_sdl_plugin_la_SOURCES = $(SOURCES_vout_sdl)
libvout_sdl_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin vout_sdl`
libvout_sdl_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin vout_sdl`
libvout_sdl_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin vout_sdl`
libvout_sdl_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin vout_sdl`
libvout_sdl_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin vout_sdl`
libvout_sdl_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin vout_sdl`
libvout_sdl_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin vout_sdl` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libvout_sdl_plugin_la_LIBADD = $(LTLIBVLC)

libvout_sdl_a_SOURCES = $(SOURCES_vout_sdl)
libvout_sdl_builtin_la_SOURCES = $(SOURCES_vout_sdl)
libvout_sdl_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic vout_sdl`
libvout_sdl_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic vout_sdl`
libvout_sdl_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic vout_sdl`
libvout_sdl_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin vout_sdl`
libvout_sdl_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin vout_sdl`
libvout_sdl_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin vout_sdl`

# The svgalib plugin

libsvgalib_plugin_a_SOURCES = $(SOURCES_svgalib)
libsvgalib_plugin_la_SOURCES = $(SOURCES_svgalib)
libsvgalib_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin svgalib`
libsvgalib_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin svgalib`
libsvgalib_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin svgalib`
libsvgalib_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin svgalib`
libsvgalib_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin svgalib`
libsvgalib_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin svgalib`
libsvgalib_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin svgalib` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsvgalib_plugin_la_LIBADD = $(LTLIBVLC)

libsvgalib_a_SOURCES = $(SOURCES_svgalib)
libsvgalib_builtin_la_SOURCES = $(SOURCES_svgalib)
libsvgalib_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic svgalib`
libsvgalib_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic svgalib`
libsvgalib_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic svgalib`
libsvgalib_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin svgalib`
libsvgalib_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin svgalib`
libsvgalib_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin svgalib`

# The wingdi plugin

libwingdi_plugin_a_SOURCES = $(SOURCES_wingdi)
libwingdi_plugin_la_SOURCES = $(SOURCES_wingdi)
libwingdi_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin wingdi`
libwingdi_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wingdi`
libwingdi_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wingdi`
libwingdi_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin wingdi`
libwingdi_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wingdi`
libwingdi_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wingdi`
libwingdi_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin wingdi` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libwingdi_plugin_la_LIBADD = $(LTLIBVLC)

libwingdi_a_SOURCES = $(SOURCES_wingdi)
libwingdi_builtin_la_SOURCES = $(SOURCES_wingdi)
libwingdi_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic wingdi`
libwingdi_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic wingdi`
libwingdi_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic wingdi`
libwingdi_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin wingdi`
libwingdi_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin wingdi`
libwingdi_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin wingdi`

# The wingapi plugin

libwingapi_plugin_a_SOURCES = $(SOURCES_wingapi)
libwingapi_plugin_la_SOURCES = $(SOURCES_wingapi)
libwingapi_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin wingapi`
libwingapi_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wingapi`
libwingapi_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wingapi`
libwingapi_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin wingapi`
libwingapi_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wingapi`
libwingapi_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wingapi`
libwingapi_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin wingapi` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libwingapi_plugin_la_LIBADD = $(LTLIBVLC)

libwingapi_a_SOURCES = $(SOURCES_wingapi)
libwingapi_builtin_la_SOURCES = $(SOURCES_wingapi)
libwingapi_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic wingapi`
libwingapi_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic wingapi`
libwingapi_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic wingapi`
libwingapi_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin wingapi`
libwingapi_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin wingapi`
libwingapi_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin wingapi`

# The mga plugin

libmga_plugin_a_SOURCES = $(SOURCES_mga)
libmga_plugin_la_SOURCES = $(SOURCES_mga)
libmga_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mga`
libmga_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mga`
libmga_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mga`
libmga_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mga`
libmga_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mga`
libmga_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mga`
libmga_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mga` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmga_plugin_la_LIBADD = $(LTLIBVLC)

libmga_a_SOURCES = $(SOURCES_mga)
libmga_builtin_la_SOURCES = $(SOURCES_mga)
libmga_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mga`
libmga_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mga`
libmga_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mga`
libmga_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mga`
libmga_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mga`
libmga_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mga`

# The hd1000v plugin

libhd1000v_plugin_a_SOURCES = $(SOURCES_hd1000v)
libhd1000v_plugin_la_SOURCES = $(SOURCES_hd1000v)
libhd1000v_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin hd1000v`
libhd1000v_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hd1000v`
libhd1000v_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hd1000v`
libhd1000v_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin hd1000v`
libhd1000v_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hd1000v`
libhd1000v_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hd1000v`
libhd1000v_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin hd1000v` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libhd1000v_plugin_la_LIBADD = $(LTLIBVLC)

libhd1000v_a_SOURCES = $(SOURCES_hd1000v)
libhd1000v_builtin_la_SOURCES = $(SOURCES_hd1000v)
libhd1000v_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic hd1000v`
libhd1000v_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic hd1000v`
libhd1000v_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic hd1000v`
libhd1000v_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin hd1000v`
libhd1000v_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin hd1000v`
libhd1000v_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin hd1000v`

# The snapshot plugin

libsnapshot_plugin_a_SOURCES = $(SOURCES_snapshot)
libsnapshot_plugin_la_SOURCES = $(SOURCES_snapshot)
libsnapshot_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin snapshot`
libsnapshot_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin snapshot`
libsnapshot_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin snapshot`
libsnapshot_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin snapshot`
libsnapshot_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin snapshot`
libsnapshot_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin snapshot`
libsnapshot_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin snapshot` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsnapshot_plugin_la_LIBADD = $(LTLIBVLC)

libsnapshot_a_SOURCES = $(SOURCES_snapshot)
libsnapshot_builtin_la_SOURCES = $(SOURCES_snapshot)
libsnapshot_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic snapshot`
libsnapshot_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic snapshot`
libsnapshot_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic snapshot`
libsnapshot_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin snapshot`
libsnapshot_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin snapshot`
libsnapshot_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin snapshot`

# The opengl plugin

libopengl_plugin_a_SOURCES = $(SOURCES_opengl)
libopengl_plugin_la_SOURCES = $(SOURCES_opengl)
libopengl_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin opengl`
libopengl_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin opengl`
libopengl_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin opengl`
libopengl_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin opengl`
libopengl_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin opengl`
libopengl_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin opengl`
libopengl_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin opengl` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libopengl_plugin_la_LIBADD = $(LTLIBVLC)

libopengl_a_SOURCES = $(SOURCES_opengl)
libopengl_builtin_la_SOURCES = $(SOURCES_opengl)
libopengl_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic opengl`
libopengl_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic opengl`
libopengl_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic opengl`
libopengl_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin opengl`
libopengl_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin opengl`
libopengl_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin opengl`

# The image plugin

libimage_plugin_a_SOURCES = $(SOURCES_image)
libimage_plugin_la_SOURCES = $(SOURCES_image)
libimage_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin image`
libimage_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin image`
libimage_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin image`
libimage_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin image`
libimage_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin image`
libimage_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin image`
libimage_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin image` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libimage_plugin_la_LIBADD = $(LTLIBVLC)

libimage_a_SOURCES = $(SOURCES_image)
libimage_builtin_la_SOURCES = $(SOURCES_image)
libimage_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic image`
libimage_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic image`
libimage_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic image`
libimage_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin image`
libimage_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin image`
libimage_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin image`

# The directfb plugin

libdirectfb_plugin_a_SOURCES = $(SOURCES_directfb)
libdirectfb_plugin_la_SOURCES = $(SOURCES_directfb)
libdirectfb_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin directfb`
libdirectfb_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin directfb`
libdirectfb_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin directfb`
libdirectfb_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin directfb`
libdirectfb_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin directfb`
libdirectfb_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin directfb`
libdirectfb_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin directfb` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdirectfb_plugin_la_LIBADD = $(LTLIBVLC)

libdirectfb_a_SOURCES = $(SOURCES_directfb)
libdirectfb_builtin_la_SOURCES = $(SOURCES_directfb)
libdirectfb_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic directfb`
libdirectfb_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic directfb`
libdirectfb_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic directfb`
libdirectfb_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin directfb`
libdirectfb_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin directfb`
libdirectfb_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin directfb`

