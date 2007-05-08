
# modules/video_filter/Makefile.am automatically generated from modules/video_filter/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = video_filter
mods = mosaic transform invert adjust distort wall clone crop motionblur logo deinterlace blend scale time marq rss motiondetect rv32 osdmenu magnify

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = swscale
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libmosaic_plugin.a libmosaic.a libtransform_plugin.a libtransform.a libinvert_plugin.a libinvert.a libadjust_plugin.a libadjust.a libdistort_plugin.a libdistort.a libwall_plugin.a libwall.a libclone_plugin.a libclone.a libcrop_plugin.a libcrop.a libmotionblur_plugin.a libmotionblur.a liblogo_plugin.a liblogo.a libdeinterlace_plugin.a libdeinterlace.a libblend_plugin.a libblend.a libscale_plugin.a libscale.a libtime_plugin.a libtime.a libmarq_plugin.a libmarq.a librss_plugin.a librss.a libmotiondetect_plugin.a libmotiondetect.a librv32_plugin.a librv32.a libosdmenu_plugin.a libosdmenu.a libmagnify_plugin.a libmagnify.a
EXTRA_LTLIBRARIES =  libmosaic_plugin.la libmosaic_builtin.la libtransform_plugin.la libtransform_builtin.la libinvert_plugin.la libinvert_builtin.la libadjust_plugin.la libadjust_builtin.la libdistort_plugin.la libdistort_builtin.la libwall_plugin.la libwall_builtin.la libclone_plugin.la libclone_builtin.la libcrop_plugin.la libcrop_builtin.la libmotionblur_plugin.la libmotionblur_builtin.la liblogo_plugin.la liblogo_builtin.la libdeinterlace_plugin.la libdeinterlace_builtin.la libblend_plugin.la libblend_builtin.la libscale_plugin.la libscale_builtin.la libtime_plugin.la libtime_builtin.la libmarq_plugin.la libmarq_builtin.la librss_plugin.la librss_builtin.la libmotiondetect_plugin.la libmotiondetect_builtin.la librv32_plugin.la librv32_builtin.la libosdmenu_plugin.la libosdmenu_builtin.la libmagnify_plugin.la libmagnify_builtin.la

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

# The mosaic plugin

libmosaic_plugin_a_SOURCES = $(SOURCES_mosaic)
libmosaic_plugin_la_SOURCES = $(SOURCES_mosaic)
libmosaic_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin mosaic`
libmosaic_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mosaic`
libmosaic_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mosaic`
libmosaic_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin mosaic`
libmosaic_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin mosaic`
libmosaic_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin mosaic`
libmosaic_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin mosaic` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmosaic_plugin_la_LIBADD = $(LTLIBVLC)

libmosaic_a_SOURCES = $(SOURCES_mosaic)
libmosaic_builtin_la_SOURCES = $(SOURCES_mosaic)
libmosaic_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic mosaic`
libmosaic_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic mosaic`
libmosaic_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic mosaic`
libmosaic_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin mosaic`
libmosaic_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin mosaic`
libmosaic_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin mosaic`

# The transform plugin

libtransform_plugin_a_SOURCES = $(SOURCES_transform)
libtransform_plugin_la_SOURCES = $(SOURCES_transform)
libtransform_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin transform`
libtransform_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin transform`
libtransform_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin transform`
libtransform_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin transform`
libtransform_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin transform`
libtransform_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin transform`
libtransform_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin transform` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtransform_plugin_la_LIBADD = $(LTLIBVLC)

libtransform_a_SOURCES = $(SOURCES_transform)
libtransform_builtin_la_SOURCES = $(SOURCES_transform)
libtransform_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic transform`
libtransform_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic transform`
libtransform_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic transform`
libtransform_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin transform`
libtransform_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin transform`
libtransform_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin transform`

# The invert plugin

libinvert_plugin_a_SOURCES = $(SOURCES_invert)
libinvert_plugin_la_SOURCES = $(SOURCES_invert)
libinvert_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin invert`
libinvert_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin invert`
libinvert_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin invert`
libinvert_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin invert`
libinvert_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin invert`
libinvert_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin invert`
libinvert_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin invert` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libinvert_plugin_la_LIBADD = $(LTLIBVLC)

libinvert_a_SOURCES = $(SOURCES_invert)
libinvert_builtin_la_SOURCES = $(SOURCES_invert)
libinvert_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic invert`
libinvert_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic invert`
libinvert_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic invert`
libinvert_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin invert`
libinvert_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin invert`
libinvert_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin invert`

# The adjust plugin

libadjust_plugin_a_SOURCES = $(SOURCES_adjust)
libadjust_plugin_la_SOURCES = $(SOURCES_adjust)
libadjust_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin adjust`
libadjust_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin adjust`
libadjust_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin adjust`
libadjust_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin adjust`
libadjust_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin adjust`
libadjust_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin adjust`
libadjust_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin adjust` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libadjust_plugin_la_LIBADD = $(LTLIBVLC)

libadjust_a_SOURCES = $(SOURCES_adjust)
libadjust_builtin_la_SOURCES = $(SOURCES_adjust)
libadjust_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic adjust`
libadjust_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic adjust`
libadjust_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic adjust`
libadjust_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin adjust`
libadjust_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin adjust`
libadjust_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin adjust`

# The distort plugin

libdistort_plugin_a_SOURCES = $(SOURCES_distort)
libdistort_plugin_la_SOURCES = $(SOURCES_distort)
libdistort_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin distort`
libdistort_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin distort`
libdistort_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin distort`
libdistort_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin distort`
libdistort_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin distort`
libdistort_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin distort`
libdistort_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin distort` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdistort_plugin_la_LIBADD = $(LTLIBVLC)

libdistort_a_SOURCES = $(SOURCES_distort)
libdistort_builtin_la_SOURCES = $(SOURCES_distort)
libdistort_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic distort`
libdistort_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic distort`
libdistort_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic distort`
libdistort_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin distort`
libdistort_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin distort`
libdistort_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin distort`

# The wall plugin

libwall_plugin_a_SOURCES = $(SOURCES_wall)
libwall_plugin_la_SOURCES = $(SOURCES_wall)
libwall_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin wall`
libwall_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wall`
libwall_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wall`
libwall_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin wall`
libwall_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin wall`
libwall_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin wall`
libwall_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin wall` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libwall_plugin_la_LIBADD = $(LTLIBVLC)

libwall_a_SOURCES = $(SOURCES_wall)
libwall_builtin_la_SOURCES = $(SOURCES_wall)
libwall_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic wall`
libwall_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic wall`
libwall_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic wall`
libwall_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin wall`
libwall_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin wall`
libwall_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin wall`

# The clone plugin

libclone_plugin_a_SOURCES = $(SOURCES_clone)
libclone_plugin_la_SOURCES = $(SOURCES_clone)
libclone_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin clone`
libclone_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin clone`
libclone_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin clone`
libclone_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin clone`
libclone_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin clone`
libclone_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin clone`
libclone_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin clone` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libclone_plugin_la_LIBADD = $(LTLIBVLC)

libclone_a_SOURCES = $(SOURCES_clone)
libclone_builtin_la_SOURCES = $(SOURCES_clone)
libclone_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic clone`
libclone_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic clone`
libclone_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic clone`
libclone_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin clone`
libclone_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin clone`
libclone_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin clone`

# The crop plugin

libcrop_plugin_a_SOURCES = $(SOURCES_crop)
libcrop_plugin_la_SOURCES = $(SOURCES_crop)
libcrop_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin crop`
libcrop_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin crop`
libcrop_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin crop`
libcrop_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin crop`
libcrop_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin crop`
libcrop_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin crop`
libcrop_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin crop` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libcrop_plugin_la_LIBADD = $(LTLIBVLC)

libcrop_a_SOURCES = $(SOURCES_crop)
libcrop_builtin_la_SOURCES = $(SOURCES_crop)
libcrop_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic crop`
libcrop_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic crop`
libcrop_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic crop`
libcrop_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin crop`
libcrop_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin crop`
libcrop_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin crop`

# The motionblur plugin

libmotionblur_plugin_a_SOURCES = $(SOURCES_motionblur)
libmotionblur_plugin_la_SOURCES = $(SOURCES_motionblur)
libmotionblur_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin motionblur`
libmotionblur_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin motionblur`
libmotionblur_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin motionblur`
libmotionblur_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin motionblur`
libmotionblur_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin motionblur`
libmotionblur_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin motionblur`
libmotionblur_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin motionblur` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmotionblur_plugin_la_LIBADD = $(LTLIBVLC)

libmotionblur_a_SOURCES = $(SOURCES_motionblur)
libmotionblur_builtin_la_SOURCES = $(SOURCES_motionblur)
libmotionblur_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic motionblur`
libmotionblur_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic motionblur`
libmotionblur_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic motionblur`
libmotionblur_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin motionblur`
libmotionblur_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin motionblur`
libmotionblur_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin motionblur`

# The logo plugin

liblogo_plugin_a_SOURCES = $(SOURCES_logo)
liblogo_plugin_la_SOURCES = $(SOURCES_logo)
liblogo_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin logo`
liblogo_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin logo`
liblogo_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin logo`
liblogo_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin logo`
liblogo_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin logo`
liblogo_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin logo`
liblogo_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin logo` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liblogo_plugin_la_LIBADD = $(LTLIBVLC)

liblogo_a_SOURCES = $(SOURCES_logo)
liblogo_builtin_la_SOURCES = $(SOURCES_logo)
liblogo_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic logo`
liblogo_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic logo`
liblogo_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic logo`
liblogo_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin logo`
liblogo_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin logo`
liblogo_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin logo`

# The deinterlace plugin

libdeinterlace_plugin_a_SOURCES = $(SOURCES_deinterlace)
libdeinterlace_plugin_la_SOURCES = $(SOURCES_deinterlace)
libdeinterlace_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin deinterlace`
libdeinterlace_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin deinterlace`
libdeinterlace_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin deinterlace`
libdeinterlace_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin deinterlace`
libdeinterlace_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin deinterlace`
libdeinterlace_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin deinterlace`
libdeinterlace_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin deinterlace` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdeinterlace_plugin_la_LIBADD = $(LTLIBVLC)

libdeinterlace_a_SOURCES = $(SOURCES_deinterlace)
libdeinterlace_builtin_la_SOURCES = $(SOURCES_deinterlace)
libdeinterlace_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic deinterlace`
libdeinterlace_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic deinterlace`
libdeinterlace_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic deinterlace`
libdeinterlace_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin deinterlace`
libdeinterlace_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin deinterlace`
libdeinterlace_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin deinterlace`

# The blend plugin

libblend_plugin_a_SOURCES = $(SOURCES_blend)
libblend_plugin_la_SOURCES = $(SOURCES_blend)
libblend_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin blend`
libblend_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin blend`
libblend_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin blend`
libblend_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin blend`
libblend_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin blend`
libblend_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin blend`
libblend_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin blend` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libblend_plugin_la_LIBADD = $(LTLIBVLC)

libblend_a_SOURCES = $(SOURCES_blend)
libblend_builtin_la_SOURCES = $(SOURCES_blend)
libblend_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic blend`
libblend_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic blend`
libblend_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic blend`
libblend_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin blend`
libblend_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin blend`
libblend_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin blend`

# The scale plugin

libscale_plugin_a_SOURCES = $(SOURCES_scale)
libscale_plugin_la_SOURCES = $(SOURCES_scale)
libscale_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin scale`
libscale_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin scale`
libscale_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin scale`
libscale_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin scale`
libscale_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin scale`
libscale_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin scale`
libscale_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin scale` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libscale_plugin_la_LIBADD = $(LTLIBVLC)

libscale_a_SOURCES = $(SOURCES_scale)
libscale_builtin_la_SOURCES = $(SOURCES_scale)
libscale_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic scale`
libscale_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic scale`
libscale_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic scale`
libscale_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin scale`
libscale_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin scale`
libscale_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin scale`

# The time plugin

libtime_plugin_a_SOURCES = $(SOURCES_time)
libtime_plugin_la_SOURCES = $(SOURCES_time)
libtime_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin time`
libtime_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin time`
libtime_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin time`
libtime_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin time`
libtime_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin time`
libtime_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin time`
libtime_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin time` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtime_plugin_la_LIBADD = $(LTLIBVLC)

libtime_a_SOURCES = $(SOURCES_time)
libtime_builtin_la_SOURCES = $(SOURCES_time)
libtime_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic time`
libtime_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic time`
libtime_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic time`
libtime_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin time`
libtime_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin time`
libtime_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin time`

# The marq plugin

libmarq_plugin_a_SOURCES = $(SOURCES_marq)
libmarq_plugin_la_SOURCES = $(SOURCES_marq)
libmarq_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin marq`
libmarq_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin marq`
libmarq_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin marq`
libmarq_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin marq`
libmarq_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin marq`
libmarq_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin marq`
libmarq_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin marq` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmarq_plugin_la_LIBADD = $(LTLIBVLC)

libmarq_a_SOURCES = $(SOURCES_marq)
libmarq_builtin_la_SOURCES = $(SOURCES_marq)
libmarq_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic marq`
libmarq_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic marq`
libmarq_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic marq`
libmarq_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin marq`
libmarq_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin marq`
libmarq_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin marq`

# The rss plugin

librss_plugin_a_SOURCES = $(SOURCES_rss)
librss_plugin_la_SOURCES = $(SOURCES_rss)
librss_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin rss`
librss_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rss`
librss_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rss`
librss_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin rss`
librss_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rss`
librss_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rss`
librss_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin rss` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
librss_plugin_la_LIBADD = $(LTLIBVLC)

librss_a_SOURCES = $(SOURCES_rss)
librss_builtin_la_SOURCES = $(SOURCES_rss)
librss_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic rss`
librss_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic rss`
librss_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic rss`
librss_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin rss`
librss_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin rss`
librss_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin rss`

# The motiondetect plugin

libmotiondetect_plugin_a_SOURCES = $(SOURCES_motiondetect)
libmotiondetect_plugin_la_SOURCES = $(SOURCES_motiondetect)
libmotiondetect_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin motiondetect`
libmotiondetect_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin motiondetect`
libmotiondetect_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin motiondetect`
libmotiondetect_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin motiondetect`
libmotiondetect_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin motiondetect`
libmotiondetect_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin motiondetect`
libmotiondetect_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin motiondetect` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmotiondetect_plugin_la_LIBADD = $(LTLIBVLC)

libmotiondetect_a_SOURCES = $(SOURCES_motiondetect)
libmotiondetect_builtin_la_SOURCES = $(SOURCES_motiondetect)
libmotiondetect_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic motiondetect`
libmotiondetect_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic motiondetect`
libmotiondetect_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic motiondetect`
libmotiondetect_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin motiondetect`
libmotiondetect_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin motiondetect`
libmotiondetect_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin motiondetect`

# The rv32 plugin

librv32_plugin_a_SOURCES = $(SOURCES_rv32)
librv32_plugin_la_SOURCES = $(SOURCES_rv32)
librv32_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin rv32`
librv32_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rv32`
librv32_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rv32`
librv32_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin rv32`
librv32_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rv32`
librv32_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rv32`
librv32_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin rv32` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
librv32_plugin_la_LIBADD = $(LTLIBVLC)

librv32_a_SOURCES = $(SOURCES_rv32)
librv32_builtin_la_SOURCES = $(SOURCES_rv32)
librv32_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic rv32`
librv32_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic rv32`
librv32_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic rv32`
librv32_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin rv32`
librv32_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin rv32`
librv32_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin rv32`

# The osdmenu plugin

libosdmenu_plugin_a_SOURCES = $(SOURCES_osdmenu)
libosdmenu_plugin_la_SOURCES = $(SOURCES_osdmenu)
libosdmenu_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin osdmenu`
libosdmenu_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin osdmenu`
libosdmenu_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin osdmenu`
libosdmenu_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin osdmenu`
libosdmenu_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin osdmenu`
libosdmenu_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin osdmenu`
libosdmenu_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin osdmenu` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libosdmenu_plugin_la_LIBADD = $(LTLIBVLC)

libosdmenu_a_SOURCES = $(SOURCES_osdmenu)
libosdmenu_builtin_la_SOURCES = $(SOURCES_osdmenu)
libosdmenu_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic osdmenu`
libosdmenu_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic osdmenu`
libosdmenu_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic osdmenu`
libosdmenu_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin osdmenu`
libosdmenu_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin osdmenu`
libosdmenu_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin osdmenu`

# The magnify plugin

libmagnify_plugin_a_SOURCES = $(SOURCES_magnify)
libmagnify_plugin_la_SOURCES = $(SOURCES_magnify)
libmagnify_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin magnify`
libmagnify_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin magnify`
libmagnify_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin magnify`
libmagnify_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin magnify`
libmagnify_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin magnify`
libmagnify_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin magnify`
libmagnify_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin magnify` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libmagnify_plugin_la_LIBADD = $(LTLIBVLC)

libmagnify_a_SOURCES = $(SOURCES_magnify)
libmagnify_builtin_la_SOURCES = $(SOURCES_magnify)
libmagnify_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic magnify`
libmagnify_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic magnify`
libmagnify_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic magnify`
libmagnify_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin magnify`
libmagnify_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin magnify`
libmagnify_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin magnify`

