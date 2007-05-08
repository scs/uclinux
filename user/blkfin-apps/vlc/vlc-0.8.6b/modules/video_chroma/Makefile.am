
# modules/video_chroma/Makefile.am automatically generated from modules/video_chroma/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = video_chroma
mods = i420_rgb i420_rgb_mmx i420_yuy2 i420_yuy2_mmx i420_yuy2_altivec i422_yuy2 i422_yuy2_mmx i420_ymga i420_ymga_mmx

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libi420_rgb_plugin.a libi420_rgb.a libi420_rgb_mmx_plugin.a libi420_rgb_mmx.a libi420_yuy2_plugin.a libi420_yuy2.a libi420_yuy2_mmx_plugin.a libi420_yuy2_mmx.a libi420_yuy2_altivec_plugin.a libi420_yuy2_altivec.a libi422_yuy2_plugin.a libi422_yuy2.a libi422_yuy2_mmx_plugin.a libi422_yuy2_mmx.a libi420_ymga_plugin.a libi420_ymga.a libi420_ymga_mmx_plugin.a libi420_ymga_mmx.a
EXTRA_LTLIBRARIES =  libi420_rgb_plugin.la libi420_rgb_builtin.la libi420_rgb_mmx_plugin.la libi420_rgb_mmx_builtin.la libi420_yuy2_plugin.la libi420_yuy2_builtin.la libi420_yuy2_mmx_plugin.la libi420_yuy2_mmx_builtin.la libi420_yuy2_altivec_plugin.la libi420_yuy2_altivec_builtin.la libi422_yuy2_plugin.la libi422_yuy2_builtin.la libi422_yuy2_mmx_plugin.la libi422_yuy2_mmx_builtin.la libi420_ymga_plugin.la libi420_ymga_builtin.la libi420_ymga_mmx_plugin.la libi420_ymga_mmx_builtin.la

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

# The i420_rgb plugin

libi420_rgb_plugin_a_SOURCES = $(SOURCES_i420_rgb)
libi420_rgb_plugin_la_SOURCES = $(SOURCES_i420_rgb)
libi420_rgb_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_rgb`
libi420_rgb_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_rgb`
libi420_rgb_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_rgb`
libi420_rgb_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_rgb`
libi420_rgb_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_rgb`
libi420_rgb_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_rgb`
libi420_rgb_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_rgb` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_rgb_plugin_la_LIBADD = $(LTLIBVLC)

libi420_rgb_a_SOURCES = $(SOURCES_i420_rgb)
libi420_rgb_builtin_la_SOURCES = $(SOURCES_i420_rgb)
libi420_rgb_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_rgb`
libi420_rgb_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_rgb`
libi420_rgb_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_rgb`
libi420_rgb_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_rgb`
libi420_rgb_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_rgb`
libi420_rgb_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_rgb`

# The i420_rgb_mmx plugin

libi420_rgb_mmx_plugin_a_SOURCES = $(SOURCES_i420_rgb_mmx)
libi420_rgb_mmx_plugin_la_SOURCES = $(SOURCES_i420_rgb_mmx)
libi420_rgb_mmx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_rgb_mmx`
libi420_rgb_mmx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_rgb_mmx`
libi420_rgb_mmx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_rgb_mmx`
libi420_rgb_mmx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_rgb_mmx`
libi420_rgb_mmx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_rgb_mmx`
libi420_rgb_mmx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_rgb_mmx`
libi420_rgb_mmx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_rgb_mmx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_rgb_mmx_plugin_la_LIBADD = $(LTLIBVLC)

libi420_rgb_mmx_a_SOURCES = $(SOURCES_i420_rgb_mmx)
libi420_rgb_mmx_builtin_la_SOURCES = $(SOURCES_i420_rgb_mmx)
libi420_rgb_mmx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_rgb_mmx`
libi420_rgb_mmx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_rgb_mmx`
libi420_rgb_mmx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_rgb_mmx`
libi420_rgb_mmx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_rgb_mmx`
libi420_rgb_mmx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_rgb_mmx`
libi420_rgb_mmx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_rgb_mmx`

# The i420_yuy2 plugin

libi420_yuy2_plugin_a_SOURCES = $(SOURCES_i420_yuy2)
libi420_yuy2_plugin_la_SOURCES = $(SOURCES_i420_yuy2)
libi420_yuy2_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_yuy2`
libi420_yuy2_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_yuy2`
libi420_yuy2_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_yuy2`
libi420_yuy2_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_yuy2`
libi420_yuy2_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_yuy2`
libi420_yuy2_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_yuy2`
libi420_yuy2_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_yuy2` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_yuy2_plugin_la_LIBADD = $(LTLIBVLC)

libi420_yuy2_a_SOURCES = $(SOURCES_i420_yuy2)
libi420_yuy2_builtin_la_SOURCES = $(SOURCES_i420_yuy2)
libi420_yuy2_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_yuy2`
libi420_yuy2_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_yuy2`
libi420_yuy2_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_yuy2`
libi420_yuy2_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_yuy2`
libi420_yuy2_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_yuy2`
libi420_yuy2_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_yuy2`

# The i420_yuy2_mmx plugin

libi420_yuy2_mmx_plugin_a_SOURCES = $(SOURCES_i420_yuy2_mmx)
libi420_yuy2_mmx_plugin_la_SOURCES = $(SOURCES_i420_yuy2_mmx)
libi420_yuy2_mmx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_yuy2_mmx`
libi420_yuy2_mmx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_yuy2_mmx`
libi420_yuy2_mmx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_yuy2_mmx`
libi420_yuy2_mmx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_yuy2_mmx`
libi420_yuy2_mmx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_yuy2_mmx`
libi420_yuy2_mmx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_yuy2_mmx`
libi420_yuy2_mmx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_yuy2_mmx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_yuy2_mmx_plugin_la_LIBADD = $(LTLIBVLC)

libi420_yuy2_mmx_a_SOURCES = $(SOURCES_i420_yuy2_mmx)
libi420_yuy2_mmx_builtin_la_SOURCES = $(SOURCES_i420_yuy2_mmx)
libi420_yuy2_mmx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_yuy2_mmx`
libi420_yuy2_mmx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_yuy2_mmx`
libi420_yuy2_mmx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_yuy2_mmx`
libi420_yuy2_mmx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_yuy2_mmx`
libi420_yuy2_mmx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_yuy2_mmx`
libi420_yuy2_mmx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_yuy2_mmx`

# The i420_yuy2_altivec plugin

libi420_yuy2_altivec_plugin_a_SOURCES = $(SOURCES_i420_yuy2_altivec)
libi420_yuy2_altivec_plugin_la_SOURCES = $(SOURCES_i420_yuy2_altivec)
libi420_yuy2_altivec_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_yuy2_altivec`
libi420_yuy2_altivec_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_yuy2_altivec`
libi420_yuy2_altivec_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_yuy2_altivec`
libi420_yuy2_altivec_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_yuy2_altivec`
libi420_yuy2_altivec_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_yuy2_altivec`
libi420_yuy2_altivec_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_yuy2_altivec`
libi420_yuy2_altivec_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_yuy2_altivec` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_yuy2_altivec_plugin_la_LIBADD = $(LTLIBVLC)

libi420_yuy2_altivec_a_SOURCES = $(SOURCES_i420_yuy2_altivec)
libi420_yuy2_altivec_builtin_la_SOURCES = $(SOURCES_i420_yuy2_altivec)
libi420_yuy2_altivec_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_yuy2_altivec`
libi420_yuy2_altivec_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_yuy2_altivec`
libi420_yuy2_altivec_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_yuy2_altivec`
libi420_yuy2_altivec_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_yuy2_altivec`
libi420_yuy2_altivec_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_yuy2_altivec`
libi420_yuy2_altivec_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_yuy2_altivec`

# The i422_yuy2 plugin

libi422_yuy2_plugin_a_SOURCES = $(SOURCES_i422_yuy2)
libi422_yuy2_plugin_la_SOURCES = $(SOURCES_i422_yuy2)
libi422_yuy2_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i422_yuy2`
libi422_yuy2_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i422_yuy2`
libi422_yuy2_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i422_yuy2`
libi422_yuy2_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i422_yuy2`
libi422_yuy2_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i422_yuy2`
libi422_yuy2_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i422_yuy2`
libi422_yuy2_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i422_yuy2` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi422_yuy2_plugin_la_LIBADD = $(LTLIBVLC)

libi422_yuy2_a_SOURCES = $(SOURCES_i422_yuy2)
libi422_yuy2_builtin_la_SOURCES = $(SOURCES_i422_yuy2)
libi422_yuy2_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i422_yuy2`
libi422_yuy2_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i422_yuy2`
libi422_yuy2_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i422_yuy2`
libi422_yuy2_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i422_yuy2`
libi422_yuy2_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i422_yuy2`
libi422_yuy2_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i422_yuy2`

# The i422_yuy2_mmx plugin

libi422_yuy2_mmx_plugin_a_SOURCES = $(SOURCES_i422_yuy2_mmx)
libi422_yuy2_mmx_plugin_la_SOURCES = $(SOURCES_i422_yuy2_mmx)
libi422_yuy2_mmx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i422_yuy2_mmx`
libi422_yuy2_mmx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i422_yuy2_mmx`
libi422_yuy2_mmx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i422_yuy2_mmx`
libi422_yuy2_mmx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i422_yuy2_mmx`
libi422_yuy2_mmx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i422_yuy2_mmx`
libi422_yuy2_mmx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i422_yuy2_mmx`
libi422_yuy2_mmx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i422_yuy2_mmx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi422_yuy2_mmx_plugin_la_LIBADD = $(LTLIBVLC)

libi422_yuy2_mmx_a_SOURCES = $(SOURCES_i422_yuy2_mmx)
libi422_yuy2_mmx_builtin_la_SOURCES = $(SOURCES_i422_yuy2_mmx)
libi422_yuy2_mmx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i422_yuy2_mmx`
libi422_yuy2_mmx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i422_yuy2_mmx`
libi422_yuy2_mmx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i422_yuy2_mmx`
libi422_yuy2_mmx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i422_yuy2_mmx`
libi422_yuy2_mmx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i422_yuy2_mmx`
libi422_yuy2_mmx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i422_yuy2_mmx`

# The i420_ymga plugin

libi420_ymga_plugin_a_SOURCES = $(SOURCES_i420_ymga)
libi420_ymga_plugin_la_SOURCES = $(SOURCES_i420_ymga)
libi420_ymga_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_ymga`
libi420_ymga_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_ymga`
libi420_ymga_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_ymga`
libi420_ymga_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_ymga`
libi420_ymga_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_ymga`
libi420_ymga_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_ymga`
libi420_ymga_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_ymga` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_ymga_plugin_la_LIBADD = $(LTLIBVLC)

libi420_ymga_a_SOURCES = $(SOURCES_i420_ymga)
libi420_ymga_builtin_la_SOURCES = $(SOURCES_i420_ymga)
libi420_ymga_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_ymga`
libi420_ymga_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_ymga`
libi420_ymga_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_ymga`
libi420_ymga_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_ymga`
libi420_ymga_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_ymga`
libi420_ymga_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_ymga`

# The i420_ymga_mmx plugin

libi420_ymga_mmx_plugin_a_SOURCES = $(SOURCES_i420_ymga_mmx)
libi420_ymga_mmx_plugin_la_SOURCES = $(SOURCES_i420_ymga_mmx)
libi420_ymga_mmx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_ymga_mmx`
libi420_ymga_mmx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_ymga_mmx`
libi420_ymga_mmx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_ymga_mmx`
libi420_ymga_mmx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin i420_ymga_mmx`
libi420_ymga_mmx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin i420_ymga_mmx`
libi420_ymga_mmx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin i420_ymga_mmx`
libi420_ymga_mmx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin i420_ymga_mmx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libi420_ymga_mmx_plugin_la_LIBADD = $(LTLIBVLC)

libi420_ymga_mmx_a_SOURCES = $(SOURCES_i420_ymga_mmx)
libi420_ymga_mmx_builtin_la_SOURCES = $(SOURCES_i420_ymga_mmx)
libi420_ymga_mmx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic i420_ymga_mmx`
libi420_ymga_mmx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic i420_ymga_mmx`
libi420_ymga_mmx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic i420_ymga_mmx`
libi420_ymga_mmx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin i420_ymga_mmx`
libi420_ymga_mmx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin i420_ymga_mmx`
libi420_ymga_mmx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin i420_ymga_mmx`

