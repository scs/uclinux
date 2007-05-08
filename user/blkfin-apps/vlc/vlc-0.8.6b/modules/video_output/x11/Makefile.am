
# modules/video_output/x11/Makefile.am automatically generated from modules/video_output/x11/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = video_output
mods = x11 xvideo glx

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libx11_plugin.a libx11.a libxvideo_plugin.a libxvideo.a libglx_plugin.a libglx.a
EXTRA_LTLIBRARIES =  libx11_plugin.la libx11_builtin.la libxvideo_plugin.la libxvideo_builtin.la libglx_plugin.la libglx_builtin.la

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

# The x11 plugin

libx11_plugin_a_SOURCES = $(SOURCES_x11)
libx11_plugin_la_SOURCES = $(SOURCES_x11)
libx11_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin x11`
libx11_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin x11`
libx11_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin x11`
libx11_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin x11`
libx11_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin x11`
libx11_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin x11`
libx11_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin x11` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libx11_plugin_la_LIBADD = $(LTLIBVLC)

libx11_a_SOURCES = $(SOURCES_x11)
libx11_builtin_la_SOURCES = $(SOURCES_x11)
libx11_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic x11`
libx11_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic x11`
libx11_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic x11`
libx11_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin x11`
libx11_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin x11`
libx11_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin x11`

# The xvideo plugin

libxvideo_plugin_a_SOURCES = $(SOURCES_xvideo)
libxvideo_plugin_la_SOURCES = $(SOURCES_xvideo)
libxvideo_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin xvideo`
libxvideo_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin xvideo`
libxvideo_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin xvideo`
libxvideo_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin xvideo`
libxvideo_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin xvideo`
libxvideo_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin xvideo`
libxvideo_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin xvideo` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libxvideo_plugin_la_LIBADD = $(LTLIBVLC)

libxvideo_a_SOURCES = $(SOURCES_xvideo)
libxvideo_builtin_la_SOURCES = $(SOURCES_xvideo)
libxvideo_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic xvideo`
libxvideo_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic xvideo`
libxvideo_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic xvideo`
libxvideo_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin xvideo`
libxvideo_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin xvideo`
libxvideo_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin xvideo`

# The glx plugin

libglx_plugin_a_SOURCES = $(SOURCES_glx)
libglx_plugin_la_SOURCES = $(SOURCES_glx)
libglx_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin glx`
libglx_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin glx`
libglx_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin glx`
libglx_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin glx`
libglx_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin glx`
libglx_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin glx`
libglx_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin glx` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libglx_plugin_la_LIBADD = $(LTLIBVLC)

libglx_a_SOURCES = $(SOURCES_glx)
libglx_builtin_la_SOURCES = $(SOURCES_glx)
libglx_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic glx`
libglx_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic glx`
libglx_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic glx`
libglx_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin glx`
libglx_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin glx`
libglx_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin glx`

