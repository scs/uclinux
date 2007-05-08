
# modules/services_discovery/Makefile.am automatically generated from modules/services_discovery/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = services_discovery
mods = sap hal daap shout upnp_cc upnp_intel bonjour podcast

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libsap_plugin.a libsap.a libhal_plugin.a libhal.a libdaap_plugin.a libdaap.a libshout_plugin.a libshout.a libupnp_cc_plugin.a libupnp_cc.a libupnp_intel_plugin.a libupnp_intel.a libbonjour_plugin.a libbonjour.a libpodcast_plugin.a libpodcast.a
EXTRA_LTLIBRARIES =  libsap_plugin.la libsap_builtin.la libhal_plugin.la libhal_builtin.la libdaap_plugin.la libdaap_builtin.la libshout_plugin.la libshout_builtin.la libupnp_cc_plugin.la libupnp_cc_builtin.la libupnp_intel_plugin.la libupnp_intel_builtin.la libbonjour_plugin.la libbonjour_builtin.la libpodcast_plugin.la libpodcast_builtin.la

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

# The sap plugin

libsap_plugin_a_SOURCES = $(SOURCES_sap)
libsap_plugin_la_SOURCES = $(SOURCES_sap)
libsap_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin sap`
libsap_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin sap`
libsap_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin sap`
libsap_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin sap`
libsap_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin sap`
libsap_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin sap`
libsap_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin sap` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libsap_plugin_la_LIBADD = $(LTLIBVLC)

libsap_a_SOURCES = $(SOURCES_sap)
libsap_builtin_la_SOURCES = $(SOURCES_sap)
libsap_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic sap`
libsap_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic sap`
libsap_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic sap`
libsap_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin sap`
libsap_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin sap`
libsap_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin sap`

# The hal plugin

libhal_plugin_a_SOURCES = $(SOURCES_hal)
libhal_plugin_la_SOURCES = $(SOURCES_hal)
libhal_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin hal`
libhal_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hal`
libhal_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hal`
libhal_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin hal`
libhal_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hal`
libhal_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hal`
libhal_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin hal` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libhal_plugin_la_LIBADD = $(LTLIBVLC)

libhal_a_SOURCES = $(SOURCES_hal)
libhal_builtin_la_SOURCES = $(SOURCES_hal)
libhal_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic hal`
libhal_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic hal`
libhal_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic hal`
libhal_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin hal`
libhal_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin hal`
libhal_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin hal`

# The daap plugin

libdaap_plugin_a_SOURCES = $(SOURCES_daap)
libdaap_plugin_la_SOURCES = $(SOURCES_daap)
libdaap_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin daap`
libdaap_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin daap`
libdaap_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin daap`
libdaap_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin daap`
libdaap_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin daap`
libdaap_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin daap`
libdaap_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin daap` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdaap_plugin_la_LIBADD = $(LTLIBVLC)

libdaap_a_SOURCES = $(SOURCES_daap)
libdaap_builtin_la_SOURCES = $(SOURCES_daap)
libdaap_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic daap`
libdaap_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic daap`
libdaap_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic daap`
libdaap_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin daap`
libdaap_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin daap`
libdaap_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin daap`

# The shout plugin

libshout_plugin_a_SOURCES = $(SOURCES_shout)
libshout_plugin_la_SOURCES = $(SOURCES_shout)
libshout_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin shout`
libshout_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin shout`
libshout_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin shout`
libshout_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin shout`
libshout_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin shout`
libshout_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin shout`
libshout_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin shout` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libshout_plugin_la_LIBADD = $(LTLIBVLC)

libshout_a_SOURCES = $(SOURCES_shout)
libshout_builtin_la_SOURCES = $(SOURCES_shout)
libshout_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic shout`
libshout_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic shout`
libshout_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic shout`
libshout_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin shout`
libshout_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin shout`
libshout_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin shout`

# The upnp_cc plugin

libupnp_cc_plugin_a_SOURCES = $(SOURCES_upnp_cc)
libupnp_cc_plugin_la_SOURCES = $(SOURCES_upnp_cc)
libupnp_cc_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin upnp_cc`
libupnp_cc_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin upnp_cc`
libupnp_cc_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin upnp_cc`
libupnp_cc_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin upnp_cc`
libupnp_cc_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin upnp_cc`
libupnp_cc_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin upnp_cc`
libupnp_cc_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin upnp_cc` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libupnp_cc_plugin_la_LIBADD = $(LTLIBVLC)

libupnp_cc_a_SOURCES = $(SOURCES_upnp_cc)
libupnp_cc_builtin_la_SOURCES = $(SOURCES_upnp_cc)
libupnp_cc_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic upnp_cc`
libupnp_cc_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic upnp_cc`
libupnp_cc_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic upnp_cc`
libupnp_cc_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin upnp_cc`
libupnp_cc_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin upnp_cc`
libupnp_cc_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin upnp_cc`

# The upnp_intel plugin

libupnp_intel_plugin_a_SOURCES = $(SOURCES_upnp_intel)
libupnp_intel_plugin_la_SOURCES = $(SOURCES_upnp_intel)
libupnp_intel_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin upnp_intel`
libupnp_intel_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin upnp_intel`
libupnp_intel_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin upnp_intel`
libupnp_intel_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin upnp_intel`
libupnp_intel_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin upnp_intel`
libupnp_intel_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin upnp_intel`
libupnp_intel_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin upnp_intel` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libupnp_intel_plugin_la_LIBADD = $(LTLIBVLC)

libupnp_intel_a_SOURCES = $(SOURCES_upnp_intel)
libupnp_intel_builtin_la_SOURCES = $(SOURCES_upnp_intel)
libupnp_intel_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic upnp_intel`
libupnp_intel_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic upnp_intel`
libupnp_intel_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic upnp_intel`
libupnp_intel_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin upnp_intel`
libupnp_intel_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin upnp_intel`
libupnp_intel_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin upnp_intel`

# The bonjour plugin

libbonjour_plugin_a_SOURCES = $(SOURCES_bonjour)
libbonjour_plugin_la_SOURCES = $(SOURCES_bonjour)
libbonjour_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin bonjour`
libbonjour_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin bonjour`
libbonjour_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin bonjour`
libbonjour_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin bonjour`
libbonjour_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin bonjour`
libbonjour_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin bonjour`
libbonjour_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin bonjour` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libbonjour_plugin_la_LIBADD = $(LTLIBVLC)

libbonjour_a_SOURCES = $(SOURCES_bonjour)
libbonjour_builtin_la_SOURCES = $(SOURCES_bonjour)
libbonjour_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic bonjour`
libbonjour_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic bonjour`
libbonjour_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic bonjour`
libbonjour_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin bonjour`
libbonjour_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin bonjour`
libbonjour_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin bonjour`

# The podcast plugin

libpodcast_plugin_a_SOURCES = $(SOURCES_podcast)
libpodcast_plugin_la_SOURCES = $(SOURCES_podcast)
libpodcast_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin podcast`
libpodcast_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin podcast`
libpodcast_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin podcast`
libpodcast_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin podcast`
libpodcast_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin podcast`
libpodcast_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin podcast`
libpodcast_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin podcast` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libpodcast_plugin_la_LIBADD = $(LTLIBVLC)

libpodcast_a_SOURCES = $(SOURCES_podcast)
libpodcast_builtin_la_SOURCES = $(SOURCES_podcast)
libpodcast_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic podcast`
libpodcast_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic podcast`
libpodcast_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic podcast`
libpodcast_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin podcast`
libpodcast_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin podcast`
libpodcast_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin podcast`

