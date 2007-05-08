
# modules/control/Makefile.am automatically generated from modules/control/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = control
mods = gestures showintf telnet netsync ntservice hotkeys lirc rc

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = http corba
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libgestures_plugin.a libgestures.a libshowintf_plugin.a libshowintf.a libtelnet_plugin.a libtelnet.a libnetsync_plugin.a libnetsync.a libntservice_plugin.a libntservice.a libhotkeys_plugin.a libhotkeys.a liblirc_plugin.a liblirc.a librc_plugin.a librc.a
EXTRA_LTLIBRARIES =  libgestures_plugin.la libgestures_builtin.la libshowintf_plugin.la libshowintf_builtin.la libtelnet_plugin.la libtelnet_builtin.la libnetsync_plugin.la libnetsync_builtin.la libntservice_plugin.la libntservice_builtin.la libhotkeys_plugin.la libhotkeys_builtin.la liblirc_plugin.la liblirc_builtin.la librc_plugin.la librc_builtin.la

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

# The gestures plugin

libgestures_plugin_a_SOURCES = $(SOURCES_gestures)
libgestures_plugin_la_SOURCES = $(SOURCES_gestures)
libgestures_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin gestures`
libgestures_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin gestures`
libgestures_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin gestures`
libgestures_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin gestures`
libgestures_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin gestures`
libgestures_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin gestures`
libgestures_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin gestures` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libgestures_plugin_la_LIBADD = $(LTLIBVLC)

libgestures_a_SOURCES = $(SOURCES_gestures)
libgestures_builtin_la_SOURCES = $(SOURCES_gestures)
libgestures_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic gestures`
libgestures_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic gestures`
libgestures_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic gestures`
libgestures_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin gestures`
libgestures_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin gestures`
libgestures_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin gestures`

# The showintf plugin

libshowintf_plugin_a_SOURCES = $(SOURCES_showintf)
libshowintf_plugin_la_SOURCES = $(SOURCES_showintf)
libshowintf_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin showintf`
libshowintf_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin showintf`
libshowintf_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin showintf`
libshowintf_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin showintf`
libshowintf_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin showintf`
libshowintf_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin showintf`
libshowintf_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin showintf` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libshowintf_plugin_la_LIBADD = $(LTLIBVLC)

libshowintf_a_SOURCES = $(SOURCES_showintf)
libshowintf_builtin_la_SOURCES = $(SOURCES_showintf)
libshowintf_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic showintf`
libshowintf_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic showintf`
libshowintf_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic showintf`
libshowintf_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin showintf`
libshowintf_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin showintf`
libshowintf_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin showintf`

# The telnet plugin

libtelnet_plugin_a_SOURCES = $(SOURCES_telnet)
libtelnet_plugin_la_SOURCES = $(SOURCES_telnet)
libtelnet_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin telnet`
libtelnet_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin telnet`
libtelnet_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin telnet`
libtelnet_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin telnet`
libtelnet_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin telnet`
libtelnet_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin telnet`
libtelnet_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin telnet` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtelnet_plugin_la_LIBADD = $(LTLIBVLC)

libtelnet_a_SOURCES = $(SOURCES_telnet)
libtelnet_builtin_la_SOURCES = $(SOURCES_telnet)
libtelnet_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic telnet`
libtelnet_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic telnet`
libtelnet_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic telnet`
libtelnet_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin telnet`
libtelnet_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin telnet`
libtelnet_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin telnet`

# The netsync plugin

libnetsync_plugin_a_SOURCES = $(SOURCES_netsync)
libnetsync_plugin_la_SOURCES = $(SOURCES_netsync)
libnetsync_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin netsync`
libnetsync_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin netsync`
libnetsync_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin netsync`
libnetsync_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin netsync`
libnetsync_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin netsync`
libnetsync_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin netsync`
libnetsync_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin netsync` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libnetsync_plugin_la_LIBADD = $(LTLIBVLC)

libnetsync_a_SOURCES = $(SOURCES_netsync)
libnetsync_builtin_la_SOURCES = $(SOURCES_netsync)
libnetsync_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic netsync`
libnetsync_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic netsync`
libnetsync_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic netsync`
libnetsync_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin netsync`
libnetsync_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin netsync`
libnetsync_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin netsync`

# The ntservice plugin

libntservice_plugin_a_SOURCES = $(SOURCES_ntservice)
libntservice_plugin_la_SOURCES = $(SOURCES_ntservice)
libntservice_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin ntservice`
libntservice_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ntservice`
libntservice_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ntservice`
libntservice_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin ntservice`
libntservice_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin ntservice`
libntservice_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin ntservice`
libntservice_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin ntservice` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libntservice_plugin_la_LIBADD = $(LTLIBVLC)

libntservice_a_SOURCES = $(SOURCES_ntservice)
libntservice_builtin_la_SOURCES = $(SOURCES_ntservice)
libntservice_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic ntservice`
libntservice_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic ntservice`
libntservice_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic ntservice`
libntservice_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin ntservice`
libntservice_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin ntservice`
libntservice_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin ntservice`

# The hotkeys plugin

libhotkeys_plugin_a_SOURCES = $(SOURCES_hotkeys)
libhotkeys_plugin_la_SOURCES = $(SOURCES_hotkeys)
libhotkeys_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin hotkeys`
libhotkeys_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hotkeys`
libhotkeys_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hotkeys`
libhotkeys_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin hotkeys`
libhotkeys_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin hotkeys`
libhotkeys_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin hotkeys`
libhotkeys_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin hotkeys` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libhotkeys_plugin_la_LIBADD = $(LTLIBVLC)

libhotkeys_a_SOURCES = $(SOURCES_hotkeys)
libhotkeys_builtin_la_SOURCES = $(SOURCES_hotkeys)
libhotkeys_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic hotkeys`
libhotkeys_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic hotkeys`
libhotkeys_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic hotkeys`
libhotkeys_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin hotkeys`
libhotkeys_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin hotkeys`
libhotkeys_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin hotkeys`

# The lirc plugin

liblirc_plugin_a_SOURCES = $(SOURCES_lirc)
liblirc_plugin_la_SOURCES = $(SOURCES_lirc)
liblirc_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin lirc`
liblirc_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin lirc`
liblirc_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin lirc`
liblirc_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin lirc`
liblirc_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin lirc`
liblirc_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin lirc`
liblirc_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin lirc` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
liblirc_plugin_la_LIBADD = $(LTLIBVLC)

liblirc_a_SOURCES = $(SOURCES_lirc)
liblirc_builtin_la_SOURCES = $(SOURCES_lirc)
liblirc_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic lirc`
liblirc_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic lirc`
liblirc_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic lirc`
liblirc_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin lirc`
liblirc_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin lirc`
liblirc_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin lirc`

# The rc plugin

librc_plugin_a_SOURCES = $(SOURCES_rc)
librc_plugin_la_SOURCES = $(SOURCES_rc)
librc_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin rc`
librc_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rc`
librc_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rc`
librc_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin rc`
librc_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin rc`
librc_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin rc`
librc_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin rc` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
librc_plugin_la_LIBADD = $(LTLIBVLC)

librc_a_SOURCES = $(SOURCES_rc)
librc_builtin_la_SOURCES = $(SOURCES_rc)
librc_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic rc`
librc_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic rc`
librc_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic rc`
librc_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin rc`
librc_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin rc`
librc_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin rc`

