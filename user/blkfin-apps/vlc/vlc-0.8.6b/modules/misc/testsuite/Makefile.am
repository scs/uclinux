
# modules/misc/testsuite/Makefile.am automatically generated from modules/misc/testsuite/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = misc
mods = test1 test2 test3 test4 test_playlist

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = 
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libtest1_plugin.a libtest1.a libtest2_plugin.a libtest2.a libtest3_plugin.a libtest3.a libtest4_plugin.a libtest4.a libtest_playlist_plugin.a libtest_playlist.a
EXTRA_LTLIBRARIES =  libtest1_plugin.la libtest1_builtin.la libtest2_plugin.la libtest2_builtin.la libtest3_plugin.la libtest3_builtin.la libtest4_plugin.la libtest4_builtin.la libtest_playlist_plugin.la libtest_playlist_builtin.la

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

# The test1 plugin

libtest1_plugin_a_SOURCES = $(SOURCES_test1)
libtest1_plugin_la_SOURCES = $(SOURCES_test1)
libtest1_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin test1`
libtest1_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test1`
libtest1_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test1`
libtest1_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin test1`
libtest1_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test1`
libtest1_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test1`
libtest1_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin test1` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtest1_plugin_la_LIBADD = $(LTLIBVLC)

libtest1_a_SOURCES = $(SOURCES_test1)
libtest1_builtin_la_SOURCES = $(SOURCES_test1)
libtest1_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic test1`
libtest1_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic test1`
libtest1_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic test1`
libtest1_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin test1`
libtest1_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin test1`
libtest1_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin test1`

# The test2 plugin

libtest2_plugin_a_SOURCES = $(SOURCES_test2)
libtest2_plugin_la_SOURCES = $(SOURCES_test2)
libtest2_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin test2`
libtest2_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test2`
libtest2_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test2`
libtest2_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin test2`
libtest2_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test2`
libtest2_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test2`
libtest2_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin test2` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtest2_plugin_la_LIBADD = $(LTLIBVLC)

libtest2_a_SOURCES = $(SOURCES_test2)
libtest2_builtin_la_SOURCES = $(SOURCES_test2)
libtest2_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic test2`
libtest2_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic test2`
libtest2_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic test2`
libtest2_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin test2`
libtest2_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin test2`
libtest2_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin test2`

# The test3 plugin

libtest3_plugin_a_SOURCES = $(SOURCES_test3)
libtest3_plugin_la_SOURCES = $(SOURCES_test3)
libtest3_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin test3`
libtest3_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test3`
libtest3_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test3`
libtest3_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin test3`
libtest3_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test3`
libtest3_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test3`
libtest3_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin test3` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtest3_plugin_la_LIBADD = $(LTLIBVLC)

libtest3_a_SOURCES = $(SOURCES_test3)
libtest3_builtin_la_SOURCES = $(SOURCES_test3)
libtest3_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic test3`
libtest3_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic test3`
libtest3_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic test3`
libtest3_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin test3`
libtest3_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin test3`
libtest3_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin test3`

# The test4 plugin

libtest4_plugin_a_SOURCES = $(SOURCES_test4)
libtest4_plugin_la_SOURCES = $(SOURCES_test4)
libtest4_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin test4`
libtest4_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test4`
libtest4_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test4`
libtest4_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin test4`
libtest4_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test4`
libtest4_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test4`
libtest4_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin test4` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtest4_plugin_la_LIBADD = $(LTLIBVLC)

libtest4_a_SOURCES = $(SOURCES_test4)
libtest4_builtin_la_SOURCES = $(SOURCES_test4)
libtest4_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic test4`
libtest4_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic test4`
libtest4_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic test4`
libtest4_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin test4`
libtest4_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin test4`
libtest4_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin test4`

# The test_playlist plugin

libtest_playlist_plugin_a_SOURCES = $(SOURCES_test_playlist)
libtest_playlist_plugin_la_SOURCES = $(SOURCES_test_playlist)
libtest_playlist_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin test_playlist`
libtest_playlist_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test_playlist`
libtest_playlist_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test_playlist`
libtest_playlist_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin test_playlist`
libtest_playlist_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin test_playlist`
libtest_playlist_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin test_playlist`
libtest_playlist_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin test_playlist` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libtest_playlist_plugin_la_LIBADD = $(LTLIBVLC)

libtest_playlist_a_SOURCES = $(SOURCES_test_playlist)
libtest_playlist_builtin_la_SOURCES = $(SOURCES_test_playlist)
libtest_playlist_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic test_playlist`
libtest_playlist_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic test_playlist`
libtest_playlist_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic test_playlist`
libtest_playlist_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin test_playlist`
libtest_playlist_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin test_playlist`
libtest_playlist_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin test_playlist`

