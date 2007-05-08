
# modules/access/Makefile.am automatically generated from modules/access/Modules.am by bootstrap
# DO NOT EDIT - edit Modules.am or $(top_srcdir)/bootstrap instead

basedir = access
mods = access_file access_directory access_dv access_udp access_tcp access_http access_ftp access_smb access_gnomevfs dvdnav dvdread dc1394 access_fake cdda

NULL =
libvlc_LTLIBRARIES =
noinst_LTLIBRARIES =
EXTRA_DIST = Modules.am
BUILT_SOURCES =
clean_modules =
SUBDIRS = dshow dvb mms pvr v4l cdda rtsp vcd vcdx screen
SUFFIXES = _plugin$(LIBEXT) _plugin.a

libvlcdir = $(libdir)/vlc/$(basedir)

EXTRA_LIBRARIES =  libaccess_file_plugin.a libaccess_file.a libaccess_directory_plugin.a libaccess_directory.a libaccess_dv_plugin.a libaccess_dv.a libaccess_udp_plugin.a libaccess_udp.a libaccess_tcp_plugin.a libaccess_tcp.a libaccess_http_plugin.a libaccess_http.a libaccess_ftp_plugin.a libaccess_ftp.a libaccess_smb_plugin.a libaccess_smb.a libaccess_gnomevfs_plugin.a libaccess_gnomevfs.a libdvdnav_plugin.a libdvdnav.a libdvdread_plugin.a libdvdread.a libdc1394_plugin.a libdc1394.a libaccess_fake_plugin.a libaccess_fake.a libcdda_plugin.a libcdda.a
EXTRA_LTLIBRARIES =  libaccess_file_plugin.la libaccess_file_builtin.la libaccess_directory_plugin.la libaccess_directory_builtin.la libaccess_dv_plugin.la libaccess_dv_builtin.la libaccess_udp_plugin.la libaccess_udp_builtin.la libaccess_tcp_plugin.la libaccess_tcp_builtin.la libaccess_http_plugin.la libaccess_http_builtin.la libaccess_ftp_plugin.la libaccess_ftp_builtin.la libaccess_smb_plugin.la libaccess_smb_builtin.la libaccess_gnomevfs_plugin.la libaccess_gnomevfs_builtin.la libdvdnav_plugin.la libdvdnav_builtin.la libdvdread_plugin.la libdvdread_builtin.la libdc1394_plugin.la libdc1394_builtin.la libaccess_fake_plugin.la libaccess_fake_builtin.la libcdda_plugin.la libcdda_builtin.la

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

# The access_file plugin

libaccess_file_plugin_a_SOURCES = $(SOURCES_access_file)
libaccess_file_plugin_la_SOURCES = $(SOURCES_access_file)
libaccess_file_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_file`
libaccess_file_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_file`
libaccess_file_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_file`
libaccess_file_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_file`
libaccess_file_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_file`
libaccess_file_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_file`
libaccess_file_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_file` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_file_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_file_a_SOURCES = $(SOURCES_access_file)
libaccess_file_builtin_la_SOURCES = $(SOURCES_access_file)
libaccess_file_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_file`
libaccess_file_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_file`
libaccess_file_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_file`
libaccess_file_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_file`
libaccess_file_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_file`
libaccess_file_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_file`

# The access_directory plugin

libaccess_directory_plugin_a_SOURCES = $(SOURCES_access_directory)
libaccess_directory_plugin_la_SOURCES = $(SOURCES_access_directory)
libaccess_directory_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_directory`
libaccess_directory_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_directory`
libaccess_directory_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_directory`
libaccess_directory_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_directory`
libaccess_directory_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_directory`
libaccess_directory_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_directory`
libaccess_directory_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_directory` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_directory_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_directory_a_SOURCES = $(SOURCES_access_directory)
libaccess_directory_builtin_la_SOURCES = $(SOURCES_access_directory)
libaccess_directory_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_directory`
libaccess_directory_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_directory`
libaccess_directory_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_directory`
libaccess_directory_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_directory`
libaccess_directory_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_directory`
libaccess_directory_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_directory`

# The access_dv plugin

libaccess_dv_plugin_a_SOURCES = $(SOURCES_access_dv)
libaccess_dv_plugin_la_SOURCES = $(SOURCES_access_dv)
libaccess_dv_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_dv`
libaccess_dv_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_dv`
libaccess_dv_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_dv`
libaccess_dv_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_dv`
libaccess_dv_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_dv`
libaccess_dv_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_dv`
libaccess_dv_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_dv` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_dv_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_dv_a_SOURCES = $(SOURCES_access_dv)
libaccess_dv_builtin_la_SOURCES = $(SOURCES_access_dv)
libaccess_dv_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_dv`
libaccess_dv_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_dv`
libaccess_dv_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_dv`
libaccess_dv_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_dv`
libaccess_dv_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_dv`
libaccess_dv_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_dv`

# The access_udp plugin

libaccess_udp_plugin_a_SOURCES = $(SOURCES_access_udp)
libaccess_udp_plugin_la_SOURCES = $(SOURCES_access_udp)
libaccess_udp_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_udp`
libaccess_udp_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_udp`
libaccess_udp_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_udp`
libaccess_udp_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_udp`
libaccess_udp_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_udp`
libaccess_udp_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_udp`
libaccess_udp_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_udp` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_udp_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_udp_a_SOURCES = $(SOURCES_access_udp)
libaccess_udp_builtin_la_SOURCES = $(SOURCES_access_udp)
libaccess_udp_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_udp`
libaccess_udp_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_udp`
libaccess_udp_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_udp`
libaccess_udp_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_udp`
libaccess_udp_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_udp`
libaccess_udp_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_udp`

# The access_tcp plugin

libaccess_tcp_plugin_a_SOURCES = $(SOURCES_access_tcp)
libaccess_tcp_plugin_la_SOURCES = $(SOURCES_access_tcp)
libaccess_tcp_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_tcp`
libaccess_tcp_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_tcp`
libaccess_tcp_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_tcp`
libaccess_tcp_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_tcp`
libaccess_tcp_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_tcp`
libaccess_tcp_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_tcp`
libaccess_tcp_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_tcp` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_tcp_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_tcp_a_SOURCES = $(SOURCES_access_tcp)
libaccess_tcp_builtin_la_SOURCES = $(SOURCES_access_tcp)
libaccess_tcp_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_tcp`
libaccess_tcp_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_tcp`
libaccess_tcp_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_tcp`
libaccess_tcp_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_tcp`
libaccess_tcp_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_tcp`
libaccess_tcp_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_tcp`

# The access_http plugin

libaccess_http_plugin_a_SOURCES = $(SOURCES_access_http)
libaccess_http_plugin_la_SOURCES = $(SOURCES_access_http)
libaccess_http_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_http`
libaccess_http_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_http`
libaccess_http_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_http`
libaccess_http_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_http`
libaccess_http_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_http`
libaccess_http_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_http`
libaccess_http_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_http` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_http_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_http_a_SOURCES = $(SOURCES_access_http)
libaccess_http_builtin_la_SOURCES = $(SOURCES_access_http)
libaccess_http_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_http`
libaccess_http_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_http`
libaccess_http_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_http`
libaccess_http_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_http`
libaccess_http_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_http`
libaccess_http_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_http`

# The access_ftp plugin

libaccess_ftp_plugin_a_SOURCES = $(SOURCES_access_ftp)
libaccess_ftp_plugin_la_SOURCES = $(SOURCES_access_ftp)
libaccess_ftp_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_ftp`
libaccess_ftp_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_ftp`
libaccess_ftp_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_ftp`
libaccess_ftp_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_ftp`
libaccess_ftp_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_ftp`
libaccess_ftp_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_ftp`
libaccess_ftp_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_ftp` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_ftp_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_ftp_a_SOURCES = $(SOURCES_access_ftp)
libaccess_ftp_builtin_la_SOURCES = $(SOURCES_access_ftp)
libaccess_ftp_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_ftp`
libaccess_ftp_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_ftp`
libaccess_ftp_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_ftp`
libaccess_ftp_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_ftp`
libaccess_ftp_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_ftp`
libaccess_ftp_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_ftp`

# The access_smb plugin

libaccess_smb_plugin_a_SOURCES = $(SOURCES_access_smb)
libaccess_smb_plugin_la_SOURCES = $(SOURCES_access_smb)
libaccess_smb_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_smb`
libaccess_smb_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_smb`
libaccess_smb_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_smb`
libaccess_smb_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_smb`
libaccess_smb_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_smb`
libaccess_smb_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_smb`
libaccess_smb_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_smb` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_smb_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_smb_a_SOURCES = $(SOURCES_access_smb)
libaccess_smb_builtin_la_SOURCES = $(SOURCES_access_smb)
libaccess_smb_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_smb`
libaccess_smb_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_smb`
libaccess_smb_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_smb`
libaccess_smb_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_smb`
libaccess_smb_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_smb`
libaccess_smb_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_smb`

# The access_gnomevfs plugin

libaccess_gnomevfs_plugin_a_SOURCES = $(SOURCES_access_gnomevfs)
libaccess_gnomevfs_plugin_la_SOURCES = $(SOURCES_access_gnomevfs)
libaccess_gnomevfs_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_gnomevfs`
libaccess_gnomevfs_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_gnomevfs`
libaccess_gnomevfs_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_gnomevfs`
libaccess_gnomevfs_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_gnomevfs`
libaccess_gnomevfs_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_gnomevfs`
libaccess_gnomevfs_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_gnomevfs`
libaccess_gnomevfs_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_gnomevfs` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_gnomevfs_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_gnomevfs_a_SOURCES = $(SOURCES_access_gnomevfs)
libaccess_gnomevfs_builtin_la_SOURCES = $(SOURCES_access_gnomevfs)
libaccess_gnomevfs_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_gnomevfs`
libaccess_gnomevfs_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_gnomevfs`
libaccess_gnomevfs_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_gnomevfs`
libaccess_gnomevfs_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_gnomevfs`
libaccess_gnomevfs_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_gnomevfs`
libaccess_gnomevfs_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_gnomevfs`

# The dvdnav plugin

libdvdnav_plugin_a_SOURCES = $(SOURCES_dvdnav)
libdvdnav_plugin_la_SOURCES = $(SOURCES_dvdnav)
libdvdnav_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dvdnav`
libdvdnav_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dvdnav`
libdvdnav_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dvdnav`
libdvdnav_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dvdnav`
libdvdnav_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dvdnav`
libdvdnav_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dvdnav`
libdvdnav_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dvdnav` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdvdnav_plugin_la_LIBADD = $(LTLIBVLC)

libdvdnav_a_SOURCES = $(SOURCES_dvdnav)
libdvdnav_builtin_la_SOURCES = $(SOURCES_dvdnav)
libdvdnav_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dvdnav`
libdvdnav_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dvdnav`
libdvdnav_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dvdnav`
libdvdnav_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dvdnav`
libdvdnav_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dvdnav`
libdvdnav_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dvdnav`

# The dvdread plugin

libdvdread_plugin_a_SOURCES = $(SOURCES_dvdread)
libdvdread_plugin_la_SOURCES = $(SOURCES_dvdread)
libdvdread_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dvdread`
libdvdread_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dvdread`
libdvdread_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dvdread`
libdvdread_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dvdread`
libdvdread_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dvdread`
libdvdread_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dvdread`
libdvdread_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dvdread` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdvdread_plugin_la_LIBADD = $(LTLIBVLC)

libdvdread_a_SOURCES = $(SOURCES_dvdread)
libdvdread_builtin_la_SOURCES = $(SOURCES_dvdread)
libdvdread_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dvdread`
libdvdread_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dvdread`
libdvdread_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dvdread`
libdvdread_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dvdread`
libdvdread_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dvdread`
libdvdread_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dvdread`

# The dc1394 plugin

libdc1394_plugin_a_SOURCES = $(SOURCES_dc1394)
libdc1394_plugin_la_SOURCES = $(SOURCES_dc1394)
libdc1394_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin dc1394`
libdc1394_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dc1394`
libdc1394_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dc1394`
libdc1394_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin dc1394`
libdc1394_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin dc1394`
libdc1394_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin dc1394`
libdc1394_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin dc1394` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libdc1394_plugin_la_LIBADD = $(LTLIBVLC)

libdc1394_a_SOURCES = $(SOURCES_dc1394)
libdc1394_builtin_la_SOURCES = $(SOURCES_dc1394)
libdc1394_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic dc1394`
libdc1394_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic dc1394`
libdc1394_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic dc1394`
libdc1394_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin dc1394`
libdc1394_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin dc1394`
libdc1394_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin dc1394`

# The access_fake plugin

libaccess_fake_plugin_a_SOURCES = $(SOURCES_access_fake)
libaccess_fake_plugin_la_SOURCES = $(SOURCES_access_fake)
libaccess_fake_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_fake`
libaccess_fake_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_fake`
libaccess_fake_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_fake`
libaccess_fake_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin access_fake`
libaccess_fake_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin access_fake`
libaccess_fake_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin access_fake`
libaccess_fake_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin access_fake` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libaccess_fake_plugin_la_LIBADD = $(LTLIBVLC)

libaccess_fake_a_SOURCES = $(SOURCES_access_fake)
libaccess_fake_builtin_la_SOURCES = $(SOURCES_access_fake)
libaccess_fake_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic access_fake`
libaccess_fake_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic access_fake`
libaccess_fake_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic access_fake`
libaccess_fake_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin access_fake`
libaccess_fake_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin access_fake`
libaccess_fake_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin access_fake`

# The cdda plugin

libcdda_plugin_a_SOURCES = $(SOURCES_cdda)
libcdda_plugin_la_SOURCES = $(SOURCES_cdda)
libcdda_plugin_a_CFLAGS = `$(VLC_CONFIG) --cflags plugin cdda`
libcdda_plugin_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin cdda`
libcdda_plugin_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin cdda`
libcdda_plugin_la_CFLAGS = `$(VLC_CONFIG) --cflags plugin cdda`
libcdda_plugin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags plugin cdda`
libcdda_plugin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags plugin cdda`
libcdda_plugin_la_LDFLAGS = `$(VLC_CONFIG) --libs plugin cdda` \
	-rpath '$(libvlcdir)' -avoid-version -module -shrext $(LIBEXT)
libcdda_plugin_la_LIBADD = $(LTLIBVLC)

libcdda_a_SOURCES = $(SOURCES_cdda)
libcdda_builtin_la_SOURCES = $(SOURCES_cdda)
libcdda_a_CFLAGS = `$(VLC_CONFIG) --cflags builtin pic cdda`
libcdda_a_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin pic cdda`
libcdda_a_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin pic cdda`
libcdda_builtin_la_CFLAGS = `$(VLC_CONFIG) --cflags builtin cdda`
libcdda_builtin_la_CXXFLAGS = `$(VLC_CONFIG) --cxxflags builtin cdda`
libcdda_builtin_la_OBJCFLAGS = `$(VLC_CONFIG) --objcflags builtin cdda`

