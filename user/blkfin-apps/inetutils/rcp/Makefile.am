AUTOMAKE_OPTIONS = ../ansi2knr

bin_PROGRAMS = @rcp_BUILD@

EXTRA_PROGRAMS = rcp

rcp_SOURCES = rcp.c util.c

noinst_HEADERS = extern.h

man_MANS = rcp.1

@PATHDEFS_MAKE@

INCLUDES = $(PATHDEF_RSH) $(PATHDEF_CP) $(PATHDEF_BSHELL) -I$(top_builddir)/include

LDADD = -L../libinetutils -linetutils

EXTRA_DIST = $(man_MANS)

SUIDMODE = -o root -m 4775

install-exec-hook:
	-@$(INSTALL_PROGRAM) $(bin_PROGRAMS) $(SUIDMODE) $(AM_INSTALL_PROGRAM_FLAGS) $(DESTDIR)$(bindir)/`echo $(bin_PROGRAMS)|sed '$(transform)'` ; \
	if test $$? -ne 0; then \
		echo 'INSTALL-ERROR:'; \
		echo 'INSTALL-ERROR: THIS PROGRAM($(bin_PROGRAMS)) MUST BE INSTALLED SETUID ROOT'; \
		echo 'INSTALL-ERROR: $(INSTALL_PROGRAM) $(bin_PROGRAMS) $(SUIDMODE) $(DESTDIR)$(bindir)/$(bin_PROGRAMS)'; \
		echo 'INSTALL-ERROR:'; \
	fi
