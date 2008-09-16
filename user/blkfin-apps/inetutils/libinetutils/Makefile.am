AUTOMAKE_OPTIONS = ../ansi2knr

noinst_LIBRARIES = libinetutils.a

libinetutils_a_SOURCES = argcv.c cleansess.c daemon.c des_rw.c kcmd.c	\
	krcmd.c localhost.c logwtmpko.c setsig.c tftpsubs.c ttymsg.c	\
	xmalloc.c xstrdup.c xgetcwd.c utmp_init.c utmp_logout.c

#	memcmp.c memcpy.c memmove.c memset.c

libinetutils_a_LIBADD = daemon.o @LIBOBJS@

noinst_HEADERS = argcv.h snprintf.h pathmax.h regex.h getopt.h	\
		 obstack.h setenv.h gettext.h xalloc.h xgetcwd.h

EXTRA_DIST = regex.c obstack.c

@PATHDEFS_MAKE@

INCLUDES = $(PATHDEF_WTMPX) $(PATHDEF_TTY_PFX) $(PATHDEF_DEVNULL) $(PATHDEF_HEQUIV) -I$(top_builddir)/include
