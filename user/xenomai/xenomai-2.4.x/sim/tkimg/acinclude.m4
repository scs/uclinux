dnl ########################
dnl Scan directories for a given file
dnl ########################
AC_DEFUN(AC_SCAN_DIRS,
[
$3=""
for i in $2;
do
  for j in $1;
  do
    if test -r "$i/$j"; then
      $3=$i
      break 2
    fi
  done
done
])

AC_DEFUN(AC_FIND_FILE,
[
AC_MSG_CHECKING([for file ($3)])
filepath=""
for i in $2;
do
 a=$3
 eval filepath=`ls $i/$a 2>/dev/null | tail -1`
 if test -n "$filepath"; then
    break
 fi
done
if test x$filepath = x ; then
AC_MSG_RESULT([not found])
AC_MSG_ERROR([*** Cannot find $3 in $2.])
else
AC_MSG_RESULT([found $filepath])
fi
AC_DEFINE_UNQUOTED($1,"$filepath")
])

dnl AC_PATH_XREQUIRED() requires X libs. This frag has been
dnl lifted nearly "as is" from Postgresql's configure.in script.

AC_DEFUN(AC_PATH_XREQUIRED,
[
	save_LIBS="$LIBS"
	save_CFLAGS="$CFLAGS"
	save_CPPFLAGS="$CPPFLAGS"
	save_LDFLAGS="$LDFLAGS"

	AC_PATH_XTRA

	LIBS="$LIBS $X_EXTRA_LIBS"
	CFLAGS="$CFLAGS $X_CFLAGS"
	CPPFLAGS="$CPPFLAGS $X_CFLAGS"
	LDFLAGS="$LDFLAGS $X_LIBS"

	dnl Check for X library

	X11_LIBS=""
	AC_CHECK_LIB(X11, XOpenDisplay, X11_LIBS="-lX11",,${X_PRE_LIBS})
	if test "$X11_LIBS" = ""; then
		dnl Not having X is bad news, period. Let the user fix this.
		AC_MSG_ERROR([The X11 library '-lX11' could not be found,
so I won't go further. Please use the configure
options '--x-includes=DIR' and '--x-libraries=DIR'
to specify the X location. See the file 'config.log'
for further diagnostics.])
	fi
	AC_SUBST(X_LIBS)
	AC_SUBST(X11_LIBS)
	AC_SUBST(X_PRE_LIBS)

	LIBS="$save_LIBS"
	CFLAGS="$save_CFLAGS"
	CPPFLAGS="$save_CPPFLAGS"
	LDFLAGS="$save_LDFLAGS"
])

# This portion has been lifted and slightly patched from Scriptics'
# tcl.m4 file.
#
#	This file provides a set of autoconf macros to help TEA-enable
#	a Tcl extension.
#
# Copyright (c) 1999 Scriptics Corporation.
#
# Modified 2002 Rubens Fernandes - rubens_ramos@yahoo.com for
# the carbonkernel project
#
# See the file "license.terms" for information on usage and redistribution
# of this file, and for a DISCLAIMER OF ALL WARRANTIES.

#--------------------------------------------------------------------
# "cygpath" is used on windows to generate native path names for include
# files.
# These variables should only be used with the compiler and linker since
# they generate native path names.
#
# Unix tclConfig.sh points SRC_DIR at the top-level directory of
# the Tcl sources, while the Windows tclConfig.sh points SRC_DIR at
# the win subdirectory.  Hence the different usages of SRC_DIR below.
#
# This must be done before calling SC_PUBLIC_TCL_HEADERS
#--------------------------------------------------------------------

AC_DEFUN(SC_CYGPATH, [
case "`uname -s`" in
    *win32* | *WIN32* | *CYGWIN_NT*)
	CYGPATH="cygpath -w"
    ;;
    *)
	CYGPATH=echo
    ;;
esac

AC_SUBST(CYGPATH)
])


#------------------------------------------------------------------------
# SC_PATH_TCLCONFIG --
#
#	Locate the tclConfig.sh file and perform a sanity check on
#	the Tcl compile flags
#
# Arguments:
#	none
#
# Results:
#
#	Adds the following arguments to configure:
#		--with-tcl=...
#
#	Defines the following vars:
#		TCL_BIN_DIR	Full path to the directory containing
#				the tclConfig.sh file
#------------------------------------------------------------------------

AC_DEFUN(SC_PATH_TCLCONFIG, [
    #
    # Ok, lets find the tcl configuration
    # First, look for one uninstalled.
    # the alternative search directory is invoked by --with-tcl
    #

    if test x"${no_tcl}" = x ; then
	# we reset no_tcl in case something fails here
	no_tcl=true
	AC_ARG_WITH(tcl, [  --with-tcl              directory containing tcl configuration (tclConfig.sh)], with_tclconfig=${withval})
	AC_MSG_CHECKING([for Tcl configuration])
	AC_CACHE_VAL(ac_cv_c_tclconfig,[

	    # First check to see if --with-tcl was specified.
	    if test x"${with_tclconfig}" != x ; then
		if test -f "${with_tclconfig}/tclConfig.sh" ; then
		    ac_cv_c_tclconfig=`(cd ${with_tclconfig}; pwd)`
		else
		    AC_MSG_ERROR([${with_tclconfig} directory doesn't contain tclConfig.sh])
		fi
	    fi

	    # then check for a private Tcl installation
	    if test x"${ac_cv_c_tclconfig}" = x ; then
		for i in \
			../tcl \
			`ls -dr ../tcl[[8-9]].[[0-9]]* 2>/dev/null` \
			../../tcl \
			`ls -dr ../../tcl[[8-9]].[[0-9]]* 2>/dev/null` \
			../../../tcl \
			`ls -dr ../../../tcl[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/unix/tclConfig.sh" ; then
			ac_cv_c_tclconfig=`(cd $i/unix; pwd)`
			break
		    fi
		done
	    fi

	    # check in a few common install locations
	    if test x"${ac_cv_c_tclconfig}" = x ; then
		for i in ${prefix}/lib /usr/local/lib /usr/pkg/lib /usr/lib \
			`ls -dr /usr/lib/tcl[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/tclConfig.sh" ; then
			ac_cv_c_tclconfig=`(cd $i; pwd)`
			break
		    fi
		done
	    fi

	    # check in a few other private locations
	    if test x"${ac_cv_c_tclconfig}" = x ; then
		for i in \
			${srcdir}/../tcl \
			`ls -dr ${srcdir}/../tcl[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/unix/tclConfig.sh" ; then
		    ac_cv_c_tclconfig=`(cd $i/unix; pwd)`
		    break
		fi
		done
	    fi
	])

	if test x"${ac_cv_c_tclconfig}" = x ; then
	    TCL_BIN_DIR="# no Tcl configs found"
	    AC_MSG_WARN(Can't find Tcl configuration definitions)
	    exit 1
	else
	    no_tcl=
	    TCL_BIN_DIR=${ac_cv_c_tclconfig}
	    AC_MSG_RESULT(found $TCL_BIN_DIR/tclConfig.sh)
	fi
    fi
])

#------------------------------------------------------------------------
# SC_PATH_TKCONFIG --
#
#	Locate the tkConfig.sh file
#
# Arguments:
#	none
#
# Results:
#
#	Adds the following arguments to configure:
#		--with-tk=...
#
#	Defines the following vars:
#		TK_BIN_DIR	Full path to the directory containing
#				the tkConfig.sh file
#------------------------------------------------------------------------

AC_DEFUN(SC_PATH_TKCONFIG, [
    #
    # Ok, lets find the tk configuration
    # First, look for one uninstalled.
    # the alternative search directory is invoked by --with-tk
    #

    if test x"${no_tk}" = x ; then
	# we reset no_tk in case something fails here
	no_tk=true
	AC_ARG_WITH(tk, [  --with-tk               directory containing tk configuration (tkConfig.sh)], with_tkconfig=${withval})
	AC_MSG_CHECKING([for Tk configuration])
	AC_CACHE_VAL(ac_cv_c_tkconfig,[

	    # First check to see if --with-tkconfig was specified.
	    if test x"${with_tkconfig}" != x ; then
		if test -f "${with_tkconfig}/tkConfig.sh" ; then
		    ac_cv_c_tkconfig=`(cd ${with_tkconfig}; pwd)`
		else
		    AC_MSG_ERROR([${with_tkconfig} directory doesn't contain tkConfig.sh])
		fi
	    fi

	    # then check for a private Tk library
	    if test x"${ac_cv_c_tkconfig}" = x ; then
		for i in \
			../tk \
			`ls -dr ../tk[[8-9]].[[0-9]]* 2>/dev/null` \
			../../tk \
			`ls -dr ../../tk[[8-9]].[[0-9]]* 2>/dev/null` \
			../../../tk \
			`ls -dr ../../../tk[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/unix/tkConfig.sh" ; then
			ac_cv_c_tkconfig=`(cd $i/unix; pwd)`
			break
		    fi
		done
	    fi
	    # check in a few common install locations
	    if test x"${ac_cv_c_tkconfig}" = x ; then
		for i in ${prefix}/lib /usr/local/lib /usr/pkg/lib /usr/lib \
			`ls -dr /usr/lib/tk[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/tkConfig.sh" ; then
			ac_cv_c_tkconfig=`(cd $i; pwd)`
			break
		    fi
		done
	    fi
	    # check in a few other private locations
	    if test x"${ac_cv_c_tkconfig}" = x ; then
		for i in \
			${srcdir}/../tk \
			`ls -dr ${srcdir}/../tk[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/unix/tkConfig.sh" ; then
			ac_cv_c_tkconfig=`(cd $i/unix; pwd)`
			break
		    fi
		done
	    fi
	])
	if test x"${ac_cv_c_tkconfig}" = x ; then
	    TK_BIN_DIR="# no Tk configs found"
	    AC_MSG_WARN(Can't find Tk configuration definitions)
	    exit 1
	else
	    no_tk=
	    TK_BIN_DIR=${ac_cv_c_tkconfig}
	    AC_MSG_RESULT(found $TK_BIN_DIR/tkConfig.sh)
	fi
    fi

])

#------------------------------------------------------------------------
# SC_LOAD_TCLCONFIG --
#
#	Load the tclConfig.sh file
#
# Arguments:
#	
#	Requires the following vars to be set:
#		TCL_BIN_DIR
#
# Results:
#
#	Subst the following vars:
#		TCL_BIN_DIR
#		TCL_SRC_DIR
#		TCL_LIB_FILE
#
#------------------------------------------------------------------------

AC_DEFUN(SC_LOAD_TCLCONFIG, [
    AC_MSG_CHECKING([for existence of $TCL_BIN_DIR/tclConfig.sh])

    if test -f "$TCL_BIN_DIR/tclConfig.sh" ; then
        AC_MSG_RESULT([loading])
	. $TCL_BIN_DIR/tclConfig.sh
    else
        AC_MSG_ERROR([not found])
    fi

    AC_PATH_PROG(TCL_SCRIPT, tclsh${TCL_VERSION}, tclsh)

# Override these ones to overcome RedHat's insanities with tclConfig.sh.
    TCL_SHARED_LIB_SUFFIX='${VERSION}${TCL_DBGX}${TCL_SHLIB_SUFFIX}'
    TCL_UNSHARED_LIB_SUFFIX='${VERSION}${TCL_DBGX}.a'

    AC_SUBST(TCL_BIN_DIR)
    AC_SUBST(TCL_SRC_DIR)
    AC_SUBST(TCL_LIB_FILE)
    AC_SUBST(TCL_LIBS)
    AC_SUBST(TCL_DEFS)
    AC_SUBST(TCL_SHLIB_LD_LIBS)
    AC_SUBST(TCL_EXTRA_CFLAGS)
    AC_SUBST(TCL_LD_FLAGS)
    AC_SUBST(TCL_LIB_FILE)
    AC_SUBST(TCL_STUB_LIB_FILE)
    AC_SUBST(TCL_LIB_SPEC)
    AC_SUBST(TCL_BUILD_LIB_SPEC)
    AC_SUBST(TCL_STUB_LIB_SPEC)
    AC_SUBST(TCL_BUILD_STUB_LIB_SPEC)
    AC_SUBST(TCL_SHARED_LIB_SUFFIX)
    AC_SUBST(TCL_UNSHARED_LIB_SUFFIX)
    AC_SUBST(TCL_DBGX)
])

#------------------------------------------------------------------------
# SC_LOAD_TKCONFIG --
#
#	Load the tkConfig.sh file
#
# Arguments:
#	
#	Requires the following vars to be set:
#		TK_BIN_DIR
#
# Results:
#
#	Sets the following vars that should be in tkConfig.sh:
#		TK_BIN_DIR
#------------------------------------------------------------------------

AC_DEFUN(SC_LOAD_TKCONFIG, [
    AC_MSG_CHECKING([for existence of $TK_BIN_DIR/tkConfig.sh])

    if test -f "$TK_BIN_DIR/tkConfig.sh" ; then
        AC_MSG_RESULT([loading])
	. $TK_BIN_DIR/tkConfig.sh
    else
        AC_MSG_ERROR([not found])
    fi

    AC_SUBST(TK_BIN_DIR)
    AC_SUBST(TK_SRC_DIR)
    AC_SUBST(TK_LIB_FILE)
    AC_SUBST(TK_LIB_FLAG)
    AC_SUBST(TK_LIB_SPEC)
    AC_SUBST(TK_DBGX)
])

#------------------------------------------------------------------------
# SC_ENABLE_GCC --
#
#	Allows the use of GCC if available
#
# Arguments:
#	none
#	
# Results:
#
#	Adds the following arguments to configure:
#		--enable-gcc
#
#	Sets the following vars:
#		CC	Command to use for the compiler
#------------------------------------------------------------------------

AC_DEFUN(SC_ENABLE_GCC, [
    AC_ARG_ENABLE(gcc, [  --enable-gcc            allow use of gcc if available [--disable-gcc]],
	[ok=$enableval], [ok=no])
    if test "$ok" = "yes"; then
	CC=gcc
    else
	case "`uname -s`" in
	    *win32* | *WIN32* | *CYGWIN_NT*)
		CC=cl
	    ;;
	    *)
		CC=${CC-cc}
	    ;;
	esac
    fi
    AC_PROG_CC
])

#------------------------------------------------------------------------
# SC_ENABLE_SHARED --
#
#	Allows the building of shared libraries
#
# Arguments:
#	none
#	
# Results:
#
#	Adds the following arguments to configure:
#		--enable-shared=yes|no
#
#	Defines the following vars:
#		STATIC_BUILD	Used for building import/export libraries
#				on Windows.
#
#	Sets the following vars:
#		SHARED_BUILD	Value of 1 or 0
#------------------------------------------------------------------------

AC_DEFUN(SC_ENABLE_SHARED, [
    AC_MSG_CHECKING([how to build libraries])
    AC_ARG_ENABLE(shared,
	[  --enable-shared         build and link with shared libraries [--enable-shared]],
	[tcl_ok=$enableval], [tcl_ok=yes])

    if test "${enable_shared+set}" = set; then
	enableval="$enable_shared"
	tcl_ok=$enableval
    else
	tcl_ok=yes
    fi

    if test "$tcl_ok" = "yes" ; then
	AC_MSG_RESULT([shared])
	SHARED_BUILD=1
    else
	AC_MSG_RESULT([static])
	SHARED_BUILD=0
	AC_DEFINE(STATIC_BUILD)
    fi
])

#------------------------------------------------------------------------
# SC_ENABLE_THREADS --
#
#	Specify if thread support should be enabled
#
# Arguments:
#	none
#	
# Results:
#
#	Adds the following arguments to configure:
#		--enable-threads
#
#	Sets the following vars:
#		THREADS_LIBS	Thread library(s)
#
#	Defines the following vars:
#		TCL_THREADS
#		_REENTRANT
#
#------------------------------------------------------------------------

AC_DEFUN(SC_ENABLE_THREADS, [
    AC_MSG_CHECKING(for building with threads)
    AC_ARG_ENABLE(threads, [  --enable-threads        build with threads],
	[tcl_ok=$enableval], [tcl_ok=no])

    if test "$tcl_ok" = "yes"; then
	AC_MSG_RESULT(yes)
	TCL_THREADS=1
	AC_DEFINE(TCL_THREADS)
	AC_DEFINE(_REENTRANT)

	AC_CHECK_LIB(pthread,pthread_mutex_init,tcl_ok=yes,tcl_ok=no)
	if test "$tcl_ok" = "yes"; then
	    # The space is needed
	    THREADS_LIBS=" -lpthread"
	else
	    TCL_THREADS=0
	    AC_MSG_WARN("Don t know how to find pthread lib on your system - you must disable thread support or edit the LIBS in the Makefile...")
	fi
    else
	TCL_THREADS=0
	AC_MSG_RESULT(no (default))
    fi

])

#------------------------------------------------------------------------
# SC_ENABLE_SYMBOLS --
#
#	Specify if debugging symbols should be used
#
# Arguments:
#	none
#	
#	Requires the following vars to be set:
#		CFLAGS_DEBUG
#		CFLAGS_OPTIMIZE
#		LDFLAGS_DEBUG
#		LDFLAGS_OPTIMIZE
#	
# Results:
#
#	Adds the following arguments to configure:
#		--enable-symbols
#
#	Defines the following vars:
#		CFLAGS_DEFAULT	Sets to CFLAGS_DEBUG if true
#				Sets to CFLAGS_OPTIMIZE if false
#		LDFLAGS_DEFAULT	Sets to LDFLAGS_DEBUG if true
#				Sets to LDFLAGS_OPTIMIZE if false
#		DBGX		Debug library extension
#
#------------------------------------------------------------------------

AC_DEFUN(SC_ENABLE_SYMBOLS, [
    case "`uname -s`" in
	*win32* | *WIN32* | *CYGWIN_NT*)
	    tcl_dbgx=d
	;;
	*)
	    tcl_dbgx=g
	;;
    esac

    AC_MSG_CHECKING([for build with symbols])
    AC_ARG_ENABLE(symbols, [  --enable-symbols        build with debugging symbols [--disable-symbols]],    [tcl_ok=$enableval], [tcl_ok=no])
    if test "$tcl_ok" = "yes"; then
	CFLAGS_DEFAULT="${CFLAGS_DEBUG}"
	LDFLAGS_DEFAULT="${LDFLAGS_DEBUG}"
	DBGX=${tcl_dbgx}
	TCL_DBGX=${tcl_dbgx}
	AC_MSG_RESULT([yes])
    else
	CFLAGS_DEFAULT="${CFLAGS_OPTIMIZE}"
	LDFLAGS_DEFAULT="${LDFLAGS_OPTIMIZE}"
	DBGX=""
	TCL_DBGX=""
	AC_MSG_RESULT([no])
    fi

    AC_SUBST(TCL_DBGX)
    AC_SUBST(CFLAGS_DEFAULT)
    AC_SUBST(LDFLAGS_DEFAULT)
])

#--------------------------------------------------------------------
# SC_SERIAL_PORT
#
#	Determine which interface to use to talk to the serial port.
#	Note that #include lines must begin in leftmost column for
#	some compilers to recognize them as preprocessor directives.
#
# Arguments:
#	none
#	
# Results:
#
#	Defines only one of the following vars:
#		USE_TERMIOS
#		USE_TERMIO
#		USE_SGTTY
#
#--------------------------------------------------------------------

AC_DEFUN(SC_SERIAL_PORT, [
    AC_MSG_CHECKING([termios vs. termio vs. sgtty])

    AC_TRY_RUN([
#include <termios.h>

main()
{
    struct termios t;
    if (tcgetattr(0, &t) == 0) {
	cfsetospeed(&t, 0);
	t.c_cflag |= PARENB | PARODD | CSIZE | CSTOPB;
	return 0;
    }
    return 1;
}], tk_ok=termios, tk_ok=no, tk_ok=no)

    if test $tk_ok = termios; then
	AC_DEFINE(USE_TERMIOS)
    else
	AC_TRY_RUN([
#include <termio.h>

main()
{
    struct termio t;
    if (ioctl(0, TCGETA, &t) == 0) {
	t.c_cflag |= CBAUD | PARENB | PARODD | CSIZE | CSTOPB;
	return 0;
    }
    return 1;
    }], tk_ok=termio, tk_ok=no, tk_ok=no)

    if test $tk_ok = termio; then
	AC_DEFINE(USE_TERMIO)
    else
	AC_TRY_RUN([
#include <sgtty.h>

main()
{
    struct sgttyb t;
    if (ioctl(0, TIOCGETP, &t) == 0) {
	t.sg_ospeed = 0;
	t.sg_flags |= ODDP | EVENP | RAW;
	return 0;
    }
    return 1;
}], tk_ok=sgtty, tk_ok=none, tk_ok=none)
    if test $tk_ok = sgtty; then
	AC_DEFINE(USE_SGTTY)
    fi
    fi
    fi
    AC_MSG_RESULT($tk_ok)
])

#--------------------------------------------------------------------
# SC_MISSING_POSIX_HEADERS
#
#	Supply substitutes for missing POSIX header files.  Special
#	notes:
#	    - stdlib.h doesn't define strtol, strtoul, or
#	      strtod insome versions of SunOS
#	    - some versions of string.h don't declare procedures such
#	      as strstr
#
# Arguments:
#	none
#	
# Results:
#
#	Defines some of the following vars:
#		NO_DIRENT_H
#		NO_ERRNO_H
#		NO_VALUES_H
#		NO_LIMITS_H
#		NO_STDLIB_H
#		NO_STRING_H
#		NO_SYS_WAIT_H
#		NO_DLFCN_H
#		HAVE_UNISTD_H
#		HAVE_SYS_PARAM_H
#
#		HAVE_STRING_H ?
#
#--------------------------------------------------------------------

AC_DEFUN(SC_MISSING_POSIX_HEADERS, [

    AC_MSG_CHECKING(dirent.h)
    AC_TRY_LINK([#include <sys/types.h>
#include <dirent.h>], [
#ifndef _POSIX_SOURCE
#   ifdef __Lynx__
	/*
	 * Generate compilation error to make the test fail:  Lynx headers
	 * are only valid if really in the POSIX environment.
	 */

	missing_procedure();
#   endif
#endif
DIR *d;
struct dirent *entryPtr;
char *p;
d = opendir("foobar");
entryPtr = readdir(d);
p = entryPtr->d_name;
closedir(d);
], tcl_ok=yes, tcl_ok=no)

    if test $tcl_ok = no; then
	AC_DEFINE(NO_DIRENT_H)
    fi

    AC_MSG_RESULT($tcl_ok)
    AC_CHECK_HEADER(errno.h, , AC_DEFINE(NO_ERRNO_H))
    AC_CHECK_HEADER(float.h, , AC_DEFINE(NO_FLOAT_H))
    AC_CHECK_HEADER(values.h, , AC_DEFINE(NO_VALUES_H))
    AC_CHECK_HEADER(limits.h, , AC_DEFINE(NO_LIMITS_H))
    AC_CHECK_HEADER(stdlib.h, tcl_ok=1, tcl_ok=0)
    AC_EGREP_HEADER(strtol, stdlib.h, , tcl_ok=0)
    AC_EGREP_HEADER(strtoul, stdlib.h, , tcl_ok=0)
    AC_EGREP_HEADER(strtod, stdlib.h, , tcl_ok=0)
    if test $tcl_ok = 0; then
	AC_DEFINE(NO_STDLIB_H)
    fi
    AC_CHECK_HEADER(string.h, tcl_ok=1, tcl_ok=0)
    AC_EGREP_HEADER(strstr, string.h, , tcl_ok=0)
    AC_EGREP_HEADER(strerror, string.h, , tcl_ok=0)

    # See also memmove check below for a place where NO_STRING_H can be
    # set and why.

    if test $tcl_ok = 0; then
	AC_DEFINE(NO_STRING_H)
    fi

    AC_CHECK_HEADER(sys/wait.h, , AC_DEFINE(NO_SYS_WAIT_H))
    AC_CHECK_HEADER(dlfcn.h, , AC_DEFINE(NO_DLFCN_H))

    # OS/390 lacks sys/param.h (and doesn't need it, by chance).

    AC_HAVE_HEADERS(unistd.h sys/param.h)

])

#--------------------------------------------------------------------
# SC_PATH_X
#
#	Locate the X11 header files and the X11 library archive.  Try
#	the ac_path_x macro first, but if it doesn't find the X stuff
#	(e.g. because there's no xmkmf program) then check through
#	a list of possible directories.  Under some conditions the
#	autoconf macro will return an include directory that contains
#	no include files, so double-check its result just to be safe.
#
# Arguments:
#	none
#	
# Results:
#
#	Sets the the following vars:
#		XINCLUDES
#		XLIBSW
#
#--------------------------------------------------------------------

AC_DEFUN(SC_PATH_X, [
    AC_PATH_X
    not_really_there=""
    if test "$no_x" = ""; then
	if test "$x_includes" = ""; then
	    AC_TRY_CPP([#include <X11/XIntrinsic.h>], , not_really_there="yes")
	else
	    if test ! -r $x_includes/X11/Intrinsic.h; then
		not_really_there="yes"
	    fi
	fi
    fi
    if test "$no_x" = "yes" -o "$not_really_there" = "yes"; then
	AC_MSG_CHECKING(for X11 header files)
	XINCLUDES="# no special path needed"
	AC_TRY_CPP([#include <X11/Intrinsic.h>], , XINCLUDES="nope")
	if test "$XINCLUDES" = nope; then
	    dirs="/usr/unsupported/include /usr/local/include /usr/X386/include /usr/X11R6/include /usr/X11R5/include /usr/include/X11R5 /usr/include/X11R4 /usr/openwin/include /usr/X11/include /usr/sww/include"
	    for i in $dirs ; do
		if test -r $i/X11/Intrinsic.h; then
		    AC_MSG_RESULT($i)
		    XINCLUDES=" -I$i"
		    break
		fi
	    done
	fi
    else
	if test "$x_includes" != ""; then
	    XINCLUDES=-I$x_includes
	else
	    XINCLUDES="# no special path needed"
	fi
    fi
    if test "$XINCLUDES" = nope; then
	AC_MSG_RESULT(couldn't find any!)
	XINCLUDES="# no include files found"
    fi

    if test "$no_x" = yes; then
	AC_MSG_CHECKING(for X11 libraries)
	XLIBSW=nope
	dirs="/usr/unsupported/lib /usr/local/lib /usr/X386/lib /usr/X11R6/lib /usr/X11R5/lib /usr/lib/X11R5 /usr/lib/X11R4 /usr/openwin/lib /usr/X11/lib /usr/sww/X11/lib"
	for i in $dirs ; do
	    if test -r $i/libX11.a -o -r $i/libX11.so -o -r $i/libX11.sl; then
		AC_MSG_RESULT($i)
		XLIBSW="-L$i -lX11"
		x_libraries="$i"
		break
	    fi
	done
    else
	if test "$x_libraries" = ""; then
	    XLIBSW=-lX11
	else
	    XLIBSW="-L$x_libraries -lX11"
	fi
    fi
    if test "$XLIBSW" = nope ; then
	AC_CHECK_LIB(Xwindow, XCreateWindow, XLIBSW=-lXwindow)
    fi
    if test "$XLIBSW" = nope ; then
	AC_MSG_RESULT(couldn't find any!  Using -lX11.)
	XLIBSW=-lX11
    fi
])
#--------------------------------------------------------------------
# SC_BLOCKING_STYLE
#
#	The statements below check for systems where POSIX-style
#	non-blocking I/O (O_NONBLOCK) doesn't work or is unimplemented. 
#	On these systems (mostly older ones), use the old BSD-style
#	FIONBIO approach instead.
#
# Arguments:
#	none
#	
# Results:
#
#	Defines some of the following vars:
#		HAVE_SYS_IOCTL_H
#		HAVE_SYS_FILIO_H
#		USE_FIONBIO
#		O_NONBLOCK
#
#--------------------------------------------------------------------

AC_DEFUN(SC_BLOCKING_STYLE, [
    AC_CHECK_HEADERS(sys/ioctl.h)
    AC_CHECK_HEADERS(sys/filio.h)
    AC_MSG_CHECKING([FIONBIO vs. O_NONBLOCK for nonblocking I/O])
    if test -f /usr/lib/NextStep/software_version; then
	system=NEXTSTEP-`awk '/3/,/3/' /usr/lib/NextStep/software_version`
    else
	system=`uname -s`-`uname -r`
	if test "$?" -ne 0 ; then
	    system=unknown
	else
	    # Special check for weird MP-RAS system (uname returns weird
	    # results, and the version is kept in special file).
	
	    if test -r /etc/.relid -a "X`uname -n`" = "X`uname -s`" ; then
		system=MP-RAS-`awk '{print $3}' /etc/.relid'`
	    fi
	    if test "`uname -s`" = "AIX" ; then
		system=AIX-`uname -v`.`uname -r`
	    fi
	fi
    fi
    case $system in
	# There used to be code here to use FIONBIO under AIX.  However, it
	# was reported that FIONBIO doesn't work under AIX 3.2.5.  Since
	# using O_NONBLOCK seems fine under AIX 4.*, I removed the FIONBIO
	# code (JO, 5/31/97).

	OSF*)
	    AC_DEFINE(USE_FIONBIO)
	    AC_MSG_RESULT(FIONBIO)
	    ;;
	SunOS-4*)
	    AC_DEFINE(USE_FIONBIO)
	    AC_MSG_RESULT(FIONBIO)
	    ;;
	ULTRIX-4.*)
	    AC_DEFINE(USE_FIONBIO)
	    AC_MSG_RESULT(FIONBIO)
	    ;;
	*)
	    AC_MSG_RESULT(O_NONBLOCK)
	    ;;
    esac
])

#--------------------------------------------------------------------
# SC_HAVE_VFORK
#
#	Check to see whether the system provides a vfork kernel call.
#	If not, then use fork instead.  Also, check for a problem with
#	vforks and signals that can cause core dumps if a vforked child
#	resets a signal handler.  If the problem exists, then use fork
#	instead of vfork.
#
# Arguments:
#	none
#	
# Results:
#
#	Defines some of the following vars:
#		vfork (=fork)
#
#--------------------------------------------------------------------

AC_DEFUN(SC_HAVE_VFORK, [
    AC_TYPE_SIGNAL()
    AC_CHECK_FUNC(vfork, tcl_ok=1, tcl_ok=0)
    if test "$tcl_ok" = 1; then
	AC_MSG_CHECKING([vfork/signal bug]);
	AC_TRY_RUN([
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
int gotSignal = 0;
sigProc(sig)
    int sig;
{
    gotSignal = 1;
}
main()
{
    int pid, sts;
    (void) signal(SIGCHLD, sigProc);
    pid = vfork();
    if (pid <  0) {
	exit(1);
    } else if (pid == 0) {
	(void) signal(SIGCHLD, SIG_DFL);
	_exit(0);
    } else {
	(void) wait(&sts);
    }
    exit((gotSignal) ? 0 : 1);
}], tcl_ok=1, tcl_ok=0, tcl_ok=0)

	if test "$tcl_ok" = 1; then
	    AC_MSG_RESULT(ok)
	else
	    AC_MSG_RESULT([buggy, using fork instead])
	fi
    fi
    rm -f core
    if test "$tcl_ok" = 0; then
	AC_DEFINE(vfork, fork)
    fi
])

#--------------------------------------------------------------------
# SC_TIME_HANLDER
#
#	Checks how the system deals with time.h, what time structures
#	are used on the system, and what fields the structures have.
#
# Arguments:
#	none
#	
# Results:
#
#	Defines some of the following vars:
#		USE_DELTA_FOR_TZ
#		HAVE_TM_GMTOFF
#		HAVE_TM_TZADJ
#		HAVE_TIMEZONE_VAR
#
#--------------------------------------------------------------------

AC_DEFUN(SC_TIME_HANDLER, [
    AC_CHECK_HEADERS(sys/time.h)
    AC_HEADER_TIME
    AC_STRUCT_TIMEZONE

    AC_MSG_CHECKING([tm_tzadj in struct tm])
    AC_TRY_COMPILE([#include <time.h>], [struct tm tm; tm.tm_tzadj;],
	    [AC_DEFINE(HAVE_TM_TZADJ)
	    AC_MSG_RESULT(yes)],
	    AC_MSG_RESULT(no))

    AC_MSG_CHECKING([tm_gmtoff in struct tm])
    AC_TRY_COMPILE([#include <time.h>], [struct tm tm; tm.tm_gmtoff;],
	    [AC_DEFINE(HAVE_TM_GMTOFF)
	    AC_MSG_RESULT(yes)],
	    AC_MSG_RESULT(no))

    #
    # Its important to include time.h in this check, as some systems
    # (like convex) have timezone functions, etc.
    #
    have_timezone=no
    AC_MSG_CHECKING([long timezone variable])
    AC_TRY_COMPILE([#include <time.h>],
	    [extern long timezone;
	    timezone += 1;
	    exit (0);],
	    [have_timezone=yes
	    AC_DEFINE(HAVE_TIMEZONE_VAR)
	    AC_MSG_RESULT(yes)],
	    AC_MSG_RESULT(no))

    #
    # On some systems (eg IRIX 6.2), timezone is a time_t and not a long.
    #
    if test "$have_timezone" = no; then
    AC_MSG_CHECKING([time_t timezone variable])
    AC_TRY_COMPILE([#include <time.h>],
	    [extern time_t timezone;
	    timezone += 1;
	    exit (0);],
	    [AC_DEFINE(HAVE_TIMEZONE_VAR)
	    AC_MSG_RESULT(yes)],
	    AC_MSG_RESULT(no))
    fi

    #
    # AIX does not have a timezone field in struct tm. When the AIX bsd
    # library is used, the timezone global and the gettimeofday methods are
    # to be avoided for timezone deduction instead, we deduce the timezone
    # by comparing the localtime result on a known GMT value.
    #

    if test "`uname -s`" = "AIX" ; then
	AC_CHECK_LIB(bsd, gettimeofday, libbsd=yes)
	if test $libbsd = yes; then
	    AC_DEFINE(USE_DELTA_FOR_TZ)
	fi
    fi
])

#--------------------------------------------------------------------
# SC_BUGGY_STRTOD
#
#	Under Solaris 2.4, strtod returns the wrong value for the
#	terminating character under some conditions.  Check for this
#	and if the problem exists use a substitute procedure
#	"fixstrtod" (provided by Tcl) that corrects the error.
#
# Arguments:
#	none
#	
# Results:
#
#	Might defines some of the following vars:
#		strtod (=fixstrtod)
#
#--------------------------------------------------------------------

AC_DEFUN(SC_BUGGY_STRTOD, [
    AC_CHECK_FUNC(strtod, tk_strtod=1, tk_strtod=0)
    if test "$tk_strtod" = 1; then
	AC_MSG_CHECKING([for Solaris 2.4 strtod bug])
	AC_TRY_RUN([
	    extern double strtod();
	    int main()
	    {
		char *string = "NaN";
		char *term;
		strtod(string, &term);
		if ((term != string) && (term[-1] == 0)) {
		    exit(1);
		}
		exit(0);
	    }], tk_ok=1, tk_ok=0, tk_ok=0)
	if test "$tk_ok" = 1; then
	    AC_MSG_RESULT(ok)
	else
	    AC_MSG_RESULT(buggy)
	    AC_DEFINE(strtod, fixstrtod)
	fi
    fi
])

#--------------------------------------------------------------------
# SC_TCL_LINK_LIBS
#
#	Search for the libraries needed to link the Tcl shell.
#	Things like the math library (-lm) and socket stuff (-lsocket vs.
#	-lnsl) are dealt with here.
#
# Arguments:
#	Requires the following vars to be set in the Makefile:
#		DL_LIBS
#		LIBS
#		MATH_LIBS
#	
# Results:
#
#	Subst's the following var:
#		TCL_LIBS
#		MATH_LIBS
#
#	Might append to the following vars:
#		LIBS
#
#	Might define the following vars:
#		HAVE_NET_ERRNO_H
#
#--------------------------------------------------------------------

AC_DEFUN(SC_TCL_LINK_LIBS, [
    #--------------------------------------------------------------------
    # On a few very rare systems, all of the libm.a stuff is
    # already in libc.a.  Set compiler flags accordingly.
    # Also, Linux requires the "ieee" library for math to work
    # right (and it must appear before "-lm").
    #--------------------------------------------------------------------

    AC_CHECK_FUNC(sin, MATH_LIBS="", MATH_LIBS="-lm")
    AC_CHECK_LIB(ieee, main, [MATH_LIBS="-lieee $MATH_LIBS"])

    #--------------------------------------------------------------------
    # On AIX systems, libbsd.a has to be linked in to support
    # non-blocking file IO.  This library has to be linked in after
    # the MATH_LIBS or it breaks the pow() function.  The way to
    # insure proper sequencing, is to add it to the tail of MATH_LIBS.
    # This library also supplies gettimeofday.
    #--------------------------------------------------------------------

    libbsd=no
    if test "`uname -s`" = "AIX" ; then
	AC_CHECK_LIB(bsd, gettimeofday, libbsd=yes)
	if test $libbsd = yes; then
	    MATH_LIBS="$MATH_LIBS -lbsd"
	fi
    fi


    #--------------------------------------------------------------------
    # Interactive UNIX requires -linet instead of -lsocket, plus it
    # needs net/errno.h to define the socket-related error codes.
    #--------------------------------------------------------------------

    AC_CHECK_LIB(inet, main, [LIBS="$LIBS -linet"])
    AC_CHECK_HEADER(net/errno.h, AC_DEFINE(HAVE_NET_ERRNO_H))

    #--------------------------------------------------------------------
    #	Check for the existence of the -lsocket and -lnsl libraries.
    #	The order here is important, so that they end up in the right
    #	order in the command line generated by make.  Here are some
    #	special considerations:
    #	1. Use "connect" and "accept" to check for -lsocket, and
    #	   "gethostbyname" to check for -lnsl.
    #	2. Use each function name only once:  can't redo a check because
    #	   autoconf caches the results of the last check and won't redo it.
    #	3. Use -lnsl and -lsocket only if they supply procedures that
    #	   aren't already present in the normal libraries.  This is because
    #	   IRIX 5.2 has libraries, but they aren't needed and they're
    #	   bogus:  they goof up name resolution if used.
    #	4. On some SVR4 systems, can't use -lsocket without -lnsl too.
    #	   To get around this problem, check for both libraries together
    #	   if -lsocket doesn't work by itself.
    #--------------------------------------------------------------------

    tcl_checkBoth=0
    AC_CHECK_FUNC(connect, tcl_checkSocket=0, tcl_checkSocket=1)
    if test "$tcl_checkSocket" = 1; then
	AC_CHECK_LIB(socket, main, LIBS="$LIBS -lsocket", tcl_checkBoth=1)
    fi
    if test "$tcl_checkBoth" = 1; then
	tk_oldLibs=$LIBS
	LIBS="$LIBS -lsocket -lnsl"
	AC_CHECK_FUNC(accept, tcl_checkNsl=0, [LIBS=$tk_oldLibs])
    fi
    AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, main,
	    [LIBS="$LIBS -lnsl"]))
    
    # Don't perform the eval of the libraries here because DL_LIBS
    # won't be set until we call SC_CONFIG_CFLAGS

    TCL_LIBS='${DL_LIBS} ${LIBS} ${MATH_LIBS}'
    AC_SUBST(TCL_LIBS)
    AC_SUBST(MATH_LIBS)
])

#------------------------------------------------------------------------
# SC_MAKE_LIB --
#
#	Generate a line that can be used to build a shared/unshared library
#	in a platform independent manner.
#
# Arguments:
#	none
#
#	Requires:
#
# Results:
#
#	Defines the following vars:
#		MAKE_LIB	Makefile rule for building a library
#		MAKE_SHARED_LIB	Makefile rule for building a shared library
#		MAKE_UNSHARED_LIB	Makefile rule for building a static
#				library
#------------------------------------------------------------------------

AC_DEFUN(SC_MAKE_LIB, [
    case "`uname -s`" in
	*win32* | *WIN32* | *CYGWIN_NT*)
	    if test "${CC-cc}" = "cl"; then
		MAKE_STATIC_LIB="\${STLIB_LD} -out:\[$]@ \$(\[$]@_OBJECTS) "
		MAKE_SHARED_LIB="\${SHLIB_LD} \${SHLIB_LDFLAGS} \${SHLIB_LD_LIBS} \$(LDFLAGS) -out:\[$]@ \$(\[$]@_OBJECTS) "
	    fi
	    ;;
	*)
	    MAKE_STATIC_LIB="\${STLIB_LD} \[$]@ \$(\[$]@_OBJECTS)"
	    MAKE_SHARED_LIB="\${SHLIB_LD} -o \[$]@ \$(\[$]@_OBJECTS) \${SHLIB_LDFLAGS} \${SHLIB_LD_LIBS}"
	    ;;
    esac

    if test "${SHARED_BUILD}" = "1" ; then
	MAKE_LIB=${MAKE_SHARED_LIB}
    else
	MAKE_LIB=${MAKE_STATIC_LIB}
    fi

    AC_SUBST(MAKE_LIB)
    AC_SUBST(MAKE_SHARED_LIB)
    AC_SUBST(MAKE_STATIC_LIB)
])

#------------------------------------------------------------------------
# SC_LIB_SPEC --
#
#	Compute the name of an existing object library located in libdir
#	from the given base name and produce the appropriate linker flags.
#
# Arguments:
#	basename	The base name of the library without version
#			numbers, extensions, or "lib" prefixes.
#
#	Requires:
#
# Results:
#
#	Defines the following vars:
#		${basename}_LIB_NAME	The computed library name.
#		${basename}_LIB_SPEC	The computed linker flags.
#------------------------------------------------------------------------

AC_DEFUN(SC_LIB_SPEC, [
    AC_MSG_CHECKING(for $1 library)
    eval "sc_lib_name_dir=${libdir}"
    for i in \
	    `ls -dr ${sc_lib_name_dir}/$1[[0-9]]*.lib 2>/dev/null ` \
	    `ls -dr ${sc_lib_name_dir}/lib$1.* 2>/dev/null ` \
	    `ls -dr ${sc_lib_name_dir}/lib$1[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/pkg/*/lib$1.so 2>/dev/null ` \
	    `ls -dr /usr/pkg/*/lib$1[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/pkg/lib/lib$1.so 2>/dev/null ` \
	    `ls -dr /usr/pkg/lib/lib$1[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/lib/$1[[0-9]]*.lib 2>/dev/null ` \
	    `ls -dr /usr/lib/lib$1.so 2>/dev/null ` \
	    `ls -dr /usr/lib/lib$1[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/local/lib/$1[[0-9]]*.lib 2>/dev/null ` \
	    `ls -dr /usr/local/lib/lib$1.so 2>/dev/null ` \
	    `ls -dr /usr/local/lib/lib$1[[0-9]]* 2>/dev/null ` ; do
	if test -f "$i" ; then
	    sc_lib_name_dir=`dirname $i`
	    $1_LIB_NAME=`basename $i`
	    break
	fi
    done

    case "`uname -s`" in
	*win32* | *WIN32* | *CYGWIN_NT*)
	    $1_LIB_SPEC=${$1_LIB_NAME}
	    ;;
	*)
	    # Strip off the leading "lib" and trailing ".a" or ".so"
	    sc_lib_name_lib=`echo ${$1_LIB_NAME}|sed -e 's/^lib//' -e 's/\.so.*$//' -e 's/\.a$//'`
	    $1_LIB_SPEC="-L${sc_lib_name_dir} -l${sc_lib_name_lib}"
	    ;;
    esac
    if test "x${sc_lib_name_lib}" = x ; then
	AC_MSG_ERROR(not found)
    else
	AC_MSG_RESULT(${$1_LIB_SPEC})
    fi
])

#------------------------------------------------------------------------
# SC_PRIVATE_TCL_INCLUDE --
#
#	Locate the private Tcl include files
#
# Arguments:
#
#	Requires:
#		TCL_SRC_DIR	Assumes that SC_LOAD_TCLCONFIG has
#				 already been called.
#
# Results:
#
#	Substs the following vars:
#		TCL_TOP_DIR_NATIVE
#		TCL_GENERIC_DIR_NATIVE
#		TCL_UNIX_DIR_NATIVE
#		TCL_WIN_DIR_NATIVE
#		TCL_BMAP_DIR_NATIVE
#		TCL_TOOL_DIR_NATIVE
#		TCL_PLATFORM_DIR_NATIVE
#		TCL_BIN_DIR_NATIVE
#		TCL_INCLUDES
#------------------------------------------------------------------------

AC_DEFUN(SC_PRIVATE_TCL_HEADERS, [
    AC_MSG_CHECKING(for Tcl private include files)

    case "`uname -s`" in
	*win32* | *WIN32* | *CYGWIN_NT*)
	    TCL_TOP_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/..`\"
	    TCL_GENERIC_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/../generic`\"
	    TCL_UNIX_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/../unix`\"
	    TCL_WIN_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/../win`\"
	    TCL_BMAP_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/../bitmaps`\"
	    TCL_TOOL_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/../tools`\"
	    TCL_COMPAT_DIR_NATIVE=\"`${CYGPATH} ${TCL_SRC_DIR}/../compat`\"
	    TCL_PLATFORM_DIR_NATIVE=${TCL_WIN_DIR_NATIVE}
	;;
	*)
	    TCL_TOP_DIR_NATIVE=${TCL_SRC_DIR}
	    TCL_GENERIC_DIR_NATIVE='$(TCL_TOP_DIR_NATIVE)/generic'
	    TCL_UNIX_DIR_NATIVE='$(TCL_TOP_DIR_NATIVE)/unix'
	    TCL_WIN_DIR_NATIVE='$(TCL_TOP_DIR_NATIVE)/win'
	    TCL_BMAP_DIR_NATIVE='$(TCL_TOP_DIR_NATIVE)/bitmaps'
	    TCL_TOOL_DIR_NATIVE='$(TCL_TOP_DIR_NATIVE)/tools'
	    TCL_COMPAT_DIR_NATIVE='$(TCL_TOP_DIR_NATIVE)/compat'
	    TCL_PLATFORM_DIR_NATIVE=${TCL_UNIX_DIR_NATIVE}
	;;
    esac

    AC_SUBST(TCL_TOP_DIR_NATIVE)
    AC_SUBST(TCL_GENERIC_DIR_NATIVE)
    AC_SUBST(TCL_UNIX_DIR_NATIVE)
    AC_SUBST(TCL_WIN_DIR_NATIVE)
    AC_SUBST(TCL_BMAP_DIR_NATIVE)
    AC_SUBST(TCL_TOOL_DIR_NATIVE)
    AC_SUBST(TCL_PLATFORM_DIR_NATIVE)

    TCL_INCLUDES="-I${TCL_GENERIC_DIR_NATIVE} -I${TCL_PLATFORM_DIR_NATIVE}"
    AC_SUBST(TCL_INCLUDES)
    AC_MSG_RESULT(Using srcdir found in tclConfig.sh)
])


#------------------------------------------------------------------------
# SC_PUBLIC_TCL_HEADERS --
#
#	Locate the installed public Tcl header files
#
# Arguments:
#	None.
#
# Requires:
#
# Results:
#
#	Adds a --with-tclinclude switch to configure.
#	Result is cached.
#
#	Substs the following vars:
#		TCL_INCLUDES
#------------------------------------------------------------------------

AC_DEFUN(SC_PUBLIC_TCL_HEADERS, [
    AC_MSG_CHECKING(for Tcl public headers)

    AC_ARG_WITH(tclinclude, [  --with-tclinclude      directory containing the public Tcl header files.], with_tclinclude=${withval})

    if test x"${with_tclinclude}" != x ; then
	if test -f "${with_tclinclude}/tcl.h" ; then
	    ac_cv_c_tclh=${with_tclinclude}
	else
	    AC_MSG_ERROR([${with_tclinclude} directory does not contain Tcl public header file tcl.h])
	fi
    else
	AC_CACHE_VAL(ac_cv_c_tclh, [
	    # Use the value from --with-tclinclude, if it was given

	    if test x"${with_tclinclude}" != x ; then
		ac_cv_c_tclh=${with_tclinclude}
	    else
		# Check in the includedir, if --prefix was specified

		eval "temp_includedir=${includedir}"
		for i in \
			${temp_includedir} /usr/local/include /usr/include /usr/pkg/include \
			`ls -dr /usr/include/tcl[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/tcl.h" ; then
			ac_cv_c_tclh=$i
			break
		    fi
		done
	    fi
	])
    fi

    # Print a message based on how we determined the include path

    if test x"${ac_cv_c_tclh}" = x ; then
	AC_MSG_ERROR(tcl.h not found.  Please specify its location with --with-tclinclude)
    else
	AC_MSG_RESULT(${ac_cv_c_tclh})
    fi

    # Convert to a native path and substitute into the output files.

    INCLUDE_DIR_NATIVE=`echo ${ac_cv_c_tclh}`

    TCL_INCLUDES="-I${INCLUDE_DIR_NATIVE}"

    AC_SUBST(TCL_INCLUDES)
])

#------------------------------------------------------------------------
# SC_PUBLIC_TK_HEADERS --
#
#	Locate the installed public Tk header files
#
# Arguments:
#	None.
#
# Requires:
#
# Results:
#
#	Adds a --with-tkinclude switch to configure.
#	Result is cached.
#
#	Substs the following vars:
#		TK_INCLUDES
#------------------------------------------------------------------------

AC_DEFUN(SC_PUBLIC_TK_HEADERS, [
    AC_MSG_CHECKING(for Tk public headers)

    AC_ARG_WITH(tkinclude, [  --with-tkinclude      directory containing the public Tk header files.], with_tkinclude=${withval})

    if test x"${with_tkinclude}" != x ; then
	if test -f "${with_tkinclude}/tk.h" ; then
	    ac_cv_c_tkh=${with_tkinclude}
	else
	    AC_MSG_ERROR([${with_tkinclude} directory does not contain Tk public header file tk.h])
	fi
    else
	AC_CACHE_VAL(ac_cv_c_tkh, [
	    # Use the value from --with-tkinclude, if it was given

	    if test x"${with_tkinclude}" != x ; then
		ac_cv_c_tkh=${with_tkinclude}
	    else
		# Check in the includedir, if --prefix was specified

		eval "temp_includedir=${includedir}"
		for i in \
			${temp_includedir} /usr/local/include /usr/include /usr/pkg/include \
			`ls -dr /usr/include/tk[[8-9]].[[0-9]]* 2>/dev/null` \
			`ls -dr /usr/include/tcl[[8-9]].[[0-9]]* 2>/dev/null` ; do
		    if test -f "$i/tk.h" ; then
			ac_cv_c_tkh=$i
			break
		    fi
		done
	    fi
	])
    fi

    # Print a message based on how we determined the include path

    if test x"${ac_cv_c_tkh}" = x ; then
	AC_MSG_ERROR(tk.h not found.  Please specify its location with --with-tkinclude)
    else
	AC_MSG_RESULT(${ac_cv_c_tkh})
    fi

    # Convert to a native path and substitute into the output files.

    INCLUDE_DIR_NATIVE=`echo ${ac_cv_c_tkh}`

    TK_INCLUDES="-I${INCLUDE_DIR_NATIVE}"

    AC_SUBST(TK_INCLUDES)
])

#------------------------------------------------------------------------
# SC_PRIVATE_TK_INCLUDE --
#
#	Locate the private Tcl include files
#
# Arguments:
#
#	Requires:
#		TK_SRC_DIR	Assumes that SC_LOAD_TKCONFIG has
#				 already been called.
#
# Results:
#
#	Substs the following vars:
#		TK_TOP_DIR_NATIVE
#		TK_GENERIC_DIR_NATIVE
#		TK_UNIX_DIR_NATIVE
#		TK_WIN_DIR_NATIVE
#		TK_BMAP_DIR_NATIVE
#		TK_TOOL_DIR_NATIVE
#		TK_PLATFORM_DIR_NATIVE
#		TK_BIN_DIR_NATIVE
#		TK_INCLUDES
#------------------------------------------------------------------------

AC_DEFUN(SC_PRIVATE_TK_HEADERS, [
    AC_MSG_CHECKING(for Tcl private include files)

    case "`uname -s`" in
	*win32* | *WIN32* | *CYGWIN_NT*)
	    TK_TOP_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/..`\"
	    TK_GENERIC_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/../generic`\"
	    TK_UNIX_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/../unix`\"
	    TK_WIN_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/../win`\"
	    TK_BMAP_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/../bitmaps`\"
	    TK_TOOL_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/../tools`\"
	    TK_COMPAT_DIR_NATIVE=\"`${CYGPATH} ${TK_SRC_DIR}/../compat`\"
	    TK_PLATFORM_DIR_NATIVE=${TK_WIN_DIR_NATIVE}
	;;
	*)
	    TK_TOP_DIR_NATIVE=${TK_SRC_DIR}
	    TK_GENERIC_DIR_NATIVE='$(TK_TOP_DIR_NATIVE)/generic'
	    TK_UNIX_DIR_NATIVE='$(TK_TOP_DIR_NATIVE)/unix'
	    TK_WIN_DIR_NATIVE='$(TK_TOP_DIR_NATIVE)/win'
	    TK_BMAP_DIR_NATIVE='$(TK_TOP_DIR_NATIVE)/bitmaps'
	    TK_TOOL_DIR_NATIVE='$(TK_TOP_DIR_NATIVE)/tools'
	    TK_COMPAT_DIR_NATIVE='$(TK_TOP_DIR_NATIVE)/compat'
	    TK_PLATFORM_DIR_NATIVE=${TK_UNIX_DIR_NATIVE}
	;;
    esac

    AC_SUBST(TK_TOP_DIR_NATIVE)
    AC_SUBST(TK_GENERIC_DIR_NATIVE)
    AC_SUBST(TK_UNIX_DIR_NATIVE)
    AC_SUBST(TK_WIN_DIR_NATIVE)
    AC_SUBST(TK_BMAP_DIR_NATIVE)
    AC_SUBST(TK_TOOL_DIR_NATIVE)
    AC_SUBST(TK_PLATFORM_DIR_NATIVE)

    TK_INCLUDES="-I${TK_GENERIC_DIR_NATIVE} -I${TK_PLATFORM_DIR_NATIVE}"
    AC_SUBST(TK_INCLUDES)
    AC_MSG_RESULT(Using srcdir found in tkConfig.sh)
])
