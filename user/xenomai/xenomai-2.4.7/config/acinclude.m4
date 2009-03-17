dnl AC_PATH_XREQUIRED() requires X libs. This frag has been
dnl lifted nearly "as is" from Postgresql's configure.in script.

AC_DEFUN([AC_PATH_XREQUIRED],
[
	save_LIBS="$LIBS"
	save_CFLAGS="$CFLAGS"
	save_CPPFLAGS="$CPPFLAGS"
	save_LDFLAGS="$LDFLAGS"

	AC_PATH_X
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

dnl AC_POSIX_SIGHANDLER() determines whether
dnl signal handlers are posix compliant. This frag
dnl has been adapted from readline's aclocal.m4.

AC_DEFUN([AC_POSIX_SIGHANDLER],
[AC_MSG_CHECKING([if signal handlers are posix compliant])
AC_CACHE_VAL(ac_cv_posix_sighandler,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <signal.h>
#ifdef signal
#undef signal
#endif
#ifdef __cplusplus
extern "C"
#endif
void (*signal(void))(void);],
[int i;], ac_cv_posix_sighandler=no, ac_cv_posix_sighandler=yes)])dnl
AC_MSG_RESULT($ac_cv_posix_sighandler)
if test $ac_cv_posix_sighandler = yes; then
AC_DEFINE(HAVE_POSIX_SIGHANDLER,1,[Kconfig])
fi
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

AC_DEFUN([SC_PATH_TCLCONFIG], [
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

AC_DEFUN([SC_PATH_TKCONFIG], [
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

AC_DEFUN([SC_LOAD_TCLCONFIG], [
    AC_MSG_CHECKING([for existence of $TCL_BIN_DIR/tclConfig.sh])

    if test -f "$TCL_BIN_DIR/tclConfig.sh" ; then
        AC_MSG_RESULT([loading])
	. $TCL_BIN_DIR/tclConfig.sh
    else
        AC_MSG_ERROR([not found])
    fi

    AC_PATH_PROG(TCL_SCRIPT, tclsh${TCL_VERSION}, tclsh)

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

AC_DEFUN([SC_LOAD_TKCONFIG], [
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
# SC_PATH_TIX --
#
#	Locate the Tix installation.
#
# Arguments:
#	None.
#
# Results:
#
#	Substs the following vars:
#		TIX_TCL_LIB
#		TIX_LIB_SPEC
#------------------------------------------------------------------------

AC_DEFUN([SC_PATH_TIX], [
    AC_MSG_CHECKING(for Tix's Tcl library)

    AC_ARG_WITH(tixlibrary, [  --with-tixlibrary      directory containing the Tix library files.], with_tixlibrary=${withval})

    if test x"${with_tixlibrary}" != x ; then
	if test -f "${with_tixlibrary}/Init.tcl" ; then
	    ac_cv_tix_libdir=${with_tixlibrary}
	else
	    AC_MSG_ERROR([${with_tixlibrary} directory does not contain Tix's init file Init.tcl])
	fi
    else
	AC_CACHE_VAL(ac_cv_tix_libdir, [
	    for d in \
	    `ls -dr /usr/local/lib/tix[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/local/share/tix[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/pkg/lib/tix[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/lib/tix[[0-9]]* 2>/dev/null ` \
	    `ls -dr /usr/share/tix[[0-9]]* 2>/dev/null ` ; do
		if test -f "$d/Init.tcl" ; then
		ac_cv_tix_libdir=$d
	        break
	        fi
	    done
        ])
    fi

    AC_MSG_RESULT($ac_cv_tix_libdir)
    TIX_TCL_LIB=$ac_cv_tix_libdir
    AC_SUBST(TIX_TCL_LIB)

    SC_LIB_SPEC(tix)
    TIX_LIB_SPEC=$tix_LIB_SPEC
    AC_SUBST(TIX_LIB_SPEC)
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

AC_DEFUN([SC_LIB_SPEC], [
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

AC_DEFUN([SC_PUBLIC_TCL_HEADERS], [
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

AC_DEFUN([SC_PUBLIC_TK_HEADERS], [
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
