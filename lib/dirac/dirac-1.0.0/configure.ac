dnl --------------------------------
dnl Initialization macros.
dnl --------------------------------

AC_INIT(encoder/encmain.cpp)

dnl -----------------------------------------------
dnl Package name and version number (user defined)
dnl -----------------------------------------------

GENERIC_LIBRARY_NAME=dirac

#release versioning
GENERIC_MAJOR_VERSION=1
GENERIC_MINOR_VERSION=0
GENERIC_MICRO_VERSION=0

#shared library versioning
GENERIC_LIBRARY_VERSION=0:0:0
#                       | | |
#                +------+ | +---+
#                |        |     |
#             current:revision:age
#                |        |     |
#                |        |     +- increment if interfaces have been added
#                |        |        set to zero if interfaces have been removed
#                                  or changed
#                |        +- increment if source code has changed
#                |           set to zero if current is incremented
#                +- increment if interfaces have been added, removed or changed


dnl --------------------------------
dnl Package name and version number
dnl --------------------------------

AC_SUBST(GENERIC_LIBRARY_VERSION)

PACKAGE=$GENERIC_LIBRARY_NAME
AC_SUBST(GENERIC_LIBRARY_NAME)

GENERIC_VERSION=$GENERIC_MAJOR_VERSION.$GENERIC_MINOR_VERSION.$GENERIC_MICRO_VERSION
GENERIC_RELEASE=$GENERIC_MAJOR_VERSION.$GENERIC_MINOR_VERSION
AC_SUBST(GENERIC_RELEASE)
AC_SUBST(GENERIC_VERSION)

VERSION=$GENERIC_VERSION

AM_INIT_AUTOMAKE($PACKAGE, $VERSION, no-define)

dnl -----------------------------------------------
dnl Checks for required programs.
dnl -----------------------------------------------
AC_PROG_CXX
AM_SANITY_CHECK
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AC_SYS_LARGEFILE

ACLOCAL_AMFLAGS="-I m4 $ACLOCAL_AMFLAGS"
AC_SUBST(ACLOCAL_AMFLAGS)


dnl -------------------------------------------------------------------------
dnl Check if compiling using MS VC++ compiler in msys environment on Windows
dnl -------------------------------------------------------------------------
use_msvc=no
AC_SUBST([LIBFLAGS],[])
AC_SUBST([LIBEXT],[])
case "$CXX" in
		cl*|CL*)
		CXXFLAGS="-nologo -W1 -EHsc -DWIN32"
		if test x"$enable_shared" = "xyes"; then
		    LIBEXT=".dll";
		    LIBFLAGS="-DLL -INCREMENTAL:NO"
			CXXFLAGS="$CXXFLAGS -D_WINDLL"
		else
		    LIBEXT=".lib";
		    LIBFLAGS="-lib"
		fi
		RANLIB="echo"
		use_msvc=yes
		;;
	*)
		;;
esac
AM_CONDITIONAL(USE_MSVC, test x"$use_msvc" = "xyes")

dnl -----------------------------------------------
dnl Checks for required headers
dnl -----------------------------------------------

AC_HEADER_STDC
AC_HEADER_STDBOOL

dnl -------------------------------------------------------------------------
dnl Indirectly checking if the compiler is useable
dnl -------------------------------------------------------------------------
AC_LANG_PUSH(C++)
AC_CHECK_HEADER(streambuf,[], [AC_MSG_ERROR(["Unsupported Compiler version"])])
AC_LANG_POP(C++)
dnl ** We probably need this line, but not now
dnl AC_CHECK_HEADERS(stdint.h unistd.h fcntl.h)

AX_CREATE_STDINT_H([libdirac_common/dirac-stdint.h])

dnl -----------------------------------------------
dnl Checks for libraries.
dnl -----------------------------------------------

dnl -----------------------------------------------
dnl Checks for optional programs.
dnl -----------------------------------------------
AC_CHECK_PROG(HAVE_DOXYGEN, doxygen, true, false)
	if test $HAVE_DOXYGEN = "false"; then
		AC_MSG_WARN([*** doxygen not found, code documentation will not be built])
	fi
AM_CONDITIONAL(HAVE_DOXYGEN, $HAVE_DOXYGEN)

AC_CHECK_PROG(HAVE_DOT, dot, true, false)
	if test $HAVE_DOT = "false"; then
		AC_MSG_WARN([*** dot not found, inheritance diagrams will not be generated in code documentation])
	fi
AM_CONDITIONAL(HAVE_DOT, $HAVE_DOT)

AC_CHECK_PROG(HAVE_LATEX, latex, true, false)
	if test $HAVE_LATEX = "false"; then
		AC_MSG_WARN([*** latex not found, algorithm documentation will not be built])
	fi
AM_CONDITIONAL(HAVE_LATEX, $HAVE_LATEX)

AC_CHECK_PROG(HAVE_DVIPDFM, dvipdfm, true, false)
	if test $HAVE_DVIPDFM = "false"; then
	    AC_MSG_WARN([*** dvipdfm not found, programmer documentation will not be built])
    fi
AM_CONDITIONAL(HAVE_DVIPDFM, $HAVE_DVIPDFM)

AC_ARG_ENABLE(overlay,
[ --enable-overlay Turns onDirectory instrumentation],
[case "${enableval}" in
	yes) overlay=true ;;
	no) overlay=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-overlay) ;;
esac],[overlay=false])
AM_CONDITIONAL(OVERLAY, test x$overlay = xtrue)

dnl -----------------------------------------------
dnl Setup for the testsuite
dnl -----------------------------------------------
AC_CONFIG_TESTDIR([tests], [tests:encoder:decoder:unit_tests:util/instrumentation])
AC_CONFIG_FILES([tests/Makefile])
AC_CONFIG_FILES([tests/at_wrap], [chmod +x tests/at_wrap])
AM_MISSING_PROG([AUTOM4TE], [autom4te])

dnl ----------------------------------------------
dnl enable profiling flags
dnl -----------------------------------------------
AC_MSG_CHECKING([whether gprof flags are to be used when compiling])
AC_ARG_ENABLE(profile, AC_HELP_STRING([--enable-profile], [enable profile flags (no)]),
[
if test x"${enableval}" = x"yes" ; then
	AC_MSG_RESULT(yes)
	case "$CXX" in
	    g++*|icc)
	        CXXFLAGS="$CXXFLAGS -pg"
			;;
        *)
		    # do nothing
			;;
    esac
else
	AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)]
)

AC_LANG_PUSH(C++)
OPT_CFLAGS=""
case "$CXX" in
   g++*)
		TRY_CFLAGS="$OPT_CFLAGS -g"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -pedantic"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -Wall"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -Werror"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -W"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -Woverloaded-virtual"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		#TRY_CFLAGS="-Wno-long-double"
		#AC_TRY_CXXFLAGS([#include <math.h>],[long double lw;], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$OPT_CFLAGS $TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -Wextra"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
        CXXFLAGS="$OPT_CFLAGS $CXXFLAGS"
		   ;;
    *)
	    # do nothing at the moment
		;;
esac
dnl ----------------------------------------------
dnl enable debug flags
dnl -----------------------------------------------
AC_MSG_CHECKING([whether extra debug flags are to be used when compiling])
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable extra debug flags (no)]),
[
if test x"${enableval}" = x"yes" ; then
	AC_MSG_RESULT(yes)
	case "$CXX" in
	    g++*)
			CXXFLAGS=`echo $CXXFLAGS | sed 's/-O[[0-9]]*//g'`
			OPT_CFLAGS=""
			TRY_CFLAGS="-O0"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			CXXFLAGS="$OPT_CFLAGS $CXXFLAGS -DDIRAC_DEBUG"
		    ;;
	    icc)
			CXXFLAGS=`echo $CXXFLAGS | sed 's/-O[[0-9]]*//g'`
			CXXFLAGS="-DDIRAC_DEBUG -g -O0 $CXXFLAGS"
		    # report only errors and warnings as errors
		    CXXFLAGS="$CXXFLAGS -w1 -Werror -wr964 -wr963" 
		    ;;
	    cl*|CL*)
		    # -Od turn off optimisation, -Z7 turn on debugging info
			CXXFLAGS=`echo $CXXFLAGS | sed 's/-O[[0-9]]*//g'`
			CXXFLAGS=`echo $CXXFLAGS | sed 's/-O[[a-z]]*//g'`
			CXXFLAGS=`echo $CXXFLAGS | sed 's/-W[[0-9]]*//g'`
		    CXXFLAGS="$CXXFLAGS -Od -Z7 -W2"
			if test x"$enable_shared" = "xyes"; then
			  LIBFLAGS="$LIBFLAGS -DEBUG";
            fi
		    ;;
        *)
		    # do nothing at the moment
			;;
    esac
else
	AC_MSG_RESULT(no)
fi], 
[
	AC_MSG_RESULT(no)
	OPT_CFLAGS=""
	case "$CXX" in
    g++*|icc)
		TRY_CFLAGS="-O3"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		TRY_CFLAGS="$OPT_CFLAGS -Wuninitialized"
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		dnl arch specific flags
		case "$host" in
			i386-*) TRY_CFLAGS="$OPT_CFLAGS -march=i386";;
			i486-*) TRY_CFLAGS="$OPT_CFLAGS -march=i486";;
			i586-*) TRY_CFLAGS="$OPT_CFLAGS -march=pentium";;
			i686-*) TRY_CFLAGS="$OPT_CFLAGS -march=pentiumpro";;
			k6-*)   TRY_CFLAGS="$OPT_CFLAGS -march=k6";;
		esac
		AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
		;;
	*)
		;;
	esac

    #Try more optimising flags if supported
	case "$CXX" in
	    g++*)
			dnl TRY_CFLAGS="$OPT_CFLAGS -fprefetch-loop-arrays"
			dnl AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -fexpensive-optimizations"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -frerun-cse-after-loop"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -frerun-loop-opt"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -fomit-frame-pointer"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -minline-all-stringops"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -fschedule-insns2"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -falign-functions=4"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			dnl TRY_CFLAGS="$OPT_CFLAGS -preferred-stack-boundary=4"
			dnl AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -fforce-addr"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			TRY_CFLAGS="$OPT_CFLAGS -pipe"
			AC_TRY_CXXFLAGS([],[], [$TRY_CFLAGS $CXXFLAGS],[OPT_CFLAGS="$TRY_CFLAGS"])
			;;
		*)
		    # do nothing at the moment
			;;
	esac
    CXXFLAGS="$OPT_CFLAGS $CXXFLAGS"
]
)
AC_LANG_POP(C++)

dnl ----------------------------------------------
dnl enable MMX optimization flag
dnl TODO: need to fix this test
dnl -----------------------------------------------
AC_MSG_CHECKING([whether optimizations using MMX instructions are enabled])
AC_ARG_ENABLE(mmx, AC_HELP_STRING([--enable-mmx], [enable MMX optimization (default=yes)]), [enable_mmx="${enableval}"], [enable_mmx="yes"])

if test x"${enable_mmx}" = x"yes" ; then
	case "$CXX" in
	    g++*)
			AC_LANG_PUSH(C++)
			TRY_CFLAGS="-mmmx"
			AC_TRY_CXXFLAGS([#include <mmintrin.h>],[], [$TRY_CFLAGS $CXXFLAGS],[CXXFLAGS="$CXXFLAGS $TRY_CFLAGS -DHAVE_MMX"])
			AC_LANG_POP(C++)
			;;
   	    icc)
   			AC_LANG_PUSH(C++)
   			AC_CHECK_HEADER(mmintrin.h,[AC_MSG_RESULT(yes); CXXFLAGS="$CXXFLAGS -DHAVE_MMX=1"], [AC_MSG_RESULT(["no"])])
   			AC_LANG_POP(C++)
   			;;
        *)
		    # do nothing
			AC_MSG_RESULT(["no"])
			;;
    esac
else
	AC_MSG_RESULT(no)
fi

dnl -----------------------------------------------
dnl Setup for the cppunit testsuite
dnl -----------------------------------------------
AC_LANG_PUSH(C++)
dnl need to determine how to run AC_CHECK_LIB on a c++ library
dnl Until then just use AC_CHECK_HEADER by itself
dnl AC_CHECK_HEADER([cppunit/TestRunner.h],
dnl     [AC_CHECK_LIB([cppunit], [main], [HAVE_CPPUNIT="true"], [HAVE_CPPUNIT="false"], [ -ldl ])], [HAVE_CPPUNIT="false"])
AC_CHECK_HEADER([cppunit/TestRunner.h],[HAVE_CPPUNIT="true"], [HAVE_CPPUNIT="false"])
	if test $HAVE_CPPUNIT = "true"; then
		AC_MSG_CHECKING([whether unit tests code will compile and link])
		SAVE_LIBS=$LIBS
		SAVE_CXXFLAGS=$CXXFLAGS
		LIBS="$LIBS -lcppunit -ldl"
		case `$LD -v 2>&1 < /dev/null` in
		*GNU* | *'with BFD'*)
			CXXFLAGS="$CXXFLAGS -Wl,--fatal-warnings"
			;;
		esac;
		AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <cppunit/TestResult.h> 
		#include <cppunit/TestRunner.h>]], [[CPPUNIT_NS::TestResult controller; CPPUNIT_NS::TestRunner runner;]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT(no); HAVE_CPPUNIT="false"])
		LIBS=$SAVE_LIBS
		CXXFLAGS=$SAVE_CXXFLAGS
	fi
AM_CONDITIONAL(HAVE_CPPUNIT, $HAVE_CPPUNIT)
AC_LANG_POP(C++)

dnl -----------------------------------------------
dnl Check if static libraries to be used on non-Windows platforms
dnl -----------------------------------------------
AM_CONDITIONAL(USE_STATIC, test x"$enable_static" = "xyes")

dnl -----------------------------------------------
dnl Setup valgrind and necessary args for memcheck
dnl -----------------------------------------------
dnl Using -q --leak-check on valgrind pre-2.2 gives stderr output when
dnl no leaks are found so only use --leak-check with recent valgrind.
dnl valgrind is used during the make valgrind-check target.
AC_CHECK_PROGS(VALGRIND, valgrind)
if test x"$VALGRIND" != "x" ; then
	if $VALGRIND -q --tool=memcheck true 2>/dev/null; then
		VALGRIND="valgrind --tool=memcheck --leak-check=yes"
	fi
fi

dnl -----------------------------------------------
dnl Check if we need mathlib
dnl -----------------------------------------------
AC_LANG_PUSH(C++)
AC_SUBST([CONFIG_MATH_LIB],[])
AC_MSG_CHECKING([whether we need to link math lib])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <cmath>]], [[double lw = std::pow(2.0, 2.0);]])],[AC_MSG_RESULT(no)], [CONFIG_MATH_LIB="-lm";AC_MSG_RESULT(yes)])
AC_LANG_POP(C++)
dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_OUTPUT(Makefile dirac.pc \
          util/Makefile \
          util/conversion/Makefile \
          util/conversion/common/Makefile \
	  util/instrumentation/Makefile \
	  util/instrumentation/libdirac_instrument/Makefile \
          doc/Makefile \
          libdirac_byteio/Makefile \
          libdirac_common/Makefile \
          libdirac_motionest/Makefile \
          libdirac_encoder/Makefile \
          libdirac_decoder/Makefile \
          encoder/Makefile \
          decoder/Makefile \
          unit_tests/Makefile \
          win32/Makefile \
          win32/VisualStudio/Makefile )
