# generated automatically by aclocal 1.7.2 -*- Autoconf -*-

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

dnl Autoconf macros used by inetutils
dnl
dnl Copyright (C) 1996, 1997, 1998, 2002 Free Software Foundation, Inc.
dnl
dnl Mostly written by Miles Bader <miles@gnu.ai.mit.edu>
dnl
dnl Joel N. Weber II <devnull@gnu.org> wrote
dnl IU_ENABLE_CLIENT, IU_ENABLE_SERVER and IU_ENABLE_FOO.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2, or (at your option)
dnl any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
dnl

dnl IU_FLUSHLEFT -- remove all whitespace at the beginning of lines
dnl This is useful for c-code which may include cpp statements
dnl
define([IU_FLUSHLEFT],
 [changequote(`,')dnl
patsubst(`$1', `^[ 	]+')
changequote([,])])dnl

dnl IU_RESULT_ACTIONS -- generate shell code for the result of a test
dnl   $1 -- CVAR  -- cache variable to check
dnl   $2 -- NAME  -- if not empty, used to generate a default value TRUE:
dnl                  `AC_DEFINE(HAVE_NAME)'
dnl   $2 -- TRUE  -- what to do if the CVAR is `yes'
dnl   $3 -- FALSE -- what to do otherwise; defaults to `:'
dnl
AC_DEFUN([IU_RESULT_ACTIONS], [
[if test "$$1" = yes; then
  ]ifelse([$3], ,
          [AC_DEFINE(HAVE_]translit($2, [a-z ./<>], [A-Z___])[, 1,
	             [FIXME])],
          [$3])[
else
  ]ifelse([$4], , [:], [$4])[
fi]])dnl

dnl IU_CHECK_DEFINE -- Check for cpp defines
dnl   $1 - NAME   -- printed in message
dnl   $2 - INCLS  -- C program text to inculde necessary files for testing
dnl   $3 - MACROS -- a space-separated list of macros that all must be defined
dnl		     defaults to NAME
dnl   $4 - TRUE	  -- what to do if all macros are defined; defaults to 
dnl		     AC_DEFINE(upcase(HAVE_$1))
dnl   $5 - FALSE  -- what to do if some macros aren't defined
dnl
AC_DEFUN([IU_CHECK_MACRO], [
  define([IU_CVAR], [inetutils_cv_macro_]translit($1, [A-Z ./<>], [a-z___]))dnl
  define([IU_TAG], [IU_CHECK_MACRO_]translit($1, [a-z ./<>], [A-Z___]))dnl
  AC_CACHE_CHECK([for $1], IU_CVAR,
    AC_EGREP_CPP(IU_TAG,
      IU_FLUSHLEFT(
[$2
#if ]dnl
changequote(<<,>>)dnl
patsubst(patsubst(ifelse(<<$3>>, , <<$1>>, <<$3>>),
	          <<\>[ ,]+\<>>, << && >>),
         <<\w+>>, <<defined(\&)>>) dnl
changequote([,])dnl
[
]IU_TAG[
#endif]),
      IU_CVAR[=yes],
      IU_CVAR[=no])) dnl
  IU_RESULT_ACTIONS(IU_CVAR, [$1], [$4], [$5]) dnl
  undefine([IU_CVAR]) undefine([IU_TAG])])dnl

dnl 
dnl Following are some more specific tests
dnl

dnl IU_CHECK_WEAK_REFS -- See if any of a variety of `weak reference'
dnl mechanisms works.  If so, this defines HAVE_WEAK_REFS, and one of
dnl HAVE_ATTR_WEAK_REFS, HAVE_PRAGMA_WEAK_REFS, or HAVE_ASM_WEAK_REFS to
dnl indicate which sort.
dnl
dnl This can't just be a compile-check, as gcc somtimes accepts the syntax even
dnl feature isn't actually supported.
dnl
AC_DEFUN([IU_CHECK_WEAK_REFS], [
  AH_TEMPLATE(HAVE_WEAK_REFS, 1, [Define if you have weak references])
  AC_CACHE_CHECK(whether gcc weak references work,
		 inetutils_cv_attr_weak_refs,
    AC_TRY_LINK([],
      [extern char *not_defined (char *, char *) __attribute__ ((weak));
	if (not_defined) puts ("yes"); ],
      [inetutils_cv_attr_weak_refs=yes],
      [inetutils_cv_attr_weak_refs=no]))
  if test "$inetutils_cv_weak_refs" = yes; then
    AC_DEFINE(HAVE_WEAK_REFS)
    AC_DEFINE(HAVE_ATTR_WEAK_REFS, 1,
              [Define if you have weak "attribute" references])
  else
    AC_CACHE_CHECK(whether pragma weak references work,
		   inetutils_cv_pragma_weak_refs,
      AC_TRY_LINK([],
	[extern char *not_defined (char *, char *);
#pragma weak not_defined
	 if (not_defined) puts ("yes"); ],
	[inetutils_cv_pragma_weak_refs=yes],
	[inetutils_cv_pragma_weak_refs=no]))
    if test "$inetutils_cv_pragma_weak_refs" = yes; then
      AC_DEFINE(HAVE_WEAK_REFS)
      AC_DEFINE(HAVE_PRAGMA_WEAK_REFS, 1,
                [Define if you have weak "pragma" references])
    else
      AC_CACHE_CHECK(whether asm weak references work,
		     inetutils_cv_asm_weak_refs,
	AC_TRY_LINK([],
	  [extern char *not_defined (char *, char *);
	   asm (".weak not_defined");
	   if (not_defined) puts ("yes"); ],
	  [inetutils_cv_asm_weak_refs=yes],
	  [inetutils_cv_asm_weak_refs=no]))
      if test "$inetutils_cv_asm_weak_refs" = yes; then
	AC_DEFINE(HAVE_WEAK_REFS)
	AC_DEFINE(HAVE_ASM_WEAK_REFS, 1,
	          [Define if you have weak "assembler" references])
      fi
    fi
  fi])dnl

dnl IU_LIB_NCURSES -- check for, and configure, ncurses
dnl
dnl If libncurses is found to exist on this system and the --disable-ncurses
dnl flag wasn't specified, defines LIBNCURSES with the appropriate linker
dnl specification, and possibly defines NCURSES_INCLUDE with the appropriate
dnl -I flag to get access to ncurses include files.
dnl
AC_DEFUN([IU_LIB_NCURSES], [
  AC_ARG_ENABLE(ncurses,    [  --disable-ncurses       don't prefer -lncurses over -lcurses],
              , enable_ncurses=yes)
  if test "$enable_ncurses" = yes; then
    AC_CHECK_LIB(ncurses, initscr, LIBNCURSES="-lncurses")
    if test "$LIBNCURSES"; then
      # Use ncurses header files instead of the ordinary ones, if possible;
      # is there a better way of doing this, that avoids looking in specific
      # directories?
      AC_ARG_WITH(ncurses-include-dir,
[  --with-ncurses-include-dir=DIR
                          Set directory containing the include files for
                          use with -lncurses, when it isn't installed as
                          the default curses library.  If DIR is "none",
                          then no special ncurses include files are used.
  --without-ncurses-include-dir
                          Equivalent to --with-ncurses-include-dir=none])dnl
      if test "${with_ncurses_include_dir+set}" = set; then
        AC_MSG_CHECKING(for ncurses include dir)
	case "$with_ncurses_include_dir" in
	  no|none)
	    inetutils_cv_includedir_ncurses=none;;
	  *)
	    inetutils_cv_includedir_ncurses="$with_ncurses_include_dir";;
	esac
        AC_MSG_RESULT($inetutils_cv_includedir_ncurses)
      else
	AC_CACHE_CHECK(for ncurses include dir,
		       inetutils_cv_includedir_ncurses,
	  for D in $includedir $prefix/include /local/include /usr/local/include /include /usr/include; do
	    if test -d $D/ncurses; then
	      inetutils_cv_includedir_ncurses="$D/ncurses"
	      break
	    fi
	    test "$inetutils_cv_includedir_ncurses" \
	      || inetutils_cv_includedir_ncurses=none
	  done)
      fi
      if test "$inetutils_cv_includedir_ncurses" = none; then
        NCURSES_INCLUDE=""
      else
        NCURSES_INCLUDE="-I$inetutils_cv_includedir_ncurses"
      fi
    fi
  fi
  AC_SUBST(NCURSES_INCLUDE)
  AC_SUBST(LIBNCURSES)])dnl

dnl IU_LIB_TERMCAP -- check for various termcap libraries
dnl
dnl Checks for various common libraries implementing the termcap interface,
dnl including ncurses (unless --disable ncurses is specified), curses (which
dnl does on some systems), termcap, and termlib.  If termcap is found, then
dnl LIBTERMCAP is defined with the appropriate linker specification.
dnl 
AC_DEFUN([IU_LIB_TERMCAP], [
  AC_REQUIRE([IU_LIB_NCURSES])
  if test "$LIBNCURSES"; then
    LIBTERMCAP="$LIBNCURSES"
  else
    AC_CHECK_LIB(curses, tgetent, LIBTERMCAP=-lcurses)
    if test "$ac_cv_lib_curses_tgetent" = no; then
      AC_CHECK_LIB(termcap, tgetent, LIBTERMCAP=-ltermcap)
    fi
    if test "$ac_cv_lib_termcap_tgetent" = no; then
      AC_CHECK_LIB(termlib, tgetent, LIBTERMCAP=-ltermlib)
    fi
  fi
  AC_SUBST(LIBTERMCAP)])dnl

dnl IU_LIB_CURSES -- checke for curses, and associated libraries
dnl
dnl Checks for varions libraries implementing the curses interface, and if
dnl found, defines LIBCURSES to be the appropriate linker specification,
dnl *including* any termcap libraries if needed (some versions of curses
dnl don't need termcap).
dnl
AC_DEFUN([IU_LIB_CURSES], [
  AC_REQUIRE([IU_LIB_TERMCAP])
  AC_REQUIRE([IU_LIB_NCURSES])
  if test "$LIBNCURSES"; then
    LIBCURSES="$LIBNCURSES"	# ncurses doesn't require termcap
  else
    _IU_SAVE_LIBS="$LIBS"
    LIBS="$LIBTERMCAP"
    AC_CHECK_LIB(curses, initscr, LIBCURSES="-lcurses")
    if test "$LIBCURSES" -a "$LIBTERMCAP" -a "$LIBCURSES" != "$LIBTERMCAP"; then
      AC_CACHE_CHECK(whether curses needs $LIBTERMCAP,
		     inetutils_cv_curses_needs_termcap,
	LIBS="$LIBCURSES"
	AC_TRY_LINK([#include <curses.h>], [initscr ();],
		    [inetutils_cv_curses_needs_termcap=no],
		    [inetutils_cv_curses_needs_termcap=yes]))
      if test $inetutils_cv_curses_needs_termcap = yes; then
	  LIBCURSES="$LIBCURSES $LIBTERMCAP"
      fi
    fi
    LIBS="$_IU_SAVE_LIBS"
  fi
  AC_SUBST(LIBCURSES)])dnl

dnl IU_CONFIG_PATHS -- Configure system paths for use by programs
dnl   $1 - PATHS    -- The file to read containing the paths
dnl   $2 - MAKEDEFS -- The file to generate containing make `PATHDEF_' vars
dnl   $3 - HDRDEFS  -- The file to generate containing c header stuff
dnl
dnl From the paths listed in the file PATHS, generate a file of make input
dnl (MAKEDEFS) containing a make variable for each PATH_FOO, called
dnl PATHDEF_FOO, which is set to a cpp option to define that path, unless it
dnl is to be defined using a system define, in which case the
dnl corresponding make variable is empty.  A file called HDRDEFS will also be
dnl generated containing cpp statements.  For each PATH_FOO which is found
dnl to be available as a system define, a statement will be generated which
dnl defines it to be that system define, unless it is already defined (which
dnl will be case if overridden by make).
dnl
AC_DEFUN([IU_CONFIG_PATHS], [
  dnl We need to know if we're cross compiling.
  AC_REQUIRE([AC_PROG_CC])

  AC_CHECK_HEADER(paths.h, AC_DEFINE(HAVE_PATHS_H, 1,
        [Define if you have the <paths.h> header file]) iu_paths_h="<paths.h>")

  dnl A slightly bogus use of AC_ARG_WITH; we never actually use
  dnl $with_PATHVAR, we just want to get this entry put into the help list.
  dnl We actually look for `with_' variables corresponding to each path
  dnl configured.
  AC_ARG_WITH(PATHVAR,
[  --with-PATHVAR=PATH     Set the value of PATHVAR to PATH
                          PATHVAR is the name of a \`PATH_FOO' variable,
                          downcased, with \`_' changed to \`-'
  --without-PATHVAR       Never define PATHVAR by any method])dnl

  iu_cache_file="/tmp/,iu-path-cache.$$"
  iu_tmp_file="/tmp/,iu-tmp.$$"
  ac_clean_files="$ac_clean_files $iu_cache_file $iu_tmp_file"
  while read iu_path iu_search; do
    test "$iu_path" = "#" -o -z "$iu_path" && continue

    iu_pathvar="`echo $iu_path  | sed y/${IU_UCASE}/${iu_lcase}/`"
    AC_MSG_CHECKING(for value of $iu_path)

    iu_val='' iu_hdr='' iu_sym=''
    iu_cached='' iu_defaulted=''
    iu_cross_conflict=''
    if test "`eval echo '$'{with_$iu_pathvar+set}`" = set; then
      # User-supplied value
      eval iu_val=\"'$'with_$iu_pathvar\"
    elif test "`eval echo '$'{inetutils_cv_$iu_pathvar+set}`" = set; then
      # Cached value
      eval iu_val=\"'$'inetutils_cv_$iu_pathvar\"
      # invert escaped $(...) notation used in autoconf cache
      eval iu_val=\"\`echo \'"$iu_val"\' \| sed \''s/@(/$\(/g'\'\`\"
      iu_cached="(cached) "
    elif test "`eval echo '$'{inetutils_cv_hdr_$iu_pathvar+set}`" = set; then
      # Cached non-value
      eval iu_hdr=\"'$'inetutils_cv_hdr_$iu_pathvar\"
      eval iu_sym=\"'$'inetutils_cv_hdr_sym_$iu_pathvar\"
      iu_cached="(cached) "
    else
      # search for a reasonable value

      iu_test_type=r		# `exists'
      iu_default='' iu_prev_cross_test=''
      for iu_try in $iu_paths_h $iu_search; do
	iu_cross_test=''
	case "$iu_try" in
	  "<"*">"*)
	    # <HEADER.h> and <HEADER.h>:SYMBOL -- look for SYMBOL in <HEADER.h>
	    # SYMBOL defaults to _$iu_path (e.g., _PATH_FOO)
	    changequote(,)	dnl Avoid problems with [ ] in regexps
	    eval iu_hdr=\'`echo "$iu_try" |sed 's/:.*$//'`\'
	    eval iu_sym=\'`echo "$iu_try" |sed -n 's/^<[^>]*>:\(.*\)$/\1/p'`\'
	    changequote([,])
	    test "$iu_sym" || iu_sym="_$iu_path"
	    AC_EGREP_CPP(HAVE_$iu_sym,
[#include ]$iu_hdr[
#ifdef $iu_sym
HAVE_$iu_sym
#endif],
	      :, iu_hdr='' iu_sym='')
	    ;;

	  search:*)
	    # Do a path search.  The syntax here is: search:NAME[:PATH]...

	    # Path searches always generate potential conflicts
	    test "$cross_compiling" = yes && { iu_cross_conflict=yes; continue; }

	    changequote(,)	dnl Avoid problems with [ ] in regexps
	    iu_name="`echo $iu_try | sed 's/^search:\([^:]*\).*$/\1/'`"
	    iu_spath="`echo $iu_try | sed 's/^search:\([^:]*\)//'`"
	    changequote([,])

	    test "$iu_spath" || iu_spath="$PATH"

	    for iu_dir in `echo "$iu_spath" | sed 'y/:/ /'`; do
	      test -z "$iu_dir" && iu_dir=.
	      if test -$iu_test_type "$iu_dir/$iu_name"; then
		iu_val="$iu_dir/$iu_name"
		break
	      fi
	    done
	    ;;

	  no) iu_default=no;;
	  x|d|f|c|b) iu_test_type=$iu_try;;

	  *)
	    # Just try the given name, with make-var substitution.  Besides 
	    # yielding a value if found, this also sets the default.

	    case "$iu_try" in "\""*"\"")
	      # strip off quotes
	      iu_try="`echo $iu_try | sed -e 's/^.//' -e 's/.$//'`"
	    esac

	    test -z "$iu_default" && iu_default="$iu_try"
	    test "$cross_compiling" = yes && { iu_cross_test=yes; continue; }

	    # See if the value begins with a $(FOO)/${FOO} make variable
	    # corresponding to a shell variable, and if so set try_exp to the
	    # value thereof.  Recurse.
	    iu_try_exp="$iu_try"
	    changequote(,)
	    iu_try_var="`echo "$iu_try_exp" |sed -n 's;^\$[({]\([-_a-zA-Z]*\)[)}].*;\1;p'`"
	    while eval test \"$iu_try_var\" && eval test '${'$iu_try_var'+set}'; do
	      # yes, and there's a corresponding shell variable, which substitute
	      if eval test \"'$'"$iu_try_var"\" = NONE; then
		# Not filled in by configure yet
		case "$iu_try_var" in
		  prefix | exec_prefix)
		    iu_try_exp="$ac_default_prefix`echo "$iu_try_exp" |sed 's;^\$[({][-_a-zA-Z]*[)}];;'`";;
		esac
		iu_try_var=''	# Stop expansion here
	      else
		# Use the actual value of the shell variable
		eval iu_try_exp=\"`echo "$iu_try_exp" |sed 's;^\$[({]\([-_a-zA-Z]*\)[)}];\$\1;'`\"
		iu_try_var="`echo "$iu_try_exp" |sed -n 's;^\$[({]\([-_a-zA-Z]*\)[)}].*;\1;p'`"
	      fi
	    done
	    changequote([,])

	    test -$iu_test_type "$iu_try_exp" && iu_val="$iu_try"
	    ;;

	esac

	test "$iu_val" -o "$iu_hdr" && break
	test "$iu_cross_test" -a "$iu_prev_cross_test" && iu_cross_conflict=yes
	iu_prev_cross_test=$iu_cross_test
      done

      if test -z "$iu_val" -a -z "$iu_hdr"; then
	if test -z "$iu_default"; then
	  iu_val=no
	else
	  iu_val="$iu_default"
	  iu_defaulted="(default) "
	fi
      fi
    fi

    if test "$iu_val"; then
      AC_MSG_RESULT(${iu_cached}${iu_defaulted}$iu_val)
      test "$iu_cross_conflict" -a "$iu_defaulted" \
	&& AC_MSG_WARN(may be incorrect because of cross-compilation)
      # Put the value in the autoconf cache.  We replace $( with @( to avoid
      # variable evaluation problems when autoconf reads the cache later.
      echo inetutils_cv_$iu_pathvar=\'"`echo "$iu_val" | sed 's/\$(/@(/g'`"\'
    elif test "$iu_hdr"; then
      AC_MSG_RESULT(${iu_cached}from $iu_sym in $iu_hdr)
      echo inetutils_cv_hdr_$iu_pathvar=\'"$iu_hdr"\'
      echo inetutils_cv_hdr_sym_$iu_pathvar=\'"$iu_sym"\'
    fi
  done <[$1] >$iu_cache_file

  # Read the cache values constructed by the previous loop, 
  . $iu_cache_file

  # Construct the pathdefs file -- a file of make variable definitions, of
  # the form PATHDEF_FOO, that contain cc -D switches to define the cpp macro
  # PATH_FOO.
  grep -v '^inetutils_cv_hdr_' < $iu_cache_file | \
  while read iu_cache_set; do
    iu_var="`echo $iu_cache_set | sed 's/=.*$//'`"
    eval iu_val=\"'$'"$iu_var"\"
    # invert escaped $(...) notation used in autoconf cache
    eval iu_val=\"\`echo \'"$iu_val"\' \| sed \''s/@(/$\(/g'\'\`\"
    if test "$iu_val" != no; then
      iu_path="`echo $iu_var | sed -e 's/^inetutils_cv_//' -e y/${iu_lcase}/${IU_UCASE}/`"
      iu_pathdef="`echo $iu_path | sed 's/^PATH_/PATHDEF_/'`"
      echo $iu_pathdef = -D$iu_path='\"'"$iu_val"'\"'
      AC_DEFINE_UNQUOTED($iu_path, "$iu_val")
    fi
  done >$[$2]
  AC_SUBST_FILE([$2])

  # Generate a file of #ifdefs that defaults PATH_FOO macros to _PATH_FOO (or
  # some other symbol) (excluding any who's value is set to `no').
  grep '^inetutils_cv_hdr_sym_' < $iu_cache_file | \
  while read iu_cache_set; do
    iu_sym_var="`echo "$iu_cache_set" | sed 's/=.*$//'`"
    eval iu_sym=\"'$'"$iu_sym_var"\"
    iu_path="`echo $iu_sym_var | sed -e 's/^inetutils_cv_hdr_sym_//' -e y/${iu_lcase}/${IU_UCASE}/`"
    cat <<EOF
#ifndef $iu_path
#define $iu_path $iu_sym
#endif
EOF
  done >$[$3]
  AC_SUBST_FILE([$3])])

AC_DEFUN([IU_ENABLE_FOO],
 [AC_ARG_ENABLE($1, [  --disable-$1               don't compile $1], ,
                [enable_]$1[=$enable_]$2)
[if test "$enable_$1" = yes; then 
   $1_BUILD=$1
else
   $1_BUILD=''
fi;]
  AC_SUBST([$1_BUILD])
])

AC_DEFUN([IU_ENABLE_CLIENT], [IU_ENABLE_FOO($1, clients)])
AC_DEFUN([IU_ENABLE_SERVER], [IU_ENABLE_FOO($1, servers)])

#serial 12

dnl Initially derived from code in GNU grep.
dnl Mostly written by Jim Meyering.

dnl Usage: jm_INCLUDED_REGEX([lib/regex.c])
dnl
AC_DEFUN([jm_INCLUDED_REGEX],
  [
    dnl Even packages that don't use regex.c can use this macro.
    dnl Of course, for them it doesn't do anything.

    # Assume we'll default to using the included regex.c.
    ac_use_included_regex=yes

    # However, if the system regex support is good enough that it passes the
    # the following run test, then default to *not* using the included regex.c.
    # If cross compiling, assume the test would fail and use the included
    # regex.c.  The first failing regular expression is from `Spencer ere
    # test #75' in grep-2.3.
    AC_CACHE_CHECK([for working re_compile_pattern],
		   jm_cv_func_working_re_compile_pattern,
      AC_TRY_RUN(
[#include <stdio.h>
#include <regex.h>
	  int
	  main ()
	  {
	    static struct re_pattern_buffer regex;
	    const char *s;
	    struct re_registers regs;
	    re_set_syntax (RE_SYNTAX_POSIX_EGREP);
	    [s = re_compile_pattern ("a[[:@:>@:]]b\n", 9, &regex);]
	    /* This should fail with _Invalid character class name_ error.  */
	    if (!s)
	      exit (1);

	    /* This should succeed, but doesn't for e.g. glibc-2.1.3.  */
	    s = re_compile_pattern ("{1", 2, &regex);

	    if (s)
	      exit (1);

	    /* The following example is derived from a problem report
               against gawk from Jorge Stolfi <stolfi@ic.unicamp.br>.  */
	    s = re_compile_pattern ("[[anù]]*n", 7, &regex);
	    if (s)
	      exit (1);

	    /* This should match, but doesn't for e.g. glibc-2.2.1.  */
	    if (re_match (&regex, "an", 2, 0, &regs) != 2)
	      exit (1);

	    exit (0);
	  }
	],
	       jm_cv_func_working_re_compile_pattern=yes,
	       jm_cv_func_working_re_compile_pattern=no,
	       dnl When crosscompiling, assume it's broken.
	       jm_cv_func_working_re_compile_pattern=no))
    if test $jm_cv_func_working_re_compile_pattern = yes; then
      ac_use_included_regex=no
    fi

    test -n "$1" || AC_MSG_ERROR([missing argument])
    m4_syscmd([test -f $1])
    ifelse(m4_sysval, 0,
      [
	AC_ARG_WITH(included-regex,
	[  --without-included-regex don't compile regex; this is the default on
                          systems with version 2 of the GNU C library
                          (use with caution on other system)],
		    jm_with_regex=$withval,
		    jm_with_regex=$ac_use_included_regex)
	if test "$jm_with_regex" = yes; then
	  AC_LIBOBJ(regex)
	fi
      ],
    )
  ]
)

dnl IU_CHECK_KRB5(VERSION,PREFIX)
dnl Search for a Kerberos implementation in the standard locations plus PREFIX,
dnl if it is set and not "yes".
dnl VERSION should be either 4 or 5
dnl Defines KRB_CFLAGS and KRB_LIBS if found.
dnl Defines KRB_IMPL to "Heimdal", "MIT", or "OldMIT", or "none" if not found
AC_DEFUN(IU_CHECK_KRB5,
[
 if test "x$iu_cv_lib_krb5_libs" = x; then
  cache=""
  KRB5_PREFIX=[$2]
  KRB5_IMPL="none"
  # First try krb5-config
  if test "$KRB5_PREFIX" != "yes"; then
    krb5_path="$KRB5_PREFIX/bin"
  else
    krb5_path="$PATH"
  fi
  AC_PATH_PROG(KRB5CFGPATH, krb5-config, none, $krb5_path)
  if test "$KRB5CFGPATH" != "none"; then
    KRB5_CFLAGS="$CPPFLAGS `$KRB5CFGPATH --cflags krb$1`"
    KRB5_LIBS="$LDFLAGS `$KRB5CFGPATH --libs krb$1`"
    KRB5_IMPL="Heimdal"
  else
    ## OK, try the old code
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LDFLAGS="$LDFLAGS"
    saved_LIBS="$LIBS"
    if test "$KRB5_PREFIX" != "yes"; then
      KRB5_CFLAGS="-I$KRB5_PREFIX/include"
      KRB5_LDFLAGS="-L$KRB5_PREFIX/lib"
      CPPFLAGS="$CPPFLAGS $KRB5_CFLAGS"
      LDFLAGS="$LDFLAGS $KRB5_LDFLAGS"
    fi

    ## Check for new MIT kerberos V support
    AC_CHECK_LIB(krb5, krb5_init_context,
      [KRB5_IMPL="MIT",
       KRB5_LIBS="$KRB5_LDFLAGS -lkrb5 -lk5crypto -lcom_err"]
       ,, -lk5crypto -lcom_err)

    ## Heimdal kerberos V support
    if test "$KRB5_IMPL" = "none"; then
      AC_CHECK_LIB(krb5, krb5_init_context,
        [KRB5_IMPL="Heimdal"
         KRB5_LIBS="$KRB5_LDFLAGS -lkrb5 -ldes -lasn1 -lroken -lcrypt -lcom_err"]
         ,, -ldes -lasn1 -lroken -lcrypt -lcom_err)
    fi

    ## Old MIT Kerberos V
    ## Note: older krb5 distributions use -lcrypto instead of
    ## -lk5crypto. This may conflict with OpenSSL.
    if test "$KRB5_IMPL" = "none"; then
      AC_CHECK_LIB(krb5, krb5_init_context,
        [KRB5_IMPL="OldMIT",
         KRB5_LIBS="$KRB5_LDFLAGS -lkrb5 -lkrb5 -lcrypto -lcom_err"]
        ,, -lcrypto -lcom_err)
    fi
  fi

  iu_cv_lib_krb5_cflags="$KRB5_CFLAGS"
  iu_cv_lib_krb5_libs="$KRB5_LIBS"
  iu_cv_lib_krb5_impl="$KRB5_IMPL"

  LDFLAGS="$saved_LDFLAGS"
  LIBS="$saved_LIBS"
 else
  cached=" (cached) "
  KRB5_CFLAGS="$iu_cv_lib_krb5_cflags"
  KRB5_LIBS="$iu_cv_lib_krb5_libs"
  KRB5_IMPL="$iu_cv_lib_krb5_impl"
 fi
 AC_MSG_CHECKING(krb5 implementation)
 AC_MSG_RESULT(${cached}$KRB5_IMPL)
])

dnl IU_CHECK_MEMBER(AGGREGATE.MEMBER,
dnl                [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
dnl                [INCLUDES])
dnl AGGREGATE.MEMBER is for instance `struct passwd.pw_gecos'.
dnl The member itself can be of an aggregate type
dnl Shell variables are not a valid argument.
AC_DEFUN([IU_CHECK_MEMBER],
[AS_LITERAL_IF([$1], [],
               [AC_FATAL([$0: requires literal arguments])])dnl
m4_bmatch([$1], [\.], ,
         [m4_fatal([$0: Did not see any dot in `$1'])])dnl
AS_VAR_PUSHDEF([ac_Member], [ac_cv_member_$1])dnl
dnl Extract the aggregate name, and the member name
AC_CACHE_CHECK([for $1], ac_Member,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT([$4])],
[dnl AGGREGATE ac_aggr;
static m4_bpatsubst([$1], [\..*]) ac_aggr;
dnl ac_aggr.MEMBER;
if (sizeof(ac_aggr.m4_bpatsubst([$1], [^[^.]*\.])))
return 0;])],
                [AS_VAR_SET(ac_Member, yes)],
                [AS_VAR_SET(ac_Member, no)])])
AS_IF([test AS_VAR_GET(ac_Member) = yes], [$2], [$3])dnl
AS_VAR_POPDEF([ac_Member])dnl
])dnl IU_CHECK_MEMBER


dnl IU_CHECK_MEMBERS([AGGREGATE.MEMBER, ...],
dnl                  [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND]
dnl                  [INCLUDES])
AC_DEFUN([IU_CHECK_MEMBERS],
[m4_foreach([AC_Member], [$1],
  [IU_CHECK_MEMBER(AC_Member,
         [AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_[]AC_Member), 1,
                            [Define to 1 if `]m4_bpatsubst(AC_Member,
                                                     [^[^.]*\.])[' is
                             member of `]m4_bpatsubst(AC_Member, [\..*])['.])
$2],
                 [$3],
                 [$4])])])

# Like AC_CONFIG_HEADER, but automatically create stamp file. -*- Autoconf -*-

# Copyright 1996, 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_PREREQ([2.52])

# serial 6

# AM_CONFIG_HEADER is obsolete.  It has been replaced by AC_CONFIG_HEADERS.
AU_DEFUN([AM_CONFIG_HEADER], [AC_CONFIG_HEADERS($@)])

# Do all the work for Automake.                            -*- Autoconf -*-

# This macro actually does too much some checks are only needed if
# your package does certain things.  But this isn't really a big deal.

# Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 8

# There are a few dirty hacks below to avoid letting `AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...


AC_PREREQ([2.54])

# Autoconf 2.50 wants to disallow AM_ names.  We explicitly allow
# the ones we care about.
m4_pattern_allow([^AM_[A-Z]+FLAGS$])dnl

# AM_INIT_AUTOMAKE(PACKAGE, VERSION, [NO-DEFINE])
# AM_INIT_AUTOMAKE([OPTIONS])
# -----------------------------------------------
# The call with PACKAGE and VERSION arguments is the old style
# call (pre autoconf-2.50), which is being phased out.  PACKAGE
# and VERSION should now be passed to AC_INIT and removed from
# the call to AM_INIT_AUTOMAKE.
# We support both call styles for the transition.  After
# the next Automake release, Autoconf can make the AC_INIT
# arguments mandatory, and then we can depend on a new Autoconf
# release and drop the old call support.
AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
 AC_REQUIRE([AC_PROG_INSTALL])dnl
# test to see if srcdir already configured
if test "`cd $srcdir && pwd`" != "`pwd`" &&
   test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
fi

# test whether we have cygpath
if test -z "$CYGPATH_W"; then
  if (cygpath --version) >/dev/null 2>/dev/null; then
    CYGPATH_W='cygpath -w'
  else
    CYGPATH_W=echo
  fi
fi
AC_SUBST([CYGPATH_W])

# Define the identity of the package.
dnl Distinguish between old-style and new-style calls.
m4_ifval([$2],
[m4_ifval([$3], [_AM_SET_OPTION([no-define])])dnl
 AC_SUBST([PACKAGE], [$1])dnl
 AC_SUBST([VERSION], [$2])],
[_AM_SET_OPTIONS([$1])dnl
 AC_SUBST([PACKAGE], [AC_PACKAGE_TARNAME])dnl
 AC_SUBST([VERSION], [AC_PACKAGE_VERSION])])dnl

_AM_IF_OPTION([no-define],,
[AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
 AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package])])dnl

# Some tools Automake needs.
AC_REQUIRE([AM_SANITY_CHECK])dnl
AC_REQUIRE([AC_ARG_PROGRAM])dnl
AM_MISSING_PROG(ACLOCAL, aclocal-${am__api_version})
AM_MISSING_PROG(AUTOCONF, autoconf)
AM_MISSING_PROG(AUTOMAKE, automake-${am__api_version})
AM_MISSING_PROG(AUTOHEADER, autoheader)
AM_MISSING_PROG(MAKEINFO, makeinfo)
AM_MISSING_PROG(AMTAR, tar)
AM_PROG_INSTALL_SH
AM_PROG_INSTALL_STRIP
# We need awk for the "check" target.  The system "awk" is bad on
# some platforms.
AC_REQUIRE([AC_PROG_AWK])dnl
AC_REQUIRE([AC_PROG_MAKE_SET])dnl

_AM_IF_OPTION([no-dependencies],,
[AC_PROVIDE_IFELSE([AC_PROG_CC],
                  [_AM_DEPENDENCIES(CC)],
                  [define([AC_PROG_CC],
                          defn([AC_PROG_CC])[_AM_DEPENDENCIES(CC)])])dnl
AC_PROVIDE_IFELSE([AC_PROG_CXX],
                  [_AM_DEPENDENCIES(CXX)],
                  [define([AC_PROG_CXX],
                          defn([AC_PROG_CXX])[_AM_DEPENDENCIES(CXX)])])dnl
])
])


# When config.status generates a header, we must update the stamp-h file.
# This file resides in the same directory as the config header
# that is generated.  The stamp files are numbered to have different names.

# Autoconf calls _AC_AM_CONFIG_HEADER_HOOK (when defined) in the
# loop where config.status creates the headers, so we can generate
# our stamp files there.
AC_DEFUN([_AC_AM_CONFIG_HEADER_HOOK],
[_am_stamp_count=`expr ${_am_stamp_count-0} + 1`
echo "timestamp for $1" >`AS_DIRNAME([$1])`/stamp-h[]$_am_stamp_count])

# Copyright 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
AC_DEFUN([AM_AUTOMAKE_VERSION],[am__api_version="1.7"])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION so it can be traced.
# This function is AC_REQUIREd by AC_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
	 [AM_AUTOMAKE_VERSION([1.7.2])])

# Helper functions for option handling.                    -*- Autoconf -*-

# Copyright 2001, 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# _AM_MANGLE_OPTION(NAME)
# -----------------------
AC_DEFUN([_AM_MANGLE_OPTION],
[[_AM_OPTION_]m4_bpatsubst($1, [[^a-zA-Z0-9_]], [_])])

# _AM_SET_OPTION(NAME)
# ------------------------------
# Set option NAME.  Presently that only means defining a flag for this option.
AC_DEFUN([_AM_SET_OPTION],
[m4_define(_AM_MANGLE_OPTION([$1]), 1)])

# _AM_SET_OPTIONS(OPTIONS)
# ----------------------------------
# OPTIONS is a space-separated list of Automake options.
AC_DEFUN([_AM_SET_OPTIONS],
[AC_FOREACH([_AM_Option], [$1], [_AM_SET_OPTION(_AM_Option)])])

# _AM_IF_OPTION(OPTION, IF-SET, [IF-NOT-SET])
# -------------------------------------------
# Execute IF-SET if OPTION is set, IF-NOT-SET otherwise.
AC_DEFUN([_AM_IF_OPTION],
[m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])

#
# Check to make sure that the build environment is sane.
#

# Copyright 1996, 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 3

# AM_SANITY_CHECK
# ---------------
AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Just in case
sleep 1
echo timestamp > conftest.file
# Do `set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   set X `ls -Lt $srcdir/configure conftest.file 2> /dev/null`
   if test "$[*]" = "X"; then
      # -L didn't work.
      set X `ls -t $srcdir/configure conftest.file`
   fi
   rm -f conftest.file
   if test "$[*]" != "X $srcdir/configure conftest.file" \
      && test "$[*]" != "X conftest.file $srcdir/configure"; then

      # If neither matched, then we have a broken ls.  This can happen
      # if, for instance, CONFIG_SHELL is bash and it inherits a
      # broken ls alias from the environment.  This has actually
      # happened.  Such a system could not be considered "sane".
      AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
alias in your environment])
   fi

   test "$[2]" = conftest.file
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
AC_MSG_RESULT(yes)])

#  -*- Autoconf -*-


# Copyright 1997, 1999, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 3

# AM_MISSING_PROG(NAME, PROGRAM)
# ------------------------------
AC_DEFUN([AM_MISSING_PROG],
[AC_REQUIRE([AM_MISSING_HAS_RUN])
$1=${$1-"${am_missing_run}$2"}
AC_SUBST($1)])


# AM_MISSING_HAS_RUN
# ------------------
# Define MISSING if not defined so far and test if it supports --run.
# If it does, set am_missing_run to use it, otherwise, to nothing.
AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
test x"${MISSING+set}" = xset || MISSING="\${SHELL} $am_aux_dir/missing"
# Use eval to expand $SHELL
if eval "$MISSING --run true"; then
  am_missing_run="$MISSING --run "
else
  am_missing_run=
  AC_MSG_WARN([`missing' script is too old or missing])
fi
])

# AM_AUX_DIR_EXPAND

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# For projects using AC_CONFIG_AUX_DIR([foo]), Autoconf sets
# $ac_aux_dir to `$srcdir/foo'.  In other projects, it is set to
# `$srcdir', `$srcdir/..', or `$srcdir/../..'.
#
# Of course, Automake must honor this variable whenever it calls a
# tool from the auxiliary directory.  The problem is that $srcdir (and
# therefore $ac_aux_dir as well) can be either absolute or relative,
# depending on how configure is run.  This is pretty annoying, since
# it makes $ac_aux_dir quite unusable in subdirectories: in the top
# source directory, any form will work fine, but in subdirectories a
# relative path needs to be adjusted first.
#
# $ac_aux_dir/missing
#    fails when called from a subdirectory if $ac_aux_dir is relative
# $top_srcdir/$ac_aux_dir/missing
#    fails if $ac_aux_dir is absolute,
#    fails when called from a subdirectory in a VPATH build with
#          a relative $ac_aux_dir
#
# The reason of the latter failure is that $top_srcdir and $ac_aux_dir
# are both prefixed by $srcdir.  In an in-source build this is usually
# harmless because $srcdir is `.', but things will broke when you
# start a VPATH build or use an absolute $srcdir.
#
# So we could use something similar to $top_srcdir/$ac_aux_dir/missing,
# iff we strip the leading $srcdir from $ac_aux_dir.  That would be:
#   am_aux_dir='\$(top_srcdir)/'`expr "$ac_aux_dir" : "$srcdir//*\(.*\)"`
# and then we would define $MISSING as
#   MISSING="\${SHELL} $am_aux_dir/missing"
# This will work as long as MISSING is not called from configure, because
# unfortunately $(top_srcdir) has no meaning in configure.
# However there are other variables, like CC, which are often used in
# configure, and could therefore not use this "fixed" $ac_aux_dir.
#
# Another solution, used here, is to always expand $ac_aux_dir to an
# absolute PATH.  The drawback is that using absolute paths prevent a
# configured tree to be moved without reconfiguration.

# Rely on autoconf to set up CDPATH properly.
AC_PREREQ([2.50])

AC_DEFUN([AM_AUX_DIR_EXPAND], [
# expand $ac_aux_dir to an absolute path
am_aux_dir=`cd $ac_aux_dir && pwd`
])

# AM_PROG_INSTALL_SH
# ------------------
# Define $install_sh.

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_DEFUN([AM_PROG_INSTALL_SH],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
install_sh=${install_sh-"$am_aux_dir/install-sh"}
AC_SUBST(install_sh)])

# AM_PROG_INSTALL_STRIP

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# One issue with vendor `install' (even GNU) is that you can't
# specify the program used to strip binaries.  This is especially
# annoying in cross-compiling environments, where the build's strip
# is unlikely to handle the host's binaries.
# Fortunately install-sh will honor a STRIPPROG variable, so we
# always use install-sh in `make install-strip', and initialize
# STRIPPROG with the value of the STRIP variable (set by the user).
AC_DEFUN([AM_PROG_INSTALL_STRIP],
[AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
# Installed binaries are usually stripped using `strip' when the user
# run `make install-strip'.  However `strip' might not be the right
# tool to use in cross-compilation environments, therefore Automake
# will honor the `STRIP' environment variable to overrule this program.
dnl Don't test for $cross_compiling = yes, because it might be `maybe'.
if test "$cross_compiling" != no; then
  AC_CHECK_TOOL([STRIP], [strip], :)
fi
INSTALL_STRIP_PROGRAM="\${SHELL} \$(install_sh) -c -s"
AC_SUBST([INSTALL_STRIP_PROGRAM])])

# serial 4						-*- Autoconf -*-

# Copyright 1999, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.


# There are a few dirty hacks below to avoid letting `AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...



# _AM_DEPENDENCIES(NAME)
# ----------------------
# See how the compiler implements dependency checking.
# NAME is "CC", "CXX", "GCJ", or "OBJC".
# We try a few techniques and use that to set a single cache variable.
#
# We don't AC_REQUIRE the corresponding AC_PROG_CC since the latter was
# modified to invoke _AM_DEPENDENCIES(CC); we would have a circular
# dependency, and given that the user is not expected to run this macro,
# just rely on AC_PROG_CC.
AC_DEFUN([_AM_DEPENDENCIES],
[AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_REQUIRE([AM_OUTPUT_DEPENDENCY_COMMANDS])dnl
AC_REQUIRE([AM_MAKE_INCLUDE])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl

ifelse([$1], CC,   [depcc="$CC"   am_compiler_list=],
       [$1], CXX,  [depcc="$CXX"  am_compiler_list=],
       [$1], OBJC, [depcc="$OBJC" am_compiler_list='gcc3 gcc'],
       [$1], GCJ,  [depcc="$GCJ"  am_compiler_list='gcc3 gcc'],
                   [depcc="$$1"   am_compiler_list=])

AC_CACHE_CHECK([dependency style of $depcc],
               [am_cv_$1_dependencies_compiler_type],
[if test -z "$AMDEP_TRUE" && test -f "$am_depcomp"; then
  # We make a subdir and do the tests there.  Otherwise we can end up
  # making bogus files that we don't know about and never remove.  For
  # instance it was reported that on HP-UX the gcc test will end up
  # making a dummy file named `D' -- because `-MD' means `put the output
  # in D'.
  mkdir conftest.dir
  # Copy depcomp to subdir because otherwise we won't find it if we're
  # using a relative directory.
  cp "$am_depcomp" conftest.dir
  cd conftest.dir

  am_cv_$1_dependencies_compiler_type=none
  if test "$am_compiler_list" = ""; then
     am_compiler_list=`sed -n ['s/^#*\([a-zA-Z0-9]*\))$/\1/p'] < ./depcomp`
  fi
  for depmode in $am_compiler_list; do
    # We need to recreate these files for each test, as the compiler may
    # overwrite some of them when testing with obscure command lines.
    # This happens at least with the AIX C compiler.
    echo '#include "conftest.h"' > conftest.c
    echo 'int i;' > conftest.h
    echo "${am__include} ${am__quote}conftest.Po${am__quote}" > confmf

    case $depmode in
    nosideeffect)
      # after this tag, mechanisms are not by side-effect, so they'll
      # only be used when explicitly requested
      if test "x$enable_dependency_tracking" = xyes; then
	continue
      else
	break
      fi
      ;;
    none) break ;;
    esac
    # We check with `-c' and `-o' for the sake of the "dashmstdout"
    # mode.  It turns out that the SunPro C++ compiler does not properly
    # handle `-M -o', and we need to detect this.
    if depmode=$depmode \
       source=conftest.c object=conftest.o \
       depfile=conftest.Po tmpdepfile=conftest.TPo \
       $SHELL ./depcomp $depcc -c -o conftest.o conftest.c >/dev/null 2>&1 &&
       grep conftest.h conftest.Po > /dev/null 2>&1 &&
       ${MAKE-make} -s -f confmf > /dev/null 2>&1; then
      am_cv_$1_dependencies_compiler_type=$depmode
      break
    fi
  done

  cd ..
  rm -rf conftest.dir
else
  am_cv_$1_dependencies_compiler_type=none
fi
])
AC_SUBST([$1DEPMODE], [depmode=$am_cv_$1_dependencies_compiler_type])
AM_CONDITIONAL([am__fastdep$1], [
  test "x$enable_dependency_tracking" != xno \
  && test "$am_cv_$1_dependencies_compiler_type" = gcc3])
])


# AM_SET_DEPDIR
# -------------
# Choose a directory name for dependency files.
# This macro is AC_REQUIREd in _AM_DEPENDENCIES
AC_DEFUN([AM_SET_DEPDIR],
[rm -f .deps 2>/dev/null
mkdir .deps 2>/dev/null
if test -d .deps; then
  DEPDIR=.deps
else
  # MS-DOS does not allow filenames that begin with a dot.
  DEPDIR=_deps
fi
rmdir .deps 2>/dev/null
AC_SUBST([DEPDIR])
])


# AM_DEP_TRACK
# ------------
AC_DEFUN([AM_DEP_TRACK],
[AC_ARG_ENABLE(dependency-tracking,
[  --disable-dependency-tracking Speeds up one-time builds
  --enable-dependency-tracking  Do not reject slow dependency extractors])
if test "x$enable_dependency_tracking" != xno; then
  am_depcomp="$ac_aux_dir/depcomp"
  AMDEPBACKSLASH='\'
fi
AM_CONDITIONAL([AMDEP], [test "x$enable_dependency_tracking" != xno])
AC_SUBST([AMDEPBACKSLASH])
])

# Generate code to set up dependency tracking.   -*- Autoconf -*-

# Copyright 1999, 2000, 2001, 2002 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

#serial 2

# _AM_OUTPUT_DEPENDENCY_COMMANDS
# ------------------------------
AC_DEFUN([_AM_OUTPUT_DEPENDENCY_COMMANDS],
[for mf in $CONFIG_FILES; do
  # Strip MF so we end up with the name of the file.
  mf=`echo "$mf" | sed -e 's/:.*$//'`
  # Check whether this is an Automake generated Makefile or not.
  # We used to match only the files named `Makefile.in', but
  # some people rename them; so instead we look at the file content.
  # Grep'ing the first line is not enough: some people post-process
  # each Makefile.in and add a new line on top of each file to say so.
  # So let's grep whole file.
  if grep '^#.*generated by automake' $mf > /dev/null 2>&1; then
    dirpart=`AS_DIRNAME("$mf")`
  else
    continue
  fi
  grep '^DEP_FILES *= *[[^ @%:@]]' < "$mf" > /dev/null || continue
  # Extract the definition of DEP_FILES from the Makefile without
  # running `make'.
  DEPDIR=`sed -n -e '/^DEPDIR = / s///p' < "$mf"`
  test -z "$DEPDIR" && continue
  # When using ansi2knr, U may be empty or an underscore; expand it
  U=`sed -n -e '/^U = / s///p' < "$mf"`
  test -d "$dirpart/$DEPDIR" || mkdir "$dirpart/$DEPDIR"
  # We invoke sed twice because it is the simplest approach to
  # changing $(DEPDIR) to its actual value in the expansion.
  for file in `sed -n -e '
    /^DEP_FILES = .*\\\\$/ {
      s/^DEP_FILES = //
      :loop
	s/\\\\$//
	p
	n
	/\\\\$/ b loop
      p
    }
    /^DEP_FILES = / s/^DEP_FILES = //p' < "$mf" | \
       sed -e 's/\$(DEPDIR)/'"$DEPDIR"'/g' -e 's/\$U/'"$U"'/g'`; do
    # Make sure the directory exists.
    test -f "$dirpart/$file" && continue
    fdir=`AS_DIRNAME(["$file"])`
    AS_MKDIR_P([$dirpart/$fdir])
    # echo "creating $dirpart/$file"
    echo '# dummy' > "$dirpart/$file"
  done
done
])# _AM_OUTPUT_DEPENDENCY_COMMANDS


# AM_OUTPUT_DEPENDENCY_COMMANDS
# -----------------------------
# This macro should only be invoked once -- use via AC_REQUIRE.
#
# This code is only required when automatic dependency tracking
# is enabled.  FIXME.  This creates each `.P' file that we will
# need in order to bootstrap the dependency handling code.
AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
[AC_CONFIG_COMMANDS([depfiles],
     [test x"$AMDEP_TRUE" != x"" || _AM_OUTPUT_DEPENDENCY_COMMANDS],
     [AMDEP_TRUE="$AMDEP_TRUE" ac_aux_dir="$ac_aux_dir"])
])

# Check to see how 'make' treats includes.	-*- Autoconf -*-

# Copyright (C) 2001, 2002 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# AM_MAKE_INCLUDE()
# -----------------
# Check to see how make treats includes.
AC_DEFUN([AM_MAKE_INCLUDE],
[am_make=${MAKE-make}
cat > confinc << 'END'
doit:
	@echo done
END
# If we don't find an include directive, just comment out the code.
AC_MSG_CHECKING([for style of include used by $am_make])
am__include="#"
am__quote=
_am_result=none
# First try GNU make style include.
echo "include confinc" > confmf
# We grep out `Entering directory' and `Leaving directory'
# messages which can occur if `w' ends up in MAKEFLAGS.
# In particular we don't look at `^make:' because GNU make might
# be invoked under some other name (usually "gmake"), in which
# case it prints its new name instead of `make'.
if test "`$am_make -s -f confmf 2> /dev/null | grep -v 'ing directory'`" = "done"; then
   am__include=include
   am__quote=
   _am_result=GNU
fi
# Now try BSD make style include.
if test "$am__include" = "#"; then
   echo '.include "confinc"' > confmf
   if test "`$am_make -s -f confmf 2> /dev/null`" = "done"; then
      am__include=.include
      am__quote="\""
      _am_result=BSD
   fi
fi
AC_SUBST(am__include)
AC_SUBST(am__quote)
AC_MSG_RESULT($_am_result)
rm -f confinc confmf
])

# AM_CONDITIONAL                                              -*- Autoconf -*-

# Copyright 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 5

AC_PREREQ(2.52)

# AM_CONDITIONAL(NAME, SHELL-CONDITION)
# -------------------------------------
# Define a conditional.
AC_DEFUN([AM_CONDITIONAL],
[ifelse([$1], [TRUE],  [AC_FATAL([$0: invalid condition: $1])],
        [$1], [FALSE], [AC_FATAL([$0: invalid condition: $1])])dnl
AC_SUBST([$1_TRUE])
AC_SUBST([$1_FALSE])
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi
AC_CONFIG_COMMANDS_PRE(
[if test -z "${$1_TRUE}" && test -z "${$1_FALSE}"; then
  AC_MSG_ERROR([conditional "$1" was never defined.
Usually this means the macro was only invoked conditionally.])
fi])])

# isc-posix.m4 serial 2 (gettext-0.11.2)
dnl Copyright (C) 1995-2002 Free Software Foundation, Inc.
dnl This file is free software, distributed under the terms of the GNU
dnl General Public License.  As a special exception to the GNU General
dnl Public License, this file may be distributed as part of a program
dnl that contains a configuration script generated by Autoconf, under
dnl the same distribution terms as the rest of that program.

# This file is not needed with autoconf-2.53 and newer.  Remove it in 2005.

# This test replaces the one in autoconf.
# Currently this macro should have the same name as the autoconf macro
# because gettext's gettext.m4 (distributed in the automake package)
# still uses it.  Otherwise, the use in gettext.m4 makes autoheader
# give these diagnostics:
#   configure.in:556: AC_TRY_COMPILE was called before AC_ISC_POSIX
#   configure.in:556: AC_TRY_RUN was called before AC_ISC_POSIX

undefine([AC_ISC_POSIX])

AC_DEFUN([AC_ISC_POSIX],
  [
    dnl This test replaces the obsolescent AC_ISC_POSIX kludge.
    AC_CHECK_LIB(cposix, strerror, [LIBS="$LIBS -lcposix"])
  ]
)


# Copyright 1996, 1997, 1998, 2000, 2001, 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

AC_DEFUN([AM_C_PROTOTYPES],
[AC_REQUIRE([AM_PROG_CC_STDC])
AC_REQUIRE([AC_PROG_CPP])
AC_MSG_CHECKING([for function prototypes])
if test "$am_cv_prog_cc_stdc" != no; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(PROTOTYPES,1,[Define if compiler has function prototypes])
  U= ANSI2KNR=
else
  AC_MSG_RESULT(no)
  U=_ ANSI2KNR=./ansi2knr
fi
# Ensure some checks needed by ansi2knr itself.
AC_HEADER_STDC
AC_CHECK_HEADERS(string.h)
AC_SUBST(U)dnl
AC_SUBST(ANSI2KNR)dnl
])

AU_DEFUN([fp_C_PROTOTYPES], [AM_C_PROTOTYPES])


# Copyright 1996, 1997, 1999, 2000, 2001, 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# @defmac AC_PROG_CC_STDC
# @maindex PROG_CC_STDC
# @ovindex CC
# If the C compiler in not in ANSI C mode by default, try to add an option
# to output variable @code{CC} to make it so.  This macro tries various
# options that select ANSI C on some system or another.  It considers the
# compiler to be in ANSI C mode if it handles function prototypes correctly.
#
# If you use this macro, you should check after calling it whether the C
# compiler has been set to accept ANSI C; if not, the shell variable
# @code{am_cv_prog_cc_stdc} is set to @samp{no}.  If you wrote your source
# code in ANSI C, you can make an un-ANSIfied copy of it by using the
# program @code{ansi2knr}, which comes with Ghostscript.
# @end defmac

AC_DEFUN([AM_PROG_CC_STDC],
[AC_REQUIRE([AC_PROG_CC])
AC_BEFORE([$0], [AC_C_INLINE])
AC_BEFORE([$0], [AC_C_CONST])
dnl Force this before AC_PROG_CPP.  Some cpp's, eg on HPUX, require
dnl a magic option to avoid problems with ANSI preprocessor commands
dnl like #elif.
dnl FIXME: can't do this because then AC_AIX won't work due to a
dnl circular dependency.
dnl AC_BEFORE([$0], [AC_PROG_CPP])
AC_MSG_CHECKING([for ${CC-cc} option to accept ANSI C])
AC_CACHE_VAL(am_cv_prog_cc_stdc,
[am_cv_prog_cc_stdc=no
ac_save_CC="$CC"
# Don't try gcc -ansi; that turns off useful extensions and
# breaks some systems' header files.
# AIX			-qlanglvl=ansi
# Ultrix and OSF/1	-std1
# HP-UX 10.20 and later	-Ae
# HP-UX older versions	-Aa -D_HPUX_SOURCE
# SVR4			-Xc -D__EXTENSIONS__
for ac_arg in "" -qlanglvl=ansi -std1 -Ae "-Aa -D_HPUX_SOURCE" "-Xc -D__EXTENSIONS__"
do
  CC="$ac_save_CC $ac_arg"
  AC_TRY_COMPILE(
[#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
/* Most of the following tests are stolen from RCS 5.7's src/conf.sh.  */
struct buf { int x; };
FILE * (*rcsopen) (struct buf *, struct stat *, int);
static char *e (p, i)
     char **p;
     int i;
{
  return p[i];
}
static char *f (char * (*g) (char **, int), char **p, ...)
{
  char *s;
  va_list v;
  va_start (v,p);
  s = g (p, va_arg (v,int));
  va_end (v);
  return s;
}
int test (int i, double x);
struct s1 {int (*f) (int a);};
struct s2 {int (*f) (double a);};
int pairnames (int, char **, FILE *(*)(struct buf *, struct stat *, int), int, int);
int argc;
char **argv;
], [
return f (e, argv, 0) != argv[0]  ||  f (e, argv, 1) != argv[1];
],
[am_cv_prog_cc_stdc="$ac_arg"; break])
done
CC="$ac_save_CC"
])
if test -z "$am_cv_prog_cc_stdc"; then
  AC_MSG_RESULT([none needed])
else
  AC_MSG_RESULT([$am_cv_prog_cc_stdc])
fi
case "x$am_cv_prog_cc_stdc" in
  x|xno) ;;
  *) CC="$CC $am_cv_prog_cc_stdc" ;;
esac
])

AU_DEFUN([fp_PROG_CC_STDC], [AM_PROG_CC_STDC])

