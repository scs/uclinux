dnl
dnl $Id: acinclude.m4,v 1.1 2008/05/06 09:35:51 asuraparaju Exp $ $Name: Dirac_1_0_0 $
dnl
AC_DEFUN([AC_TRY_CXXFLAGS],
	[AC_MSG_CHECKING([if $CXX supports $3 flags])
	SAVE_CXXFLAGS="$CXXFLAGS"
	CXXFLAGS="$3"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[$1]], [[$2]])],[ac_cv_try_cxxflags_ok=yes], [ac_cv_try_cxxflags_ok=no])
	CXXFLAGS="$SAVE_CXXFLAGS"
	AC_MSG_RESULT([$ac_cv_try_cxxflags_ok])
	if test x"$ac_cv_try_cxxflags_ok" = x"yes"; then
	ifelse([$4],[],[:],[$4])
    else
	ifelse([$5],[],[:],[$5])
    fi])

