# Configuration for inetutils
#
# Copyright (C) 1995, 1996, 1997, 1998, 2000, 2001, 2002 Free Software Foundation, Inc.
#
# Written by Miles Bader <miles@gnu.ai.mit.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

AC_PREREQ(2.54)

AC_INIT([GNU inetutils], [1.4.2], [bug-inetutils@gnu.org])

AC_CONFIG_SRCDIR([inetd/inetd.c])
AM_CONFIG_HEADER([config.h:config.hin])
AC_CANONICAL_SYSTEM # FIXME: Why not just _HOST?

# config.h turns this on, so make sure it's on for our tests too
#CPPFLAGS=-D_BSD_SOURCE

# Include files that we link into our own include directory from headers.
# Initialize it with the things we always want to use.
INCLUDES="crypt.h arpa/telnet.h arpa/ftp.h arpa/tftp.h protocols/talkd.h
	tftpsubs.h"

# Files that we link from somewhere other than headers to includes .  The
# number of entries in LINK_SRCS should match that in LINK_DSTS.
LINK_SRCS=''
LINK_DSTS=''

dnl For now, we always use libexecdir; later we may want to vary where the
dnl daemons go.
inetdaemondir='$(libexecdir)'
AC_SUBST(inetdaemondir)

AC_ARG_ENABLE(servers, [  --disable-servers       don't compile servers],
	      , enable_servers=yes)
AC_ARG_ENABLE(clients, [  --disable-clients       don't compile clients],
	      , enable_clients=yes)
AC_ARG_ENABLE(libls,   [  --disable-libls         disable support for libls ],
              , enable_libls=yes)
AC_ARG_ENABLE(encryption, [  --enable-encryption     enable encryption],
	      , enable_encryption=no)
AC_ARG_ENABLE(authentication,
              [  --enable-authentication enable connection authentication],
	      , enable_authentication=no)

AC_ARG_WITH(krb4, [  --with-krb4[[=PATH]]      Compile with Kerberos IV],
            [KERBEROS_VERSION=4
             KERBEROS_DIR=$withval])
AC_ARG_WITH(krb5, [  --with-krb5[[=PATH]]      Compile with Kerberos V],
            [KERBEROS_VERSION=5
             KERBEROS_DIR=$withval])
AC_ARG_WITH(wrap, [  --with-wrap    add tcp wrapper support])
AC_ARG_WITH(pam,  [  --with-pam    add support for PAM])

IU_ENABLE_SERVER(ftpd)
IU_ENABLE_SERVER(inetd)
IU_ENABLE_SERVER(rexecd)
IU_ENABLE_SERVER(rlogind)
IU_ENABLE_SERVER(rshd)
IU_ENABLE_SERVER(syslogd)
IU_ENABLE_SERVER(talkd)
IU_ENABLE_SERVER(telnetd)
IU_ENABLE_SERVER(tftpd)
IU_ENABLE_SERVER(uucpd)

IU_ENABLE_CLIENT(ftp)
IU_ENABLE_CLIENT(ping)
IU_ENABLE_CLIENT(rcp)
IU_ENABLE_CLIENT(rlogin)
IU_ENABLE_CLIENT(rsh)
IU_ENABLE_CLIENT(logger)
IU_ENABLE_CLIENT(talk)
IU_ENABLE_CLIENT(telnet)
IU_ENABLE_CLIENT(tftp)
IU_ENABLE_CLIENT(whois)
IU_ENABLE_CLIENT(ifconfig)

AM_INIT_AUTOMAKE

### Checks for programs.
AC_AIX
AC_CHECK_TOOL(AR, ar)
AC_ISC_POSIX
AC_MINIX
AC_PATH_PROG(RM, rm, rm)
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_YACC

dnl __P is the standard name for the ansi-or-not-ansi arg-decl macro.
dnl We define our own version in <config.h> if the system doesn't supply one.
dnl NOTE: This check has to be done pretty early because we use __P in
dnl       <config.h>
IU_CHECK_MACRO(__P, [#include <sys/cdefs.h>])

AH_BOTTOM(
[#ifdef HAVE___P
/* The system defines __P; we tested for it in <sys/cdefs.h>, so include that
   if we can.  */
# ifdef HAVE_SYS_CDEFS_H
#  include <sys/cdefs.h>
# endif
#else /* !HAVE___P */
/* If the system includes don't seem to define __P, do it here instead.  */
# if defined (__GNUC__) || (defined (__STDC__) && __STDC__) || defined (__cplusplus)
#  define	__P(args)	args	/* Use prototypes.  */
#else
#  define	__P(args)	()	/* No prototypes.  */
#endif
#endif /* HAVE___P */])

### Checks for libraries.
AC_CHECK_LIB(bsd, revoke)
AC_CHECK_LIB(nsl, inet_ntoa)
AC_CHECK_LIB(resolv, gethostname)
AC_CHECK_LIB(socket, getpeername)
AC_CHECK_LIB(opie, opiegenerator)
AC_CHECK_LIB(z, gzdopen)

# We want to use libreadline if it is available.  However, it seems that the
# guile hackers have had problems because there is a Solaris libreadline
# that is different from the GNU libreadline; therefore we test for an obscure
# function in the GNU libreadline.
#AC_CHECK_LIB(termcap, tputs)
#AC_CHECK_LIB(readline, rl_bind_key,,, -ltermcap)
AC_CHECK_LIB(readline, rl_bind_key,
             [LIBREADLINE=-lreadline
              AC_DEFINE(HAVE_LIBREADLINE, 1,
	           [Define to one if you have -lreadline])],
             [LIBREADLINE=], "$LIBTERMCAP")
AC_SUBST(LIBREADLINE)
AC_SUBST(LIBTERMCAP)

dnl See if there's a separate libcrypt (many systems put crypt there)
AC_CHECK_LIB(crypt, crypt, LIBCRYPT=-lcrypt)
AC_SUBST(LIBCRYPT)

# See if a termcap library is available (under one of several names)
IU_LIB_TERMCAP
# If not, add a bogus version of tgetent to libinetutils, as that's the only
# function actually used (to check terminal type validity), modulo any
# dependencies from curses.
if test -z "$LIBTERMCAP"; then
  # Some packages include termcap just ;
  # for those cases, we really don't need termcap.
  AC_LIBOBJ(stub_tgetent)
fi

dnl libutil is a 4.4BSD library that defines several functions handy for
dnl inetutil daemons, doing such things as utmp frobbing, and pty setup.
AC_CHECK_LIB(util, logout, LIBUTIL=-lutil)
AC_SUBST(LIBUTIL)

# Check if they want support for PAM.  Certain daemons like
# ftpd have support for it.

# See if we have libpam.a this is for ftpd.
if test "$with_pam" = yes ; then
  AC_CHECK_LIB(dl, dlopen)
  AC_CHECK_LIB(pam, pam_authenticate, LIBPAM=-lpam)
  if test "$ac_cv_lib_pam_pam_authenticate" = yes ; then
     AC_DEFINE(WITH_PAM, 1, [Define to one if you have -lpam.])
  fi
fi
AC_SUBST(LIBPAM)

# Can we use libls? but we must have fchdir()
if test "$enable_libls" = yes  -a "$ac_cv_func_fchdir" = yes ; then
  LIBLS="../libls/libls.a"
  libls_BUILD="libls.a"
  AC_DEFINE(WITH_LIBLS, 1, [Define to one if you have -lls])
else
  LIBLS=''
  libls_BUILD=''
fi
AC_SUBST(LIBLS)
AC_SUBST(libls_BUILD)

# Only talk uses curses, so only check for it if we want that
if test "$enable_talk" != no; then
  IU_LIB_CURSES
fi
if test "$enable_talk" != no -a "$LIBCURSES"; then
  enable_talk=yes
else
  if test "$enable_talk" = yes; then
    AC_MSG_WARN([curses is not available, so not building talk])
  fi
  enable_talk=no
  talk_BUILD=''
fi

# Look for a system `glob' function, and use our own if we can't find one (or
# if the system one is missing features we need).
sys_glob=no
if test "$ac_cv_header_glob_h" = yes; then
  AC_CHECK_LIB(glob, glob, LIBGLOB=-lglob)
  _SAVE_LIBS="$LIBS"
  LIBS="$LIBGLOB $LIBS"
  AC_CHECK_FUNC(glob,
    IU_CHECK_MACRO(ok system glob,
      [#include <glob.h>], GLOB_BRACE GLOB_TILDE,
      sys_glob=yes))
  LIBS="$_SAVE_LIBS"
fi
if test "$sys_glob" != yes; then
  libglob_BUILD=libglob.a
  LINK_SRCS="$LINK_SRCS glob/glob.h"
  LINK_DSTS="$LINK_DSTS include/glob.h"
  LINK_SRCS="$LINK_SRCS glob/fnmatch.h"
  LINK_DSTS="$LINK_DSTS include/fnmatch.h"
  LIBGLOB="-L../glob -lglob"
else
  libglob_BUILD=''
fi
AC_SUBST(LIBGLOB)
AC_SUBST(libglob_BUILD)


dnl FIXME: Make this test case a bit more robust.  Is there a reason why
dnl        KRB4 exists?
LIBAUTH=
INCAUTH=
if test "$enable_encryption" = yes -o "$enable_authentication" = yes; then
  AH_TEMPLATE(KERBEROS_IV, [Define to one if you have Kerberos IV])
  AH_TEMPLATE(KRB4, [Define to one if you have Kerberos IV])
  AH_TEMPLATE(KERBEROS, [Define to one if you have Kerberos])
  AH_TEMPLATE(DES_ENCRYPTION, [FIXME])
  AH_TEMPLATE(KERBEROS_V, [Define to one if you have Kerberos V])
  AH_TEMPLATE(KRB5, [Define to one if you have Kerberos V])
  
  if test "$KERBEROS_VERSION" = 4; then
    AC_CHECK_LIB(krb, krb_mk_req,
                 [LIBAUTH=-lkrb
                  AC_DEFINE(KERBEROS_IV)
                  AC_DEFINE(KRB4)],
                 -L$KERBEROS_DIR)
    if test ".$LIBAUTH" != . ; then
      AC_CHECK_LIB(des, des_key_sched,
                   [LIBAUTH="$LIBAUTH -ldes"],
                   -L$KERBEROS_DIR)
      dnl FIXME: Fix this to one test case.
      test "$enable_authentication" = yes -a "$ac_cv_lib_krb_krb_mk_req" = yes\
  && AC_DEFINE(KRB4)
      test "$enable_authentication" = yes -a "$ac_cv_lib_krb_krb_mk_req" = yes \
  && AC_DEFINE(KERBEROS)
      test "$enable_encryption" = yes -a "$ac_cv_lib_des_des_key_sched" = yes \
        && AC_DEFINE(DES_ENCRYPTION)
    fi
  else
    IU_CHECK_KRB5($KERBEROS_VERSION,$KERBEROS_DIR)
    LIBAUTH=$KRB5_LIBS
    INCAUTH=$KRB_CFLAGS
    if test ".$LIBAUTH" != . ;then
      case $KERBEROS_VERSION in
      4) AC_DEFINE(KERBEROS_IV)
         AC_DEFINE(KRB4)
         ;;
      5) AC_DEFINE(KERBEROS_V)
	 AC_DEFINE(KRB5)
         ;;
      esac
    fi
  fi
fi
AC_SUBST(LIBAUTH)
AC_SUBST(INCAUTH)

dnl Define CPP macros that enable auth/encrypt code
if test ".$LIBAUTH" != .; then
  test "$enable_authentication" = yes && AC_DEFINE(AUTHENTICATION, 1,
                   [Define to one if you want authentication.])
  test "$enable_encryption" = yes     && AC_DEFINE(ENCRYPTION, 1,
                   [Define to one if you want encryption.])
fi

dnl Check if they want support for Wrap.  Certain daemons like
dnl ftpd have support for it.

if test "$with_wrap" = yes; then
dnl See if we have libwrap.a
dnl we can not use AC_CHECK_LIB reliably since for the wrap lib
dnl you have to define some global variables
#AC_CHECK_LIB(wrap, hosts_ctl, LIBWRAP=-lwrap)
  AC_MSG_CHECKING(hosts_ctl in -lwrap);
  save_LIBS=$LIBS
  LIBS="$save_LIBS -lwrap"
  AC_TRY_LINK([int allow_severity = 1; int deny_severity = 1;],
              hosts_ctl(), eval "ac_cv_lib_wrap_hosts_ctl=yes",
              eval "ac_cv_lib_wrap_hosts_ctl=no")
  LIBS=$save_LIBS
  if test "$ac_cv_lib_wrap_hosts_ctl" = yes ; then
    AC_DEFINE(WITH_WRAP, 1, [Define to one if you have -lwrap.])
    LIBWRAP=-lwrap
  fi
  AC_MSG_RESULT($ac_cv_lib_wrap_hosts_ctl);
fi
AC_SUBST(LIBWRAP)

### Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_DIRENT

AC_CHECK_HEADERS(arpa/nameser.h des.h errno.h fcntl.h features.h glob.h \
                 krb.h memory.h malloc.h netinet/in_systm.h netinet/ip.h \
                 netinet/ip_icmp.h netinet/ip_var.h \
                 security/pam_appl.h \
                 shadow.h stdarg.h stdlib.h string.h stropts.h sys/tty.h \
                 sys/utsname.h sys/ptyvar.h sys/msgbuf.h sys/filio.h \
                 sys/ioctl_compat.h sys/cdefs.h sys/stream.h sys/mkdev.h \
		 sys/sockio.h sys/sysmacros.h sys/param.h sys/file.h \
		 sys/proc.h sys/select.h sys/time.h sys/wait.h sys/resource.h \
		 stropts.h tcpd.h termio.h termios.h utmp.h utmpx.h unistd.h \
                 vis.h)

AC_CHECK_HEADER(poll.h, , [INCLUDES="$INCLUDES poll.h"])

### Checks for types.
dnl Checks return type of signal handlers
AC_TYPE_SIGNAL

dnl We may need our own definition for struct osockaddr (equivalent to the
dnl old 4.3BSD struct sockaddr, and used in grotty bsd talk protocol)
AC_CHECK_TYPE(struct osockaddr, ,
              AC_DEFINE(HAVE_OSOCKADDR_H, 1,
                        [Define to one if you have <osockaddr.h>.])
                        INCLUDES="$INCLUDES osockaddr.h",
	      [#include <sys/types.h>
               #include <sys/socket.h> ])

AC_CHECK_TYPES(struct if_nameindex, , ,
  [#include <sys/socket.h>
   #include <net/if.h>])

dnl sig_t is the type of a signal handler (4.4BSD)
AC_CHECK_TYPES(sig_t, , ,
  [#include <sys/types.h>
   #include <signal.h> ])
AH_BOTTOM(
[#ifndef HAVE_SIG_T
typedef RETSIGTYPE (*sig_t) ();
#endif])

dnl sigset_t is a set of signals (4.4BSD)
AC_CHECK_TYPE(sigset_t, , AC_DEFINE(sigset_t, unsigned long, [FIXME]),
  [#include <sys/types.h>
   #include <signal.h> ])

dnl I'm not sure what this is, but netbsd has it; just use int if necessary.
AC_CHECK_TYPE(sig_atomic_t, , AC_DEFINE(sig_atomic_t, int, [FIXME]),
  [#include <sys/types.h>
   #include <signal.h> ])

AC_CHECK_TYPE(sa_family_t, , AC_DEFINE(sa_family_t, unsigned int, [FIXME]),
    [#include <sys/types.h>
     #ifdef HAVE_SOCKET_H
     #include <socket.h>
     #endif
     #include <sys/socket.h> ])

dnl Check for termio-related types and defines
AC_CHECK_TYPES(cc_t, , ,
 [#if defined(HAVE_TERMIOS_H)
  # include <termios.h>
  #elif defined(HAVE_TERMIO_H)
  # include <termio.h>
  #else
  # include <sgtty.h>
  #endif ])

### Checks for structures.
IU_CHECK_MEMBERS([struct sockaddr_in.sin_len], , ,
    [ #include <sys/types.h>
      #include <netinet/in.h> ])

if test "$ac_cv_header_utmp_h" = yes; then
  AC_CHECK_TYPES(struct lastlog, , , [#include <utmp.h>])
  IU_CHECK_MEMBERS([struct utmp.ut_type, struct utmp.ut_pid, 
                    struct utmp.ut_id, struct utmp.ut_user,
		    struct utmp.ut_host, struct utmp.ut_tv, 
		    struct utmp.ut_exit], , ,
		   [#ifdef HAVE_SYS_TYPES_H
                    # include <sys/types.h>
                    #endif
		    #include <utmp.h>])
fi
if test "$ac_cv_header_utmpx_h" = yes; then
  IU_CHECK_MEMBERS([struct utmpx.ut_tv], , , [#include <utmpx.h>])
fi

IU_CHECK_MEMBERS([stuct ifreq.ifr_index,
                  struct ifreq.ifr_netmask,
                  struct ifreq.ifr_broadaddr], , ,
                 [#include <sys/socket.h>
                  #include <net/if.h>])

IU_CHECK_MEMBERS([struct sockaddr.sa_len], , ,
                 [#include <sys/types.h>
                  #include <sys/socket.h>])
IU_CHECK_MEMBERS([struct hostent.h_addr_list], , , [#include <netdb.h>])

IU_CHECK_MEMBERS([struct stat.st_blksize])

AH_BOTTOM(
[#ifdef HAVE_SYS_PARAM_H
#include <sys/types.h>
#include <sys/param.h>
#endif
/* Get or fake the disk device blocksize.
   Usually defined by sys/param.h (if at all).  */
#if !defined(DEV_BSIZE) && defined(BSIZE)
#define DEV_BSIZE BSIZE
#endif
#if !defined(DEV_BSIZE) && defined(BBSIZE) /* SGI */
#define DEV_BSIZE BBSIZE
#endif
#ifndef DEV_BSIZE
#define DEV_BSIZE 4096
#endif

/* Extract or fake data from a `struct stat'.
   ST_BLKSIZE: Optimal I/O blocksize for the file, in bytes. */
#ifndef HAVE_STRUCT_STAT_ST_BLKSIZE
# define ST_BLKSIZE(statbuf) DEV_BSIZE
#else /* HAVE_STRUCT_STAT_ST_BLKSIZE */
/* Some systems, like Sequents, return st_blksize of 0 on pipes. */
# define ST_BLKSIZE(statbuf) ((statbuf).st_blksize > 0 \
                              ? (statbuf).st_blksize : DEV_BSIZE)
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */])

### Checks for compiler characteristics.
AM_C_PROTOTYPES dnl FIXME: Does inetutils even compile on pre-ANSI compilers?
AC_C_CONST

dnl See if `weak refs' are possible; these make it possible (with shared
dnl libraries) to check for the existance of a standard function at run-time
dnl instead of compile time, which is very handy for distributing binary
dnl version programs that automatically adapt -- in inetutils case, to whether
dnl or not crypt is available.
IU_CHECK_WEAK_REFS

### Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ALLOCA
AC_FUNC_SETVBUF_REVERSED
AC_FUNC_FORK
AC_FUNC_STRCOLL
AC_FUNC_MMAP
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS(bcopy bcmp bzero cfsetspeed cgetent dirfd fchdir flock \
               fpathconf ftruncate \
	       getcwd getmsg getspnam initgroups initsetproctitle killpg \
               mkstemp ptsname \
               setegid seteuid setpgid \
               setsid setregid setreuid setresgid setresuid setutent_r \
               sigaction sigvec strchr setproctitle tcgetattr tzset utimes \
               utime uname \
               updwtmp updwtmpx vhangup wait3 wait4)
AH_BOTTOM(
[#ifndef HAVE_BCOPY
#define bcopy(f,t,z) memmove(t,f,z)
#endif])

AH_BOTTOM(
[#ifndef HAVE_BZERO
#define bzero(x,z) memset(x,0,z)
#endif])

dnl Functions that we will define (in libinetutils) if necessary.
AC_REPLACE_FUNCS(getpass getusershell herror memcmp memcpy memmove memset \
	         setenv strdup strcasecmp strsignal waitpid poll)

dnl Look for the functions typically defined by libutil (which of course may
dnl not actually be in libutil), and and use our own versions if necesary.
_SAVE_LIBS="$LIBS"
LIBS="$LIBUTIL $LIBS"
AC_REPLACE_FUNCS(login logout logwtmp openpty forkpty ruserok iruserok login_tty)
LIBS="$_SAVE_LIBS"

dnl Look for the crypt function itself (in libcrypt if possible)
_SAVE_LIBS="$LIBS"
LIBS="$LIBCRYPT $LIBS"
AC_CHECK_FUNCS(crypt)
LIBS="$_SAVE_LIBS"

AH_BOTTOM(
[#ifndef HAVE_MEMCPY
#define memcpy memmove
#endif])
AH_BOTTOM(
[#if !defined(HAVE_MEMMOVE) || !defined(HAVE_MEMSET)
/* Make sure size_t is defined */
#include <sys/types.h>
#endif])
AH_BOTTOM(
[#ifndef HAVE_MEMMOVE
/* Declare our own silly version.  */
extern void *memmove __P ((void *to, const void *from, size_t sz));
#endif])
AH_BOTTOM(
[#ifndef HAVE_MEMSET
/* Declare our own silly version.  */
extern void memset __P ((void *mem, int val, size_t sz));
#endif])

dnl FIXME: I don't understand this.
dnl If revoke hasn't been defined yet, just define a dummy version
AC_REPLACE_FUNCS(revoke)

jm_INCLUDED_REGEX(libinetutils/regex.c)

AC_CHECK_FUNC(_obstack_free, ,
  AC_LIBOBJ(obstack) INCLUDES="$INCLUDES obstack.h")

dnl Use (posix) `setpgid' if it's around, otherwise assume a BSD setpgrp
AC_CHECK_FUNC(setpgid, , AC_DEFINE(setpgid, setpgrp,
                          [Define to `setpgrp' if you don't have `setpgid'.]))

dnl We use our own version of getopt (including our own header file) if the
dnl system one doesn't have getopt_long.
AC_CHECK_FUNC(getopt_long, ,
  AC_LIBOBJ(getopt)
  AC_LIBOBJ(getopt1)
  INCLUDES="$INCLUDES getopt.h")

dnl Supply a version of poll() if the libray is missing.
dnl syslogd uses poll() unconditionnaly.
AC_CHECK_FUNC(poll, ,
  AC_DEFINE(HAVE_POLL_H, 1, [Define to one if you have <poll.h>])
  AC_LIBOBJ(poll)
  INCLUDES="$INCLUDES poll.h")

dnl Supply versions of the BSD error reporting functions if the system doesn't
AC_CHECK_FUNC(verrx, ,
  AC_LIBOBJ(err)
  INCLUDES="$INCLUDES err.h")

dnl See if the __PROGNAME variable is defined, otherwise use our own.
AC_CHECK_FUNC(__progname,
  AC_DEFINE(HAVE___PROGNAME, 1, [Define to one if you have __progname]),
  AC_LIBOBJ(__progname))

dnl See if snprintf exists, otherwise just use a bogus version
AC_CHECK_FUNC(snprintf,
  AC_DEFINE(HAVE_SNPRINTF, 1, [Define to one if you have snprintf]),
  AC_LIBOBJ(snprintf))

dnl See if vsnprintf exists, otherwise use our own.
AC_CHECK_FUNC(vsnprintf,
  AC_DEFINE(HAVE_VSNPRINTF, 1, [FIXME]),
  AC_LIBOBJ(snprintf))
AH_BOTTOM(
[#ifndef HAVE_VSNPRINTF
#include <sys/types.h>
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
extern int vsnprintf __P ((char *, size_t, const char *, va_list));
#endif])

dnl See if the system has strerror, and replace it if not
AC_CHECK_FUNC(strerror, , AC_LIBOBJ(strerror))
if test "$ac_cv_func_strerror" = no; then
  # No strerror, so see if the SYS_ERRLIST variable can be used by ours
  AC_CHECK_FUNC(sys_errlist, AC_DEFINE(HAVE_SYS_ERRLIST, 1,
                              [Define to one if you have sys_errlist.]))
  if test "$ac_cv_func_sys_errlist" = yes; then
    AC_CHECK_DECL(sys_errlist, , ,
     [#include <stdio.h>
      #ifdef HAVE_ERRNO_H
      #include <errno.h>
      #endif])
  fi
fi

dnl See if the system has hstrerror, and replace it if not
AC_CHECK_FUNC(hstrerror, , AC_LIBOBJ(hstrerror))
if test "$ac_cv_func_hstrerror" = yes; then
  AC_CHECK_DECL(hstrerror, , , [#include <netdb.h>])
else
  # No hstrerror, so see if the H_ERRLIST variable can be used by ours
  AC_CHECK_FUNC(h_errlist)
  if test "$ac_cv_func_h_errlist" = yes; then
    AC_CHECK_DECL(h_errlist, , , [#include <netdb.h>])
  fi
fi
if test "$ac_cv_func_hstrerror" = yes -o "$ac_cv_func_h_errlist" = yes; then
  # If there's a system hstrerror, or we can reasonably replace it, say so.
  # We still provide some definition, regardless, but this allows people to use
  # a reasonable alternative if the situation allows, rather than using a
  # degenerate version that only says `Host lookup error N'.
  AC_DEFINE(HAVE_HSTRERROR, 1, [Define to one if you have hstrerror.])
fi

AH_BOTTOM(
[#if !defined(HAVE_DECL_HSTRERROR) || !HAVE_DECL_HSTRERROR
extern const char *hstrerror __P ((int));
#endif])

## Checks for function declarations.

AC_DECL_SYS_SIGLIST

AC_CHECK_DECLS(crypt, , , [#include <unistd.h>])

dnl EWOULDBLOCK is more or less the BSD version of posix EAGAIN.
IU_CHECK_MACRO(EWOULDBLOCK, [#include <errno.h>], , ,
  AC_DEFINE(EWOULDBLOCK, EAGAIN, 1, [FIXME]))
AC_CHECK_DECLS(errno, , , [#include <errno.h>])

dnl See whether <syslog.h> will declare special internal stuff if we define
dnl SYSLOG_NAMES before including it.  We check for various syslog internal
dnl macros, the typedef `CODE', and the variable `prioritynames'.
define([iu_syslog_includes],
  [[#include <stdlib.h>
    #define SYSLOG_NAMES
    #include <syslog.h> ]])
IU_CHECK_MACRO(syslog internal macros,
  iu_syslog_includes,
  [LOG_MAKEPRI LOG_PRI LOG_FAC],
  AC_CHECK_TYPE(CODE,
    AC_CHECK_DECL(prioritynames,
      AC_DEFINE(HAVE_SYSLOG_INTERNAL, 1, [FIXME]),
      INCLUDES="$INCLUDES syslog-int.h",
      iu_syslog_includes),
    INCLUDES="$INCLUDES syslog-int.h", iu_syslog_includes),
  INCLUDES="$INCLUDES syslog-int.h")
undefine([iu_syslog_includes])

dnl Some systems don't declare common functions (especially if they return
dnl int), at least in the expected header file.  Check.
AC_CHECK_DECLS([fclose, pclose], , , [#include <stdio.h>])
AC_CHECK_DECLS([getcwd, getlogin, getpass, getusershell, ttyname], , ,
               [#include <unistd.h>])
AH_BOTTOM(
[#if !HAVE_DECL_GETLOGIN
extern char *getlogin __P((void));
#endif])
AH_BOTTOM(
[#if !HAVE_DECL_GETCWD
extern char *getcwd __P((char *, size_t));
#endif])
AH_BOTTOM(
[#if !HAVE_DECL_GETPASS
extern char *getpass __P((const char *));
#endif])
AH_BOTTOM(
[#if !HAVE_DECL_TTYNAME
extern char *ttyname __P ((int));
#endif])

AC_CHECK_DECLS([strerror, strchr], , , [#include <string.h>])
AH_BOTTOM(
[#if !HAVE_DECL_STRERROR
extern const char *strerror __P ((int));
#endif])
AH_BOTTOM(
[#if !HAVE_DECL_STRCHR
extern char *strchr __P ((char *str, int ch));
extern char *strrchr __P ((char *str, int ch));
#endif
#ifndef HAVE_STRCHR
#define strchr index
#define strrchr rindex
#endif])

AC_CHECK_DECLS([getgrnam, initgroups], , , [#include <grp.h>])
AH_BOTTOM(
[#ifndef HAVE_DECl_GETGRNAM
extern struct group *getgrnam __P ((const char *));
#endif])

AC_CHECK_DECLS(htons, , ,
  [ #ifdef HAVE_SYS_TYPES_H
    # include <sys/types.h>
    #endif
    #ifdef HAVE_SYS_PARAM_H
    # include <sys/param.h>
    #endif
    #include <netinet/in.h> ])


dnl Our home-grown version of setenv needs to use ENVIRON
AC_CHECK_DECLS(environ, , ,
  [ #ifdef HAVE_UNISTD_H
    # include <unistd.h>
    #endif
    #ifdef HAVE_STDLIB_H
    # include <stdlib.h>
    #endif ])

dnl See if we have h_errno (the test is here so we can use -lresolv
dnl if necessary).
AC_CACHE_CHECK([for h_errno], inetutils_cv_var_h_errno,
  AC_TRY_COMPILE([#include <netdb.h>],
    [ extern int h_errno; int iu_x = h_errno; ],
    inetutils_cv_var_h_errno=yes, inetutils_cv_var_h_errno=no))
if test "$inetutils_cv_var_h_errno" = yes; then
  dnl FIXME: Isn't this wrong? Shouldn't the declaration check define
  dnl        this if we find h_errno?
  AC_DEFINE(HAVE_H_ERRNO, 1, [Define to one if you have h_errno.])
  AC_CHECK_DECL(h_errno, , , [#include <netdb.h>])
fi

## Checks for CPP macros.
dnl Look for the posix SEEK_ macros (for lseek), and if not found, try the
dnl similar berkeley L_ macros; if neither can be found, use the classic unix
dnl values.
IU_CHECK_MACRO(SEEK_ macros,
  [#include <unistd.h>], SEEK_SET SEEK_CUR SEEK_END,
  :,
  IU_CHECK_MACRO(L_ seek macros,
    [#include <unistd.h>], L_SET L_INCR L_XTND,
    AC_DEFINE(SEEK_SET, L_SET, [FIXME])
    AC_DEFINE(SEEK_CUR, L_INCR, [FIXME])
    AC_DEFINE(SEEK_END, L_XTND, [FIXME]),
    AC_DEFINE(SEEK_SET, 0, [FIXME])
    AC_DEFINE(SEEK_CUR, 1, [FIXME])
    AC_DEFINE(SEEK_END, 2, [FIXME])))

dnl Look for the posix _FILENO macros; if not found, use the classic unix values.
IU_CHECK_MACRO(_FILENO macros,
  [#include <unistd.h>], STDIN_FILENO STDOUT_FILENO STDERR_FILENO,
  :,
  AC_DEFINE(STDIN_FILENO, 0, [FIXME])
  AC_DEFINE(STDOUT_FILENO, 1, [FIXME])
  AC_DEFINE(STDERR_FILENO, 2, [FIXME]))

dnl See where to find fd_set (bit-vectors for select) manipulation macros.
IU_CHECK_MACRO(fd_set macros, [#include <sys/types.h>],
  FD_ZERO FD_CLR FD_SET FD_ISSET)
if test "$inetutils_cv_macro_fd_set_macros" = no; then
  IU_CHECK_MACRO(fd_set macros in <sys/time.h>, [#include <sys/time.h>],
    FD_ZERO FD_CLR FD_SET FD_ISSET)
fi

dnl Configure paths used by inetutils programs.  See the file `paths' for
dnl details.
PATHDEFS_MAKE=pathdefs.make
PATHS_DEFS=paths.defs
IU_CONFIG_PATHS($srcdir/paths, PATHDEFS_MAKE, PATHS_DEFS)
AH_BOTTOM(
[/* Defaults for PATH_ variables.  */
#include <include/confpaths.h>])

dnl Supply optional header files by linking a copy into the object include dir
LINK_SRCS="$LINK_SRCS `for I in $INCLUDES; do echo $ac_n ' 'headers/$I$ac_c; done`"
LINK_DSTS="$LINK_DSTS `for I in $INCLUDES; do echo $ac_n ' 'include/$I$ac_c; done`"
ac_sources="$LINK_SRCS"
ac_dests="$LINK_DSTS"
while test -n "$ac_sources"; do
  set $ac_dests
  ac_dest=$1
  shift
  ac_dests=$*
  set $ac_sources
  ac_source=$1
  shift
  ac_sources=$*
  ac_config_links_1="$ac_config_links_1 $ac_dest:$ac_source"
done
AC_CONFIG_LINKS([$ac_config_links_1])

dnl Ok this is the end of the rope, even autoconf can't help.
dnl For example on certain system login(1) will not work if we
dnl don't have an entry in utmpx.
dnl Also for some OS they are better handle with STREAMS
case "$host" in
*olaris*)
  AC_DEFINE(SOLARIS, 1, [FIXME])
  AC_DEFINE(UTMPX, 1, [FIXME])
  AC_DEFINE(HAVE_STREAMSPTY, 1, [FIXME])
  ;;
*irix* | *hpux*)
  AC_DEFINE(UTMPX, 1, [FIXME])
  AC_DEFINE(UTMPX, 1, [FIXME])
  ;;
esac

AC_CONFIG_FILES([Makefile libinetutils/Makefile libtelnet/Makefile glob/Makefile
libicmp/Makefile ping/Makefile ftp/Makefile ftpd/Makefile inetd/Makefile
rcp/Makefile
rexecd/Makefile rlogin/Makefile rlogind/Makefile rsh/Makefile
rshd/Makefile logger/Makefile syslogd/Makefile talk/Makefile
talkd/Makefile telnet/Makefile telnetd/Makefile tftp/Makefile
tftpd/Makefile uucpd/Makefile gwhois/Makefile libls/Makefile
include/confpaths.h:headers/confpaths.h.in
headers/Makefile
doc/Makefile doc/rfc/Makefile])
AC_OUTPUT
