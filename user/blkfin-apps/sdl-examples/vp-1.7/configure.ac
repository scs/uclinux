#############################################################################
# vp    -    SDL based image viewer for linux and fbsd. (X and console)	    #
# Copyright (C) 2001-2007 Erik Greenwald <erik@smluc.org>		    #
# 									    #
# This program is free software; you can redistribute it and/or modify      #
# it under the terms of the GNU General Public License as published by	    #
# the Free Software Foundation; either version 2 of the License, or         #
# (at your option) any later version.                                       #
#                                                                           #
# This program is distributed in the hope that it will be useful,           #
# but WITHOUT ANY WARRANTY; without even the implied warranty of            #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                              #
#                                                                           #
# You should have received a copy of the GNU General Public License         #
# along with this program; if not, write to the Free Software               #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA #
#############################################################################

# $Id: configure.ac,v 1.10 2007/01/19 15:04:32 erik Exp $

AC_INIT
AC_CONFIG_SRCDIR([src/vp.c])
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(vp, 1.7)
AM_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_INSTALL

AC_CHECK_HEADERS(unistd.h stdio.h stdlib.h string.h time.h)
AC_CHECK_FUNCS(mkstemps)

AC_PATH_XTRA
AM_PATH_SDL(1.2.0,,AC_MSG_ERROR(["SDL 1.2.0 or better is required. Get it at http://libsdl.org."]))

CFLAGS="$CFLAGS $SDL_CFLAGS $X_CFLAGS"
LIBS="$LIBS $SDL_LIBS -lSDL_image $X_LIBS"

AC_CHECK_LIB(SDL_image,IMG_Load,,AC_MSG_ERROR([SDL_image is required http://www.libsdl.org/projects/SDL_image/index.html]))

AC_SEARCH_LIBS(socket,socket wsock32)

GETOPT_LONG_DIR=
AC_CHECK_FUNCS(getopt_long , [GETOPT_LONG_DIR=""], [
    AC_CHECK_LIB(gnugetopt, getopt_long, LIBS="$LIBS -lgnugetopt", [
        GETOPT_LONG_DIR="getopt_long"
        CFLAGS="$CFLAGS -I../getopt_long"
        LIBS="$LIBS ../getopt_long/libgetopt_long.a"
        AC_DEFINE(NO_GETOPT_LONG,,[Missing getopt_long])])])
AC_SUBST(GETOPT_LONG_DIR)

AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile vp.spec])
AC_OUTPUT
