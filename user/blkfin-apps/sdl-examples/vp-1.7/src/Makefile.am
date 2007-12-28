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

# $Id: Makefile.am,v 1.10 2007/01/10 15:55:27 erik Exp $

bin_PROGRAMS = vp

vp_SOURCES = ftp.c http.c image.c input.c vp.c net.c timer.c
noinst_HEADERS = ftp.h http.h image.h input.h vp.h net.h timer.h

lint:
	for a in *.[ch] ; do echo $$a ; splint $$a @CFLAGS@ @SDL_CFLAGS@  > $$a.lint ; done
indent:
	indent *.[ch]
gindent:
	gindent *.[ch]
