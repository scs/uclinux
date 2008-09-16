## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006 Simon Josefsson.
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

AM_CPPFLAGS = -I$(srcdir)/../src -I../src \
	-I$(srcdir)/../gl -I../gl

EXTRA_DIST = README

noinst_LTLIBRARIES = libgsasl-digest_md5.la
libgsasl_digest_md5_la_SOURCES = digest-md5.h mechinfo.c \
	session.h session.c \
	getsubopt.c \
	tokens.h \
	digesthmac.h digesthmac.c \
	validate.h validate.c \
	parser.h parser.c \
	printer.h printer.c \
	free.h free.c

if CLIENT
libgsasl_digest_md5_la_SOURCES += client.c
endif

if SERVER
libgsasl_digest_md5_la_SOURCES += server.c
endif

LDADD = libgsasl-digest_md5.la ../gl/libgl.la

ctests = test-parser$(EXEEXT)
TESTS = $(ctests)	
check_PROGRAMS = $(ctests)
