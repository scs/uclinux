/* -*- C++ -*-
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvmutils_tclistplusplus_h
#define _mvmutils_tclistplusplus_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <sys/types.h>
#include <stdint.h>

class TclListParser;

/*
 * The structure defined below is used to hold dynamic strings.  The only
 * field that clients should use is the string field, and they should
 * never modify it.
 */

#define MVM_TCL_DSTRING_STATIC_SIZE 200
typedef struct MvmTcl_DString {
    char *string;		/* Points to beginning of string:  either
				 * staticSpace below or a malloced array. */
    int length;			/* Number of non-NULL characters in the
				 * string. */
    int spaceAvl;		/* Total number of bytes available for the
				 * string and its terminating NULL char. */
    char staticSpace[MVM_TCL_DSTRING_STATIC_SIZE];
				/* Space to use in common case where string
				 * is small. */
} MvmTcl_DString;

class TclList {

protected:

    MvmTcl_DString tclString;

public:

    TclList(const char *s =0);

    TclList(const char *s, int n);

    TclList(const TclList& src);

    virtual ~TclList();

    const char *append(const char *s);

    const char *append(const char *s, int n);

    const char *append(u_long n);

    const char *appendx(u_long n);

    const char *append(long n);

    const char *appendx(long n);

#if __WORDSIZE < 64
    const char *append(u_gnuquad_t n);

    const char *appendx(u_gnuquad_t n);

    const char *append(gnuquad_t n);

    const char *appendx(gnuquad_t n);
#endif

    const char *append(void *);

    const char *append(int n);

    const char *append(short n);

    const char *append(unsigned n);

    const char *append(unsigned short n);

    const char *append(double g);

    const char *append(const TclList& tclist);

    TclList& operator +=(const TclList& tclist);

    TclList& operator +=(const char *s);

    TclList& operator =(const TclList& tclist);

    int length() const;

    const char *set(const char *s);

    const char *get() const;

    void clear();

    operator const char *() const {
	return get();
    }
};

class TclListParser {

public:

    int argc,
	cursor;

    char **argv;

public:

    TclListParser(const TclList& tclist);

    TclListParser(const TclListParser& src);

    TclListParser(const char *s);

    ~TclListParser();

    const char *next();

    const char *prev();

    int getArgCount() const {
	return argc;
    }

    void reset(int reverse =0);
};

#endif // !_mvmutils_tclistplusplus_h
