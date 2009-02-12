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
 * Author(s): chris
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvmutils_stringplusplus_h
#define _mvmutils_stringplusplus_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <malloc.h>
#include "vmutils/list++.h"

enum MatchFlags {
    MatchAny =0,
    MatchPathname =1,
    MatchNoPeriod =2,
    MatchNoEscape =4
};

class CString : public Link {

private:

    struct stringSize {

	unsigned ubytes : 24,	// used bytes
	    xbytes : 8;		// spare bytes (until realloc)

	stringSize() {
	    ubytes = 0;
	    xbytes = 0;
	}

    } theSize;

protected:

    char *theString;
	
    void allocate(const char *s,
		  int n =-1);

    int setMatchRegister(const char *p,
			 const char *s) const;
public:

    CString() : theString(0) {
    }

    CString(const char *s) :
	theString(0) {
	allocate(s);
    }

    CString(const char *s, int n) :
	theString(0) {
	allocate(s,n);
    }

    CString(const CString& cs) :
	theString(0) {
	allocate(cs.theString);
    }

    CString(int n);

    CString(unsigned n);

    CString(long l);

    CString(unsigned long ul);

#if __WORDSIZE < 64
    CString(gnuquad_t ll);

    CString(u_gnuquad_t ull);
#endif

    CString(void *ptr);

    CString(double v, const char *format =0);

    virtual ~CString();

    operator const char *() const {
	return theString;
    }

    CString& operator=(const CString& cs);

    CString& operator=(const char *s) {
	allocate(s);
	return *this;
    }

    char& operator[](int n) {
	return theString[n];
    }

    void catenate(const char *s,
		  int n =-1);

    void operator +=(const CString& cs) {
	catenate(cs.theString);
    }

    void operator +=(const char *s) {
	catenate(s);
    }

    friend CString operator+(const CString& s1,
			     const char *s2) {
	CString tmp(s1);
	tmp += s2;
	return tmp;
    }

    int operator==(const CString& cs) const {
	return theString == cs.theString
	    || (theString && cs.theString && !strcmp(theString,cs.theString));
    }

    int operator==(const char *s) const {
	return theString == s || (theString && s && !strcmp(theString,s));
    }

    int operator!=(const CString& cs) const {
	return !operator ==(cs);
    }

    int operator!=(const char *s) const {
	return !operator ==(s);
    }

    CString& overwrite(const char *s,
		       int len =-1);

    int	isVoid() const {
	return !theString;
    }

    int isEmpty() const {
	return !theString || !*theString;
    }

    unsigned len() const {
	return theSize.ubytes;
    }

    char *gets() const {
	return theString;
    }

    CString gets(int n) const {
	return CString(theString,n);
    }

    void clear(int from=0,
	       int to=-1);

    void repeat(char c,
		int n);

    void blanks(int n) {
	repeat(' ',n);
    }

    int	replaceSpaces(char);

    CString& trunc(unsigned nchars);

    CString& justLeft(int);
    CString& justRight(int);
    CString& justCenter(int);

    CString& upCase();

    CString& downCase();

    CString& reverse();

    CString upTo(char c,
		 int n = 1) const;

    CString downTo(char c,
		   int n = 1) const;

    int searchBegChar(char c) const;

    int searchEndChar(char c) const;

    void removeLeading(char c);

    void removeTrailing(char c);

    void removeSurroundingSpaces();

    void removeAllSpaces();

    void trimExtraZeroes();

    CString& pack(const char *set,
		  char rpl);

    int	readInt(int& n,
		int base =10);

    int readDouble(double&);

    int getInt();

    double getDouble();

    unsigned long getHex();

    CString& format(const char *, ...);

    CString& vformat(const char *, va_list);

    CString& cformat(const char *, ...);

    CString& cvformat(const char *, va_list);

    void appendChar(char c) {
	if (c)
	    catenate(&c,1);
    }

    int	compareUpTo(const CString& s,
		    char = '\0') const;

    char *expand();

    char *metaExpandC();

    CString dirname();

    CString basename();

    CString absPath();

    int fnmatch(const char *pattern,
		MatchFlags mode =MatchAny,
		int off =0) const;

    static const char *getMatchRegister(int nth);

    int subst(int leftpos,
	      int rightpos,
	      const char *s =0);

    int subst(const char *olds,
	      const char *news =0);

    int rsubst(const char *olds, const char *news =0);

    int strip(int leftpos,
	      int rightpos =-1) {
	return subst(leftpos,rightpos);
    }

    int strip(const char *s) {
	return subst(s);
    }

    int rstrip(const char *s) {
	return rsubst(s);
    }

    int insert(int point,
	       const char *s);

    int match(const char *s,
	      int leftpos =0);

    int rmatch(const char *s,
	       int rigthpos =-1);

    CString getSmartPath(int nkept =3);

    CString getAbbrevPath(int okAbsNames =0);

    const char *canonicalize();

    const char *posixize();
};

class LString : public CString {

private:

    List *ll;

public:

    LString(List *l,
	    const char *s) :
	CString(s) {
	ll = l;
	l->append(this);
    }

    LString(List *l,
	    const char *s,
	    int len) :
	CString(s,len) {
	ll = l;
	l->append(this);
    }

    LString(List *l,
	    LString *e,
	    const char *s) :
	CString(s) {
	ll = l;
	l->insert(e,this);
    }

    LString(List *l,
	    LString *e,
	    const char *s,
	    int len) :
	CString(s,len) {
	ll = l;
	l->insert(e,this);
    }

    LString(const char *s,
	    int len) :
	CString(s,len) {
	ll = 0;
    }

    LString(const char *s) :
	CString(s) {
	ll = 0;
    }

    virtual ~LString();

    virtual int compare(Link *buddy);
};

MakeList(LString);

typedef LStringList CStringList;

class CStringTok : public CString {

    char *mark;

public:

    CStringTok(const char *s) :
	CString(s) {
	mark = (char *)-1;
    }

    CStringTok(const char *s,
	       int l) :
	CString(s,l) {
	mark = (char *)-1;
    }

    CStringTok(const CStringTok& s) :
	CString(s) {
	mark = (char *)-1;
    }

    virtual ~CStringTok() {
    }

    CStringTok& overwrite(const char *s,
			  int len =-1);

    char *getNextTok(char sep);

    char *getNextTok(char *seplist);
};

static inline char *stringDup(const char *s) {
    return s ? strcpy(new char[strlen(s) + 1],s) : 0;
}

static inline void stringFree(char *s) {
    if (s) delete[] s;
}

extern const CString nilString;

extern const CString emptyString;

extern CStringList matchStrings;

#endif // !_mvmutils_stringplusplus_h
