/*
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

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <sys/param.h>
#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "vmutils/toolshop.h"
#include "vmutils/string++.h"

const CString nilString;

const CString emptyString("");

// These are *not* MT-safe.

CStringList matchStrings;

static char formatBuf[2048];

static inline int fstrlen(const char *s) {
    int l = 0; while (*s++) l++; return l;
}

void CString::catenate (const char *s, int n)

{
    if (s && n)
	{
	unsigned l = n > 0 ? n : fstrlen(s);
	unsigned ubytes = theSize.ubytes, xbytes = theSize.xbytes;

	if (xbytes < l + 1) // we need space for the string plus the null char
	    {
	    unsigned xmore = l + 16;

	    if (theString)
		theString = (char *)realloc(theString,ubytes + xbytes + xmore);
	    else
		theString = (char *)malloc(xmore);

	    xbytes += xmore;
	    }

	char *wp = theString + ubytes;
	ubytes += l;
	theSize.ubytes = ubytes;
	xbytes -= l;
	theSize.xbytes = xbytes;
	while (l-- > 0) { *wp++ = *s++; }
	*wp = '\0';
	}
}

void CString::allocate (const char *s, int n)

{
    char *oldString = theString;

    theString = NULL;
    theSize.ubytes = 0;
    theSize.xbytes = 0;

    if (s && n)
	catenate(s,n);

    if (oldString)
	free(oldString);
}

CString& CString::operator= (const CString& cs)

{
    if (!cs.theString || *cs.theString || !theString)
	allocate(cs.theString);
    else
	{
	// A special case where the allocated memory is
	// kept, whilst the string is emptied. This is
	// provided for efficiency purpose when a CString
	// is used to hold an iteratively formatted string.
	// Candidate source string is `emptyString'.
	theSize.xbytes += theSize.ubytes;
	theSize.ubytes = 0;
	*theString = '\0';
	}

    return *this;
}

CString& CString::overwrite (const char *s, int len)

{
    if (theString)
	{
	theSize.xbytes += theSize.ubytes;
	theSize.ubytes = 0;
	*theString = '\0';
	}

    catenate(s,len);

    return *this;
}

CString::CString(int n) : theString(0)
{
    sprintf(formatBuf,"%d",n);
    allocate(formatBuf);
}

CString::CString(unsigned n) : theString(0)
{
    sprintf(formatBuf,"%u",n);
    allocate(formatBuf);
}

CString::CString(long n) : theString(0)
{
    sprintf(formatBuf,"%ld",n);
    allocate(formatBuf);
}

CString::CString(unsigned long n) : theString(0)
{
    sprintf(formatBuf,"%lu",n);
    allocate(formatBuf);
}

#if __WORDSIZE < 64
CString::CString(gnuquad_t n) : theString(0)
{
    sprintf(formatBuf,"%lld",n);
    allocate(formatBuf);
}

CString::CString(u_gnuquad_t n) : theString(0)
{
    sprintf(formatBuf,"%llu",n);
    allocate(formatBuf);
}
#endif

CString::CString(void *ptr) : theString(0)

{
    if (ptr)
	{
	// Some implementations do not prefix
	// the result with "0x" -- take care of this.

	sprintf(formatBuf + 2,"%p",ptr);

	if (formatBuf[2] == '0' && formatBuf[3] == 'x')
	    allocate(formatBuf + 2);
	else
	    {
	    formatBuf[0] = '0';
	    formatBuf[1] = 'x';
	    allocate(formatBuf);
	    }
	}
    else
	// Some implementations give "nil", "null" or whatever
	// for a null pointer - we just want "0x0" so we can
	// parse it as an hex value.
	allocate("0x0");
}

CString::CString(double d, const char *format) : theString(0)
{
    if (fabs(d) == infinity())
	{
	allocate("");
	return;
	}

    if (format)
	{
	if (d == 0.0) // avoid printing -0
	    sprintf(formatBuf,format,0.0);
	else
	    sprintf(formatBuf,format,d);
	}
    else
	{
	if (d == 0.0) // avoid printing -0
	    sprintf(formatBuf,"%g",0.0);
	else
	    sprintf(formatBuf,"%g",d);
	}
    allocate(formatBuf);
}

CString::~CString ()

{ if (theString) free(theString); }

CString& CString::trunc(unsigned n)
{
    if (len() == 0 || len() <= n)
	return *this;

    *this = this->gets(n);

    return *this;
}

void CString::clear(int from, int to)

{
    if (isVoid() || isEmpty())
	return;

    if (!from && to < 0)
	{
	*this = emptyString;
	return;
	}

    if (from<0)
	from = len()-1;

    if (to<0)
	to = len()-1;

    if ((unsigned)from >= len()
	|| (unsigned)to >= len()
	|| from > to)
	return;

    CString cs(theString);
    allocate(cs,from);
    catenate(&cs[to + 1]);
}

void CString::repeat(char c, int n)

{
    char *pattern = n > 0 ? (char *)malloc(n + 1) : 0;

    if (pattern)
	{
	memset(pattern,c,n);
	pattern[n] = '\0';
	}

    allocate(pattern);

    if (pattern)
	free(pattern);
}

int CString::replaceSpaces(char c)
{
    int changed = 0;
    char *rp = theString;

    if (!rp || !*rp) return 0;
    do {
    if (isspace(*rp))
	{
	*rp = c;
	changed = 1;
	}
    rp++;
    } while (*rp);

    return changed;
}

void CString::removeAllSpaces ()

{
    if (isVoid())
	return;

    char *wp = theString;
    
    for (char *rp = theString; *rp; rp++)
	{
	if (!isspace(*rp))
	    *wp++ = *rp;
	}

    *wp = '\0';

    *this = CString(theString);
}

CString& CString::pack (const char *set, char rpl)

{
    if (theString && *theString)
	{
	char *src = theString, *dst = theString;
	unsigned oldlen = theSize.ubytes;

	while (*src && strchr(set,*src))
	    src++;

	while (*src)
	    {
	    char *mark = src;

	    while (*src && strchr(set,*src))
		src++;

	    if (src - mark > 0)
		*dst++ = rpl;
	    else
		*dst++ = *src++;
	    }

	while (--dst >= theString && strchr(set,*dst))
	    ;

	*++dst = '\0';
	theSize.ubytes = dst - theString - 1;
	theSize.xbytes += (oldlen - theSize.ubytes);
	}

    return *this;
}

CString& CString::justLeft(int size)
{
    if (size < 0) return *this;
    if (!theString) { blanks(size); return *this; }
    char *buf = (char *)malloc(size + 1);
    sprintf(buf,"%-*.*s",size,size,theString);
    buf[size] = '\0';
    allocate(buf);
    free(buf);
    return *this;
}


CString& CString::justRight(int size)
{
    if (size < 0) return *this;
    if (!theString) { blanks(size); return *this; }
    char *buf = (char *)malloc(size + 1);
    sprintf(buf,"%*.*s",size,size,theString);
    buf[size] = '\0';
    allocate(buf);
    free(buf);
    return *this;
}


CString& CString::justCenter(int size)
{
    if (size < 0) return *this;
    if (!theString) { blanks(size); return *this; }
    if (len() >= (unsigned)size) { justLeft(size); return *this; }
    int l = size - len();
    CString pre;
    pre.blanks(l/2);
    CString post;
    post.blanks(l/2+l%2);
    *this = pre + *this + post;
    return *this;
}


CString& CString::upCase()
{
    if (isVoid()) return *this;
    char *s = theString;
    while (*s != '\0')
	{
	*s = toupper(*s);
	s++;
	}
    return *this;
}


CString& CString::downCase()
{
    if (isVoid()) return *this;
    char *s = theString;
    while (*s != '\0')
	{
	*s = tolower(*s);
	s++;
	}
    return *this;
}


CString& CString::reverse()
{
    if (len() < 2) return *this;

    CString tmp(theString);
    char *s = theString;
    int count = len();
    char *t = tmp.theString+count;
    while(count-- > 0)
	{
	*(s++) = *(--t);
	}
    return *this;
}


CString CString::upTo(char c, int n) const
{
    if (c == '\0' || n == 0 || isVoid()) return nilString;

    CString result(theString);

    char *s = result.theString;
    while (s && n > 0)
	{
	s = strchr(s,c);
	if (s) ++s;
	--n;
	}
    if (s)
	{
	--s;
	*s = '\0';
	return result;
	}

    return nilString;
}


CString CString::downTo(char c, int n) const
{
    if (c == '\0' || n == 0 || isVoid()) return nilString;

    CString result(theString);
    char *end = strchr(result.theString,'\0');

    char *s;

    do {
    s = result.theString;
    s = strrchr(s,c);
    if (s) *s = '\0';
    --n;
    } while (s && n > 0);

    if (s)
	{
	char *p = s;
	while (p != end)
	    {
	    if (*p == '\0') *p = c;
	    p++;
	    }
	s++;
	return s;
	}

    return nilString;
}


int CString::searchBegChar(char c) const
{
    if (!theString || c == '\0') return -1;

    int i = 0;
    char *s = theString;
    while (*s)
	{
	if (*s++ == c) return i;
	++i;
	}

    return -1;
}

int CString::searchEndChar(char c) const
{
    if (!theString || c == '\0') return -1;

    int i = len()-1;
    char *s = theString+len();
    while (--s != theString-1)
	{
	if (*s == c) return i;
	--i;
	}

    return -1;
}

void CString::removeLeading(char c)
{
    if (!theString || c == '\0') return;
    char *r = theString;
    while (*r == c) r++;
    if (r == theString) return;
    allocate(r);
}

void CString::removeTrailing(char c)
{
    if (!theString || *theString == '\0' || c == '\0') return;
    char *r = theString+len()-1;
    while (*r == c) if (r-- == theString) break;
    r++;
    if (*r == '\0') return;
    *r = '\0';
    allocate(theString);
}

void CString::removeSurroundingSpaces()
{
    if (!theString || *theString == '\0') return;

    char *b = theString;
    while (*b != '\0' && isspace(*b)) b++;
    if (*b == '\0')
	{
	*this = "";
	return;
	}

    char *e = theString+len()-1;
    while (isspace(*e)) e--;
    e++;
    *e = '\0';

    allocate(b);
}

int CString::compareUpTo(const CString& s2, char end) const
{
    if ( isVoid() && s2.isVoid() ) return 1;
    if ( isVoid() || s2.isVoid() ) return 0;

    if ('\0' == end) return ( strcmp(theString,s2.theString) == 0);
    CString tmp = s2;
    char *t = strchr(tmp.theString,end);
    if (t) *t = '\0';
    int res = strcmp(theString,tmp.theString);
    if (t) *t = end;
    return (res == 0);
}

char *CString::expand()
    
{
    if (isVoid() || isEmpty())
	return theString;

    CStringTok tok(theString);
    char *seg = tok.getNextTok('/');
    CString cp;

    if (seg)
	{
	do
	    {
	    if (*seg == '~')
		{
		if (!*++seg)
		    seg = getenv("LOGNAME");

		if (!seg || !*seg)
		    cp += getenv("HOME");
		else
		    {
		    struct passwd *pw = getpwnam(seg);
		    cp += pw && pw->pw_dir ? pw->pw_dir : "~";
		    }
		}
	    else if (strchr(seg,'$'))
		{
		do
		    {
		    for (char lastc = '\0'; *seg &&
			     (*seg != '$' || lastc == '\\'); seg++)
			{
			lastc = *seg;
			cp.appendChar(*seg);
			}

		    if (*seg == '$')
			{
			CString vname;

			if (*++seg && strchr("({",*seg))
			    seg++;

			for (vname = ""; isalnum(*seg) || *seg == '_'; seg++)
			    vname.appendChar(*seg);
			 
			if (vname.len() > 0)
			    {
			    cp += getenv(vname);

			    if (*seg && strchr(")}",*seg))
				seg++;
			    }
			}
		    }
		while (*seg);
		}
	    else
		cp += seg;

	    seg = tok.getNextTok('/');

	    if (seg)
		cp.appendChar('/');
	    }
	while (seg);
	}

    *this = cp;

    return theString;
}

char *CString::metaExpandC()

{
    char *p = theString, *s = theString;
    unsigned oldlen = theSize.ubytes;

    if (!s || !*s) return theString;

    do
	{
	if (*s == '\\')
	    {
	    switch (*(s + 1))
		{
		case '\\':
		    *p = '\\';
		    break;
		case 'n':
		    *p = '\n';
		    break;
		case 'r':
		    *p = '\r';
		    break;
		case 'v':
		    *p = '\v';
		    break;
		case 'b':
		    *p = '\b';
		    break;
		case 't':
		    *p = '\t';
		    break;
		case 'e':
		    *p = '\033';
		    break;
		default:
		    if (*(s+1) >= '0' && *(s+1) <= '7' &&
			*(s+2) >= '0' && *(s+2) <= '7' &&
			*(s+3) >= '0' && *(s+3) <= '7')
			{
			*p = (*(s+1) - '0')*64 + (*(s+2) - '0')*8 + (*(s+3) - '0');
			s += 2;
			}
		    else
			{
			*p++ = *++s;
			continue;
			}
		}
	    
	    s++; p++;
	    continue;
	    }
	*p = *s;
	p++;

	} while (*s != '\0' && s++);

    theSize.ubytes = p - theString - 1;
    theSize.xbytes += (oldlen - theSize.ubytes);

    return theString;
}

CString& CString::format (const char *f, ...)

{
    va_list ap;

    va_start(ap,f);
    vsprintf(formatBuf,f,ap);
    va_end(ap);

    return overwrite(formatBuf,-1);
}

CString& CString::vformat (const char *f, va_list ap)

{
    vsprintf(formatBuf,f,ap);
    return overwrite(formatBuf,-1);
}

CString& CString::cformat (const char *f, ...)

{
    va_list ap;

    va_start(ap,f);
    vsprintf(formatBuf,f,ap);
    va_end(ap);

    catenate(formatBuf,-1);

    return *this;
}

CString& CString::cvformat (const char *f, va_list ap)

{
    vsprintf(formatBuf,f,ap);
    catenate(formatBuf,-1);

    return *this;
}

int CString::getInt()

{
    if (isVoid()) return 0;
    return atoi(theString);
}

double CString::getDouble()
{
    if (isVoid()) return 0.0;
    return atof(theString);
}

unsigned long CString::getHex()

{
    if (isVoid()) return 0;

    const char *p = theString;

    if (*p == '0' && tolower(p[1]) == 'x')
	p += 2;
    
    unsigned long n = 0;
    sscanf(p,"%lx",&n);
    
    return n;
}

int CString::readInt(int& val, int base)
{
    char *endp = 0;
    val = 0;
    if (isVoid()) return 0;
    val = (int)strtol(theString,&endp,base);
    return (endp - theString);
}

int CString::readDouble(double& val)
{
    char *endp = 0;
    val = 0.0;
    if (isVoid()) return 0;
    val = strtod(theString,&endp);
    return (endp - theString);
}

CStringTok& CStringTok::overwrite (const char *s, int len)

{
    CString::overwrite(s,len);
    mark = (char *)-1;
    return *this;
}

char *CStringTok::getNextTok(char sep)
{
    if (mark == (char *)-1)
	mark = theString;

    char *beg = mark;
    if (!beg) return (char *)0;

    mark = strchr(beg,sep);
    if (mark) *mark++ = '\0';

    return beg;
}

char *CStringTok::getNextTok(char *seplist)
{
    if (mark == (char *)-1)
	mark = theString;

    char *beg = mark;
    if (!beg) return (char *)0;

    mark = strpbrk(beg,seplist);
    if (mark)
	*mark++ = '\0';

    return beg;
}

CString CString::dirname ()

{
    if (isVoid())
	return CString(*this);

    CString posixp(*this);
    char *p = strrchr(posixp.posixize(),'/');

    if (p)
	return CString(posixp.theString,p - posixp.theString);
    
    return CString(".");
}

CString CString::basename ()

{
    if (isVoid())
	return CString(*this);

    CString posixp(*this);
    char *p = strrchr(posixp.posixize(),'/');

    if (p)
	return CString(p + 1);

    return CString(*this);
}

CString CString::absPath ()

{
    if (isVoid())
	return CString(*this);
    
    char cwd[MAXPATHLEN],
	wd[MAXPATHLEN];

    getcwd(cwd,sizeof(cwd));
    chdir(dirname());
    getcwd(wd,sizeof(wd));
    chdir(cwd);
    CString slash;
    slash.appendChar('/');
    strcat(wd,slash);
    strcat(wd,basename());

    return CString(wd);
}

int CString::match (const char *pattern, int leftpos)

{
    if (isVoid()
	|| leftpos < 0
	|| (unsigned)leftpos >= len())
	return -1;

    char *s = theString + leftpos;
    int sl = fstrlen(s), pl = fstrlen(pattern);
    
    while (sl - pl >= 0 && strncmp(s,pattern,pl) != 0)
	sl--, s++;

    return sl - pl >= 0 ? s - theString : -1;
}

int CString::rmatch (const char *pattern, int rightpos)

{
    if (isVoid())
	return -1;

    if (rightpos < 0)
	rightpos = (int)len();
    else if ((unsigned)rightpos >= len())
	return -1;

    int pl = fstrlen(pattern);

    char *s = theString + (rightpos - pl);
    
    while (s >= theString && strncmp(s,pattern,pl) != 0)
	s--;

    return s >= theString ? s - theString : -1;
}

int CString::fnmatch (const char *pattern,
		      MatchFlags flags,
		      int sindex) const
{
    if (!theString)
	return -1;

    if (sindex == 0)
	matchStrings.destroy();

    const char *p = pattern, *n = theString + sindex;
    char c;

    while ((c = *p++) != '\0')
	{
	if (!(flags & MatchNoEscape) && c == '\\' && setMatchRegister(p,n))
	    {
	    c = *++p;
	    p++;
	    }
	
	switch (c)
	    {
	    case '?' :

		if (*n == '\0')
		    return -1;
		else if ((flags & MatchPathname) && *n == '/')
		    return -1;
		else if ((flags & MatchNoPeriod) && *n == '.' &&
			 (n == theString || ((flags & MatchPathname) && *(n - 1) == '/')))
		    return -1;
		break;

	    case '\\':

		if (!(flags & MatchNoEscape))
		    c = *p++;

		if (*n != c)
		    return -1;

		break;

	    case '*':

		if ((flags & MatchNoPeriod) && *n == '.' &&
		    (n == theString || ((flags & MatchPathname) && *(n - 1) == '/')))
		    return -1;

		for (c = *p++; c == '?' || c == '*'; c = *p++, ++n)
		    {
		    if (((flags & MatchPathname) && *n == '/') || (c == '?' && *n == '\0'))
			return -1;
		    }

		if (c == '\0')
		    return 0;

		{
		const char *p1 = NULL;
		int okSetReg = 0;
		char c1;

		if (!(flags & MatchNoEscape))
		    {
		    if (c == '\\')
			{
			if (*p == '(' || *p == ')')
			    {
			    p1 = p;
			    okSetReg = 1; // postpone register update until
			    c1 = *++p;       // the wildcard has been fully matched
			    p++;
			    }
			else
			    c1 = *p;
			}
		    else
			c1 = c;
		    }
		else
		    c1 = c;

		for (--p; *n != '\0'; ++n)
		    {
		    if ((c == '[' || *n == c1) &&
			(!okSetReg || setMatchRegister(p1,n)) &&
			fnmatch(p,(MatchFlags)(flags & ~MatchNoPeriod),n - theString) == 0)
			return 0;
		    }
	      
		return -1;
		}

	    case '[':

		{
		int neg, done = 0;

		if (*n == '\0')
		    return -1;

		if ((flags & MatchNoPeriod) && *n == '.' &&
		    (n == theString || ((flags & MatchPathname) && *(n - 1) == '/')))
		    return -1;

		neg = (*p == '!' || *p == '^');

		if (neg)
		    ++p;

		c = *p++;

		for (;;)
		    {
		    char cstart = c, cend = c;

		    if (!(flags & MatchNoEscape) && c == '\\')
			cstart = cend = *p++;

		    if (c == '\0')
			return -1;

		    c = *p++;

		    if ((flags & MatchPathname) && c == '/')
			return -1;

		    if (c == '-' && *p != ']')
			{
			cend = *p++;

			if (!(flags & MatchNoEscape) && cend == '\\')
			    cend = *p++;

			if (cend == '\0')
			    return -1;

			c = *p++;
			}

		    if (*n >= cstart && *n <= cend)
			{
			while (c != ']')
			    {
			    if (c == '\0')
				return -1;

			    c = *p++;
			    if (!(flags & MatchNoEscape) && c == '\\')
				++p;
			    }

			if (neg)
			    return -1;

			done = 1;
			break;
			}

		    if (c == ']')
			break;
		    }

		if (!done && !neg)
		    return -1;
		}

		break;

	    default:

		if (c != *n)
		    return -1;
	    }

	++n;
	}

    return *n == '\0' ? 0 : -1;
}

int CString::setMatchRegister (const char *p,
			       const char *s) const
{
    CString *matchString;
	
    if (*p == '(')
	matchString = new LString(&matchStrings,s);
    else if (*p == ')')
	{
	matchString = matchStrings.last();

	if (matchString)
	    matchString->strip(matchString->len() - fstrlen(s),
			       matchString->len());
	}
    else
	return 0;

    return 1;
}

const char *CString::getMatchRegister (int nth)

{
    LString *ls = matchStrings.nth(nth);

    if (ls)
	return *ls;

    return 0;
}

int CString::subst (int leftpos, int rightpos, const char *s)

{
    CString cs = CString(theString,len() - (len() - leftpos));

    if (rightpos < 0)
	rightpos = len();
    
    int slen;

    if (s)
	{
	cs += s;
	slen = fstrlen(s);
	}
    else
	slen = 0;

    if ((unsigned)rightpos < len())
	cs += CString(theString + rightpos + 1);

    *this = cs;

    return Max(leftpos,0) + slen;
}

int CString::insert (int point, const char *s)

{
    CString cs(s);

    if (point >= 0 && (unsigned)point < len())
	cs.appendChar(theString[point]);

    return subst(point,point,cs);
}

int CString::subst (const char *olds, const char *news)

{
    int ix = match(olds);

    if (ix >= 0)
	ix = subst(ix,ix + fstrlen(olds) - 1,news);

    return ix;
}

int CString::rsubst (const char *olds, const char *news)

{
    int ix = rmatch(olds);

    if (ix >= 0)
	ix = subst(ix,ix + fstrlen(olds) - 1,news);

    return ix;
}

CString CString::getSmartPath (int nkept) // pretend that theString is a (long) pathname

{
    CString fullPath = *this, smartPath, seg;
    int n = 0;

    CString slash;
    slash.appendChar('/');

    do
	{
	seg = fullPath.basename();
	fullPath = fullPath.dirname();
	smartPath = slash + seg + smartPath;
	}
    while (++n < nkept && !seg.isEmpty());

    if (!fullPath.isVoid() && strcmp(fullPath,slash))
	smartPath = "{..}" + smartPath;

    return smartPath;
}

CString CString::getAbbrevPath (int okAbsNames) // pretend that theString is a pathname

{
    CString is, os;

    if (!theString)
	return os;

    is = theString;
    is.canonicalize();

    if (*is.theString != '/')	// translate relative pathes to absolute
	{
	char wd[MAXPATHLEN];
	getcwd(wd,sizeof(wd));
	is = wd + CString("/") + is;
	}

    os = is;

    struct passwd *pw = getpwuid(getuid());
    const char *userName = pw ? strdup(pw->pw_name) : "";

    if (strcmp(is.theString,"/")) // Don't abbreviate "/" to ~root...
	{
	setpwent();

	while ((pw = getpwent()) != NULL)
	    {
	    int l = pw->pw_dir ? fstrlen(pw->pw_dir) : 0;

	    if (pw->pw_uid != 65534 && // skip "nobody" - Yes, this is crappy...
		pw->pw_dir && *pw->pw_dir &&
		strncmp(pw->pw_dir,is.theString,l) == 0 &&
		(!is.theString[l] || is.theString[l] == '/'))
		{
		os = "~";
	    
		if (okAbsNames || strcmp(userName,pw->pw_name))
		    os += pw->pw_name;
		
		os += is.theString + l;
		break;
		}
	    }
	}

    return os;
}

const char *CString::canonicalize ()

{
    *this = tosh_getcanonpath(expand());
    return *this;
}

const char *CString::posixize ()

{
    *this = tosh_getposixpath(expand());
    return *this;
}

void CString::trimExtraZeroes ()

{
    if (!theString || !*theString)
	return;

    char *ptr = theString + len() - 1;

    while (ptr > theString && *ptr == '0')
	ptr--;
  
    if (*ptr != '.')
	return;

    *ptr = '\0';
    unsigned oldlen = theSize.ubytes;
    theSize.ubytes = ptr - theString;
    theSize.xbytes += (oldlen - theSize.ubytes);
}

LString::~LString ()

{
    if (ll && !ll->isDestroying())
	ll->remove(this);
}

int LString::compare (Link *buddy)

{
    LString *ls = (LString *)buddy;
    return strcmp(gets(),ls->gets());
}
