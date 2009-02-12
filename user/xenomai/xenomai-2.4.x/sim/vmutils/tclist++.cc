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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 *
 * The functions prefixed "MvmTcl", as well as the structure MvmTcl_DString
 * declared in tclist++.h were extracted from Tcl/Tk 8.3.5 sources. The
 * original comments follow:
 *
 * tclUtil.c --
 *
 *	This file contains utility procedures that are used by many Tcl
 *	commands.
 *
 * Copyright (c) 1987-1993 The Regents of the University of California.
 * Copyright (c) 1994-1998 Sun Microsystems, Inc.
 *
 * See the file "license.terms" for information on usage and redistribution
 * of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <stdlib.h>
#include <ctype.h>              /* For isspace */
#include <string.h>
#include "vmutils/string++.h"
#include "vmutils/tclist++.h"

#define ckalloc malloc
#define ckrealloc realloc
#define ckfree free

#define MvmTcl_Alloc(size) ((char *)malloc(size))
#define MvmTcl_Free free

#define MvmTcl_DStringLength(dsPtr) ((dsPtr)->length)
#define MvmTcl_DStringValue(dsPtr) ((dsPtr)->string)
#define MvmTcl_DStringTrunc Tcl_DStringSetLength

/*
 * When a TCL command returns, the interpreter contains a result from the
 * command. Programmers are strongly encouraged to use one of the
 * procedures MvmTcl_GetObjResult() or MvmTcl_GetStringResult() to read the
 * interpreter's result. See the SetResult man page for details. Besides
 * this result, the command procedure returns an integer code, which is 
 * one of the following:
 *
 * MVM_TCL_OK		Command completed normally; the interpreter's
 *			result contains	the command's result.
 * MVM_TCL_ERROR	The command couldn't be completed successfully;
 */

#define MVM_TCL_OK		0
#define MVM_TCL_ERROR	1


/*
 * The maximum number of bytes that are necessary to represent a single
 * Unicode character in UTF-8.
 */

#define MVM_TCL_UTF_MAX		3


/*
 * The macro below is used to modify a "char" value (e.g. by casting
 * it to an unsigned character) so that it can be used safely with
 * macros such as isspace.
 */

#define UCHAR(c) ((unsigned char) (c))

/*
 * Unicode characters less than this value are represented by themselves 
 * in UTF-8 strings. 
 */

#define UNICODE_SELF	0x80


/*
 * The following values are used in the flags returned by MvmTcl_ScanElement
 * and used by MvmTcl_ConvertElement.  The value TCL_DONT_USE_BRACES is also
 * defined in tcl.h;  make sure its value doesn't overlap with any of the
 * values below.
 *
 * MVM_TCL_DONT_USE_BRACES -	1 means the string mustn't be enclosed in
 *				braces (e.g. it contains unmatched braces,
 *				or ends in a backslash character, or user
 *				just doesn't want braces);  handle all
 *				special characters by adding backslashes.
 * USE_BRACES -			1 means the string contains a special
 *				character that can be handled simply by
 *				enclosing the entire argument in braces.
 * BRACES_UNMATCHED -		1 means that braces aren't properly matched
 *				in the argument.
 */

#define MVM_TCL_DONT_USE_BRACES	1
#define USE_BRACES		2
#define BRACES_UNMATCHED	4

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_DStringInit --
 *
 *	Initializes a dynamic string, discarding any previous contents
 *	of the string (MvmTcl_DStringFree should have been called already
 *	if the dynamic string was previously in use).
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	The dynamic string is initialized to be empty.
 *
 *----------------------------------------------------------------------
 */

static void
MvmTcl_DStringInit(
    MvmTcl_DString *dsPtr)      /* Pointer to structure for dynamic string. */
{
    dsPtr->string = dsPtr->staticSpace;
    dsPtr->length = 0;
    dsPtr->spaceAvl = MVM_TCL_DSTRING_STATIC_SIZE;
    dsPtr->staticSpace[0] = '\0';
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_DStringFree --
 *
 *	Frees up any memory allocated for the dynamic string and
 *	reinitializes the string to an empty state.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	The previous contents of the dynamic string are lost, and
 *	the new value is an empty string.
 *
 *---------------------------------------------------------------------- */

static void
MvmTcl_DStringFree(
    MvmTcl_DString *dsPtr)      /* Structure describing dynamic string. */
{
    if (dsPtr->string != dsPtr->staticSpace) {
	ckfree(dsPtr->string);
    }
    dsPtr->string = dsPtr->staticSpace;
    dsPtr->length = 0;
    dsPtr->spaceAvl = MVM_TCL_DSTRING_STATIC_SIZE;
    dsPtr->staticSpace[0] = '\0';
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_DStringAppend --
 *
 *	Append more characters to the current value of a dynamic string.
 *
 * Results:
 *	The return value is a pointer to the dynamic string's new value.
 *
 * Side effects:
 *	Length bytes from string (or all of string if length is less
 *	than zero) are added to the current value of the string. Memory
 *	gets reallocated if needed to accomodate the string's new size.
 *
 *----------------------------------------------------------------------
 */

static char *
MvmTcl_DStringAppend(
    MvmTcl_DString *dsPtr,      /* Structure describing dynamic string. */
    const char *string,		/* String to append.  If length is -1 then
				 * this must be null-terminated. */
    int length)			/* Number of characters from string to
				 * append.  If < 0, then append all of string,
				 * up to null at end. */
{
    int newSize;
    char *dst;
    const char *end;

    if (length < 0) {
	length = strlen(string);
    }
    newSize = length + dsPtr->length;

    /*
     * Allocate a larger buffer for the string if the current one isn't
     * large enough. Allocate extra space in the new buffer so that there
     * will be room to grow before we have to allocate again.
     */

    if (newSize >= dsPtr->spaceAvl) {
	dsPtr->spaceAvl = newSize * 2;
	if (dsPtr->string == dsPtr->staticSpace) {
	    char *newString;

	    newString = (char *) ckalloc((unsigned) dsPtr->spaceAvl);
	    memcpy((void *) newString, (void *) dsPtr->string,
		    (size_t) dsPtr->length);
	    dsPtr->string = newString;
	} else {
	    dsPtr->string = (char *) ckrealloc((void *) dsPtr->string,
		    (size_t) dsPtr->spaceAvl);
	}
    }

    /*
     * Copy the new string into the buffer at the end of the old
     * one.
     */

    for (dst = dsPtr->string + dsPtr->length, end = string+length;
	    string < end; string++, dst++) {
	*dst = *string;
    }
    *dst = '\0';
    dsPtr->length += length;
    return dsPtr->string;
}

/*
 *---------------------------------------------------------------------------
 *
 * MvmTcl_UniCharToUtf --
 *
 *	Store the given MvmTcl_UniChar as a sequence of UTF-8 bytes in the
 *	provided buffer.  Equivalent to Plan 9 runetochar().
 *
 * Results:
 *	The return values is the number of bytes in the buffer that
 *	were consumed.  
 *
 * Side effects:
 *	None.
 *
 *---------------------------------------------------------------------------
 */
 
static inline int
MvmTcl_UniCharToUtf(
    int ch,			/* The MvmTcl_UniChar to be stored in the
				 * buffer. */
    char *str)			/* Buffer in which the UTF-8 representation
				 * of the MvmTcl_UniChar is stored.  Buffer must
				 * be large enough to hold the UTF-8 character
				 * (at most MVM_TCL_UTF_MAX bytes). */
{
    if ((ch > 0) && (ch < UNICODE_SELF)) {
	str[0] = (char) ch;
	return 1;
    }
    if (ch <= 0x7FF) {
	str[1] = (char) ((ch | 0x80) & 0xBF);
	str[0] = (char) ((ch >> 6) | 0xC0);
	return 2;
    }
    if (ch <= 0xFFFF) {
	three:
	str[2] = (char) ((ch | 0x80) & 0xBF);
	str[1] = (char) (((ch >> 6) | 0x80) & 0xBF);
	str[0] = (char) ((ch >> 12) | 0xE0);
	return 3;
    }

    ch = 0xFFFD;
    goto three;
}

/*
 *---------------------------------------------------------------------------
 *
 * MvmTcl_UtfBackslash --
 *
 *	Figure out how to handle a backslash sequence.
 *
 * Results:
 *	Stores the bytes represented by the backslash sequence in dst and
 *	returns the number of bytes written to dst.  At most MVM_TCL_UTF_MAX
 *	bytes are written to dst; dst must have been large enough to accept
 *	those bytes.  If readPtr isn't NULL then it is filled in with a
 *	count of the number of bytes in the backslash sequence.  
 *
 * Side effects:
 *	The maximum number of bytes it takes to represent a Unicode
 *	character in UTF-8 is guaranteed to be less than the number of
 *	bytes used to express the backslash sequence that represents
 *	that Unicode character.  If the target buffer into which the
 *	caller is going to store the bytes that represent the Unicode
 *	character is at least as large as the source buffer from which
 *	the backslashed sequence was extracted, no buffer overruns should
 *	occur.
 *
 *---------------------------------------------------------------------------
 */

static int
MvmTcl_UtfBackslash(
    const char *src,		/* Points to the backslash character of
				 * a backslash sequence. */
    int *readPtr,		/* Fill in with number of characters read
				 * from src, unless NULL. */
    char *dst)			/* Filled with the bytes represented by the
				 * backslash sequence. */
{
    register const char *p = src+1;
    int result, count, n;
    char buf[MVM_TCL_UTF_MAX];

    if (dst == NULL) {
	dst = buf;
    }

    count = 2;
    switch (*p) {
	/*
         * Note: in the conversions below, use absolute values (e.g.,
         * 0xa) rather than symbolic values (e.g. \n) that get converted
         * by the compiler.  It's possible that compilers on some
         * platforms will do the symbolic conversions differently, which
         * could result in non-portable Tcl scripts.
         */

        case 'a':
            result = 0x7;
            break;
        case 'b':
            result = 0x8;
            break;
        case 'f':
            result = 0xc;
            break;
        case 'n':
            result = 0xa;
            break;
        case 'r':
            result = 0xd;
            break;
        case 't':
            result = 0x9;
            break;
        case 'v':
            result = 0xb;
            break;
        case 'x':
            if (isxdigit(UCHAR(p[1]))) { /* INTL: digit */
                char *end;

                result = (unsigned char) strtoul(p+1, &end, 16);
                count = end - src;
            } else {
                count = 2;
                result = 'x';
            }
            break;
	case 'u':
	    result = 0;
	    for (count = 0; count < 4; count++) {
		p++;
		if (!isxdigit(UCHAR(*p))) { /* INTL: digit */
		    break;
		}
		n = *p - '0';
		if (n > 9) {
		    n = n + '0' + 10 - 'A';
		}
		if (n > 16) {
		    n = n + 'A' - 'a';
		}
		result = (result << 4) + n;
	    }
	    if (count == 0) {
		result = 'u';
	    }
	    count += 2;
	    break;
		    
        case '\n':
            do {
                p++;
            } while ((*p == ' ') || (*p == '\t'));
            result = ' ';
            count = p - src;
            break;
        case 0:
            result = '\\';
            count = 1;
            break;
	default:
	    /*
	     * Check for an octal number \oo?o?
	     */
	    if (isdigit(UCHAR(*p)) && (UCHAR(*p) < '8')) { /* INTL: digit*/
		result = (unsigned char)(*p - '0');
		p++;
		if (!isdigit(UCHAR(*p)) || (UCHAR(*p) >= '8')) { /* INTL: digit*/
		    break;
		}
		count = 3;
		result = (unsigned char)((result << 3) + (*p - '0'));
		p++;
		if (!isdigit(UCHAR(*p)) || (UCHAR(*p) >= '8')) { /* INTL: digit*/
		    break;
		}
		count = 4;
		result = (unsigned char)((result << 3) + (*p - '0'));
		break;
	    }
	    result = *p;
	    count = 2;
	    break;
    }

    if (readPtr != NULL) {
	*readPtr = count;
    }
    return MvmTcl_UniCharToUtf(result, dst);
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_ScanCountedElement --
 *
 *	This procedure is a companion procedure to
 *	MvmTcl_ConvertCountedElement.  It scans a string to see what
 *	needs to be done to it (e.g. add backslashes or enclosing
 *	braces) to make the string into a valid Tcl list element.
 *	If length is -1, then the string is scanned up to the first
 *	null byte.
 *
 * Results:
 *	The return value is an overestimate of the number of characters
 *	that will be needed by MvmTcl_ConvertCountedElement to produce a
 *	valid list element from string.  The word at *flagPtr is
 *	filled in with a value needed by MvmTcl_ConvertCountedElement
 *	when doing the actual conversion.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
MvmTcl_ScanCountedElement(
    const char *string,		/* String to convert to Tcl list element. */
    int length,			/* Number of bytes in string, or -1. */
    int *flagPtr)		/* Where to store information to guide
				 * MvmTcl_ConvertElement. */
{
    int flags, nestingLevel;
    register const char *p, *lastChar;

    /*
     * This procedure and MvmTcl_ConvertElement together do two things:
     *
     * 1. They produce a proper list, one that will yield back the
     * argument strings when evaluated or when disassembled with
     * MvmTcl_SplitList.  This is the most important thing.
     * 
     * 2. They try to produce legible output, which means minimizing the
     * use of backslashes (using braces instead).  However, there are
     * some situations where backslashes must be used (e.g. an element
     * like "{abc": the leading brace will have to be backslashed.
     * For each element, one of three things must be done:
     *
     * (a) Use the element as-is (it doesn't contain any special
     * characters).  This is the most desirable option.
     *
     * (b) Enclose the element in braces, but leave the contents alone.
     * This happens if the element contains embedded space, or if it
     * contains characters with special interpretation ($, [, ;, or \),
     * or if it starts with a brace or double-quote, or if there are
     * no characters in the element.
     *
     * (c) Don't enclose the element in braces, but add backslashes to
     * prevent special interpretation of special characters.  This is a
     * last resort used when the argument would normally fall under case
     * (b) but contains unmatched braces.  It also occurs if the last
     * character of the argument is a backslash or if the element contains
     * a backslash followed by newline.
     *
     * The procedure figures out how many bytes will be needed to store
     * the result (actually, it overestimates). It also collects information
     * about the element in the form of a flags word.
     *
     * Note: list elements produced by this procedure and
     * MvmTcl_ConvertCountedElement must have the property that they can be
     * enclosing in curly braces to make sub-lists.  This means, for
     * example, that we must not leave unmatched curly braces in the
     * resulting list element.  This property is necessary in order for
     * procedures like MvmTcl_DStringStartSublist to work.
     */

    nestingLevel = 0;
    flags = 0;
    if (string == NULL) {
	string = "";
    }
    if (length == -1) {
	length = strlen(string);
    }
    lastChar = string + length;
    p = string;
    if ((p == lastChar) || (*p == '{') || (*p == '"')) {
	flags |= USE_BRACES;
    }
    for ( ; p < lastChar; p++) {
	switch (*p) {
	    case '{':
		nestingLevel++;
		break;
	    case '}':
		nestingLevel--;
		if (nestingLevel < 0) {
		    flags |= MVM_TCL_DONT_USE_BRACES|BRACES_UNMATCHED;
		}
		break;
	    case '[':
	    case '$':
	    case ';':
	    case ' ':
	    case '\f':
	    case '\n':
	    case '\r':
	    case '\t':
	    case '\v':
		flags |= USE_BRACES;
		break;
	    case '\\':
		if ((p+1 == lastChar) || (p[1] == '\n')) {
		    flags = MVM_TCL_DONT_USE_BRACES | BRACES_UNMATCHED;
		} else {
		    int size;

		    MvmTcl_UtfBackslash(p, &size, NULL);
		    p += size-1;
		    flags |= USE_BRACES;
		}
		break;
	}
    }
    if (nestingLevel != 0) {
	flags = MVM_TCL_DONT_USE_BRACES | BRACES_UNMATCHED;
    }
    *flagPtr = flags;

    /*
     * Allow enough space to backslash every character plus leave
     * two spaces for braces.
     */

    return 2*(p-string) + 2;
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_ScanElement --
 *
 *	This procedure is a companion procedure to MvmTcl_ConvertElement.
 *	It scans a string to see what needs to be done to it (e.g. add
 *	backslashes or enclosing braces) to make the string into a
 *	valid Tcl list element.
 *
 * Results:
 *	The return value is an overestimate of the number of characters
 *	that will be needed by MvmTcl_ConvertElement to produce a valid
 *	list element from string.  The word at *flagPtr is filled in
 *	with a value needed by MvmTcl_ConvertElement when doing the actual
 *	conversion.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static inline int
MvmTcl_ScanElement(
    register const char *string, /* String to convert to list element. */
    register int *flagPtr)	 /* Where to store information to guide
				  * MvmTcl_ConvertCountedElement. */
{
    return MvmTcl_ScanCountedElement(string, -1, flagPtr);
}

/*
 *----------------------------------------------------------------------
 *
 * TclNeedSpace --
 *
 *	This procedure checks to see whether it is appropriate to
 *	add a space before appending a new list element to an
 *	existing string.
 *
 * Results:
 *	The return value is 1 if a space is appropriate, 0 otherwise.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
TclNeedSpace(
    char *start,		/* First character in string. */
    char *end)			/* End of string (place where space will
				 * be added, if appropriate). */
{
    /*
     * A space is needed unless either
     * (a) we're at the start of the string, or
     * (b) the trailing characters of the string consist of one or more
     *     open curly braces preceded by a space or extending back to
     *     the beginning of the string.
     * (c) the trailing characters of the string consist of a space
     *	   preceded by a character other than backslash.
     */

    if (end == start) {
	return 0;
    }
    end--;
    if (*end != '{') {
	if (isspace(UCHAR(*end)) /* INTL: ISO space. */
		&& ((end == start) || (end[-1] != '\\'))) {
	    return 0;
	}
	return 1;
    }
    do {
	if (end == start) {
	    return 0;
	}
	end--;
    } while (*end == '{');
    if (isspace(UCHAR(*end))) {	/* INTL: ISO space. */
	return 0;
    }
    return 1;
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_ConvertCountedElement --
 *
 *	This is a companion procedure to MvmTcl_ScanCountedElement.  Given
 *	the information produced by MvmTcl_ScanCountedElement, this
 *	procedure converts a string to a list element equal to that
 *	string.
 *
 * Results:
 *	Information is copied to *dst in the form of a list element
 *	identical to src (i.e. if MvmTcl_SplitList is applied to dst it
 *	will produce a string identical to src).  The return value is
 *	a count of the number of characters copied (not including the
 *	terminating NULL character).
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
MvmTcl_ConvertCountedElement(
    register const char *src,	/* Source information for list element. */
    int length,			/* Number of bytes in src, or -1. */
    char *dst,			/* Place to put list-ified element. */
    int flags)			/* Flags produced by MvmTcl_ScanElement. */
{
    register char *p = dst;
    register const char *lastChar;

    /*
     * See the comment block at the beginning of the MvmTcl_ScanElement
     * code for details of how this works.
     */

    if (src && length == -1) {
	length = strlen(src);
    }
    if ((src == NULL) || (length == 0)) {
	p[0] = '{';
	p[1] = '}';
	p[2] = 0;
	return 2;
    }
    lastChar = src + length;
    if ((flags & USE_BRACES) && !(flags & MVM_TCL_DONT_USE_BRACES)) {
	*p = '{';
	p++;
	for ( ; src != lastChar; src++, p++) {
	    *p = *src;
	}
	*p = '}';
	p++;
    } else {
	if (*src == '{') {
	    /*
	     * Can't have a leading brace unless the whole element is
	     * enclosed in braces.  Add a backslash before the brace.
	     * Furthermore, this may destroy the balance between open
	     * and close braces, so set BRACES_UNMATCHED.
	     */

	    p[0] = '\\';
	    p[1] = '{';
	    p += 2;
	    src++;
	    flags |= BRACES_UNMATCHED;
	}
	for (; src != lastChar; src++) {
	    switch (*src) {
		case ']':
		case '[':
		case '$':
		case ';':
		case ' ':
		case '\\':
		case '"':
		    *p = '\\';
		    p++;
		    break;
		case '{':
		case '}':
		    /*
		     * It may not seem necessary to backslash braces, but
		     * it is.  The reason for this is that the resulting
		     * list element may actually be an element of a sub-list
		     * enclosed in braces (e.g. if MvmTcl_DStringStartSublist
		     * has been invoked), so there may be a brace mismatch
		     * if the braces aren't backslashed.
		     */

		    if (flags & BRACES_UNMATCHED) {
			*p = '\\';
			p++;
		    }
		    break;
		case '\f':
		    *p = '\\';
		    p++;
		    *p = 'f';
		    p++;
		    continue;
		case '\n':
		    *p = '\\';
		    p++;
		    *p = 'n';
		    p++;
		    continue;
		case '\r':
		    *p = '\\';
		    p++;
		    *p = 'r';
		    p++;
		    continue;
		case '\t':
		    *p = '\\';
		    p++;
		    *p = 't';
		    p++;
		    continue;
		case '\v':
		    *p = '\\';
		    p++;
		    *p = 'v';
		    p++;
		    continue;
	    }
	    *p = *src;
	    p++;
	}
    }
    *p = '\0';
    return p-dst;
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_ConvertElement --
 *
 *	This is a companion procedure to MvmTcl_ScanElement.  Given
 *	the information produced by MvmTcl_ScanElement, this procedure
 *	converts a string to a list element equal to that string.
 *
 * Results:
 *	Information is copied to *dst in the form of a list element
 *	identical to src (i.e. if MvmTcl_SplitList is applied to dst it
 *	will produce a string identical to src).  The return value is
 *	a count of the number of characters copied (not including the
 *	terminating NULL character).
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static inline int
MvmTcl_ConvertElement(
    register const char *src,	/* Source information for list element. */
    register char *dst,		/* Place to put list-ified element. */
    register int flags)		/* Flags produced by MvmTcl_ScanElement. */
{
    return MvmTcl_ConvertCountedElement(src, -1, dst, flags);
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_DStringAppendElement --
 *
 *	Append a list element to the current value of a dynamic string.
 *
 * Results:
 *	The return value is a pointer to the dynamic string's new value.
 *
 * Side effects:
 *	String is reformatted as a list element and added to the current
 *	value of the string.  Memory gets reallocated if needed to
 *	accomodate the string's new size.
 *
 *----------------------------------------------------------------------
 */

static char *
MvmTcl_DStringAppendElement(
    MvmTcl_DString *dsPtr,      /* Structure describing dynamic string. */
    const char *string)		/* String to append.  Must be
				 * null-terminated. */
{
    int newSize, flags;
    char *dst;

    newSize = MvmTcl_ScanElement(string, &flags) + dsPtr->length + 1;

    /*
     * Allocate a larger buffer for the string if the current one isn't
     * large enough.  Allocate extra space in the new buffer so that there
     * will be room to grow before we have to allocate again.
     * SPECIAL NOTE: must use memcpy, not strcpy, to copy the string
     * to a larger buffer, since there may be embedded NULLs in the
     * string in some cases.
     */

    if (newSize >= dsPtr->spaceAvl) {
	dsPtr->spaceAvl = newSize * 2;
	if (dsPtr->string == dsPtr->staticSpace) {
	    char *newString;

	    newString = (char *) ckalloc((unsigned) dsPtr->spaceAvl);
	    memcpy((void *) newString, (void *) dsPtr->string,
		    (size_t) dsPtr->length);
	    dsPtr->string = newString;
	} else {
	    dsPtr->string = (char *) ckrealloc((void *) dsPtr->string,
		    (size_t) dsPtr->spaceAvl);
	}
    }

    /*
     * Convert the new string to a list element and copy it into the
     * buffer at the end, with a space, if needed.
     */

    dst = dsPtr->string + dsPtr->length;
    if (TclNeedSpace(dsPtr->string, dst)) {
	*dst = ' ';
	dst++;
	dsPtr->length++;
    }
    dsPtr->length += MvmTcl_ConvertElement(string, dst, flags);
    return dsPtr->string;
}


/*
 *----------------------------------------------------------------------
 *
 * TclFindElement --
 *
 *	Given a pointer into a Tcl list, locate the first (or next)
 *	element in the list.
 *
 * Results:
 *	The return value is normally MVM_TCL_OK, which means that the
 *	element was successfully located.  If MVM_TCL_ERROR is returned
 *	it means that list didn't have proper list structure;
 *	the interp's result contains a more detailed error message.
 *
 *	If MVM_TCL_OK is returned, then *elementPtr will be set to point to the
 *	first element of list, and *nextPtr will be set to point to the
 *	character just after any white space following the last character
 *	that's part of the element. If this is the last argument in the
 *	list, then *nextPtr will point just after the last character in the
 *	list (i.e., at the character at list+listLength). If sizePtr is
 *	non-NULL, *sizePtr is filled in with the number of characters in the
 *	element.  If the element is in braces, then *elementPtr will point
 *	to the character after the opening brace and *sizePtr will not
 *	include either of the braces. If there isn't an element in the list,
 *	*sizePtr will be zero, and both *elementPtr and *termPtr will point
 *	just after the last character in the list. Note: this procedure does
 *	NOT collapse backslash sequences.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
MvmTclFindElement(
    const char *list,		/* Points to the first byte of a string
				 * containing a Tcl list with zero or more
				 * elements (possibly in braces). */
    int listLength,		/* Number of bytes in the list's string. */
    const char **elementPtr,	/* Where to put address of first significant
				 * character in first element of list. */
    const char **nextPtr,	/* Fill in with location of character just
				 * after all white space following end of
				 * argument (next arg or end of list). */
    int *sizePtr,		/* If non-zero, fill in with size of
				 * element. */
    int *bracePtr)		/* If non-zero, fill in with non-zero/zero
				 * to indicate that arg was/wasn't
				 * in braces. */
{
    const char *p = list;
    const char *elemStart;	/* Points to first byte of first element. */
    const char *limit;		/* Points just after list's last byte. */
    int openBraces = 0;		/* Brace nesting level during parse. */
    int inQuotes = 0;
    int size = 0;		/* lint. */
    int numChars;
    
    /*
     * Skim off leading white space and check for an opening brace or
     * quote. We treat embedded NULLs in the list as bytes belonging to
     * a list element.
     */

    limit = (list + listLength);
    while ((p < limit) && (isspace(UCHAR(*p)))) { /* INTL: ISO space. */
	p++;
    }
    if (p == limit) {		/* no element found */
	elemStart = limit;
	goto done;
    }

    if (*p == '{') {
	openBraces = 1;
	p++;
    } else if (*p == '"') {
	inQuotes = 1;
	p++;
    }
    elemStart = p;
    if (bracePtr != 0) {
	*bracePtr = openBraces;
    }

    /*
     * Find element's end (a space, close brace, or the end of the string).
     */

    while (p < limit) {
	switch (*p) {

	    /*
	     * Open brace: don't treat specially unless the element is in
	     * braces. In this case, keep a nesting count.
	     */

	    case '{':
		if (openBraces != 0) {
		    openBraces++;
		}
		break;

	    /*
	     * Close brace: if element is in braces, keep nesting count and
	     * quit when the last close brace is seen.
	     */

	    case '}':
		if (openBraces > 1) {
		    openBraces--;
		} else if (openBraces == 1) {
		    size = (p - elemStart);
		    p++;
		    if ((p >= limit)
			    || isspace(UCHAR(*p))) { /* INTL: ISO space. */
			goto done;
		    }

		    /*
		     * Garbage after the closing brace; return an error.
		     */
		    return MVM_TCL_ERROR;
		}
		break;

	    /*
	     * Backslash:  skip over everything up to the end of the
	     * backslash sequence.
	     */

	    case '\\': {
		MvmTcl_UtfBackslash(p, &numChars, NULL);
		p += (numChars - 1);
		break;
	    }

	    /*
	     * Space: ignore if element is in braces or quotes; otherwise
	     * terminate element.
	     */

	    case ' ':
	    case '\f':
	    case '\n':
	    case '\r':
	    case '\t':
	    case '\v':
		if ((openBraces == 0) && !inQuotes) {
		    size = (p - elemStart);
		    goto done;
		}
		break;

	    /*
	     * Double-quote: if element is in quotes then terminate it.
	     */

	    case '"':
		if (inQuotes) {
		    size = (p - elemStart);
		    p++;
		    if ((p >= limit)
			    || isspace(UCHAR(*p))) { /* INTL: ISO space */
			goto done;
		    }

		    /*
		     * Garbage after the closing quote; return an error.
		     */
		    
		    return MVM_TCL_ERROR;
		}
		break;
	}
	p++;
    }


    /*
     * End of list: terminate element.
     */

    if (p == limit) {
	if (openBraces != 0)
	    return MVM_TCL_ERROR;
	else
            if (inQuotes)
                return MVM_TCL_ERROR;
	size = (p - elemStart);
    }

    done:
    while ((p < limit) && (isspace(UCHAR(*p)))) { /* INTL: ISO space. */
	p++;
    }
    *elementPtr = elemStart;
    *nextPtr = p;
    if (sizePtr != 0) {
	*sizePtr = size;
    }
    return MVM_TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * TclCopyAndCollapse --
 *
 *	Copy a string and eliminate any backslashes that aren't in braces.
 *
 * Results:
 *	There is no return value. Count characters get copied from src to
 *	dst. Along the way, if backslash sequences are found outside braces,
 *	the backslashes are eliminated in the copy. After scanning count
 *	chars from source, a null character is placed at the end of dst.
 *	Returns the number of characters that got copied.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static int
MvmTclCopyAndCollapse(
    int count,			/* Number of characters to copy from src. */
    const char *src,		/* Copy from here... */
    char *dst)			/* ... to here. */
{
    register char c;
    int numRead;
    int newCount = 0;
    int backslashCount;

    for (c = *src;  count > 0;  src++, c = *src, count--) {
	if (c == '\\') {
	    backslashCount = MvmTcl_UtfBackslash(src, &numRead, dst);
	    dst += backslashCount;
	    newCount += backslashCount;
	    src += numRead-1;
	    count -= numRead-1;
	} else {
	    *dst = c;
	    dst++;
	    newCount++;
	}
    }
    *dst = 0;
    return newCount;
}

/*
 *----------------------------------------------------------------------
 *
 * MvmTcl_SplitList --
 *
 *	Splits a list up into its constituent fields.
 *
 * Results
 *	The return value is normally MVM_TCL_OK, which means that
 *	the list was successfully split up.  If MVM_TCL_ERROR is
 *	returned, it means that "list" didn't have proper list
 *	structure;  the interp's result will contain a more detailed
 *	error message.
 *
 *	*argvPtr will be filled in with the address of an array
 *	whose elements point to the elements of list, in order.
 *	*argcPtr will get filled in with the number of valid elements
 *	in the array.  A single block of memory is dynamically allocated
 *	to hold both the argv array and a copy of the list (with
 *	backslashes and braces removed in the standard way).
 *	The caller must eventually free this memory by calling free()
 *	on *argvPtr.  Note:  *argvPtr and *argcPtr are only modified
 *	if the procedure returns normally.
 *
 * Side effects:
 *	Memory is allocated.
 *
 *----------------------------------------------------------------------
 */

static int
MvmTcl_SplitList(
    const char *list,		/* Pointer to string with list structure. */
    int *argcPtr,		/* Pointer to location to fill in with
				 * the number of elements in the list. */
    char ***argvPtr)		/* Pointer to place to store pointer to
				 * array of pointers to list elements. */
{
    char **argv;
    const char *l;
    char *p;
    int length, size, i, result, elSize, brace;
    const char *element;

    /*
     * Figure out how much space to allocate.  There must be enough
     * space for both the array of pointers and also for a copy of
     * the list.  To estimate the number of pointers needed, count
     * the number of space characters in the list.
     */

    for (size = 1, l = list; *l != 0; l++) {
	if (isspace(UCHAR(*l))) { /* INTL: ISO space. */
	    size++;
	}
    }
    size++;			/* Leave space for final NULL pointer. */
    argv = (char **) ckalloc((unsigned)
	    ((size * sizeof(char *)) + (l - list) + 1));
    length = strlen(list);
    for (i = 0, p = ((char *) argv) + size*sizeof(char *);
	    *list != 0;  i++) {
	const char *prevList = list;
	
	result=MvmTclFindElement(list, length, &element, &list, &elSize, &brace);
	length -= (list - prevList);
	if (result != MVM_TCL_OK) {
	    ckfree((char *) argv);
	    return result;
	}
	if (*element == 0) {
	    break;
	}
	if (i >= size) {
	    ckfree((char *) argv);
	    return MVM_TCL_ERROR;
	}
	argv[i] = p;
	if (brace) {
	    memcpy((void *) p, (void *) element, (size_t) elSize);
	    p += elSize;
	    *p = 0;
	    p++;
	} else {
	    MvmTclCopyAndCollapse(elSize, element, p);
	    p += elSize+1;
	}
    }

    argv[i] = NULL;
    *argvPtr = argv;
    *argcPtr = i;
    return MVM_TCL_OK;
}

TclList::TclList (const char *s)

{
    MvmTcl_DStringInit(&tclString);
    append(s);
}

TclList::TclList (const char *s, int n)

{
    MvmTcl_DStringInit(&tclString);
    append(s,n);
}

TclList::TclList (const TclList& src)

{
    MvmTcl_DStringInit(&tclString);

    if (MvmTcl_DStringLength(&src.tclString) > 0)
	MvmTcl_DStringAppend(&tclString,
			  MvmTcl_DStringValue(&src.tclString),
			  -1);
}

TclList::~TclList ()

{ MvmTcl_DStringFree(&tclString); }

const char *TclList::append (const char *s)

{
    if (s)
	MvmTcl_DStringAppendElement(&tclString,(char *)s);

    return MvmTcl_DStringValue(&tclString);
}

const char *TclList::append (const char *s, int n)

{
    if (n != 0)
	MvmTcl_DStringAppend(&tclString,s,n);

    return MvmTcl_DStringValue(&tclString);
}

const char *TclList::append (u_long n)

{ return MvmTcl_DStringAppendElement(&tclString,CString(n)); }

const char *TclList::appendx (u_long n)

{ return MvmTcl_DStringAppendElement(&tclString,CString().format("0x%lx",n)); }

const char *TclList::append (long n)

{ return MvmTcl_DStringAppendElement(&tclString,CString(n)); }

const char *TclList::appendx (long n)

{ return MvmTcl_DStringAppendElement(&tclString,CString().format("0x%lx",n)); }

#if __WORDSIZE < 64
const char *TclList::append (u_gnuquad_t n)

{ return MvmTcl_DStringAppendElement(&tclString,CString(n)); }

const char *TclList::appendx (u_gnuquad_t n)

{ return MvmTcl_DStringAppendElement(&tclString,CString().format("0x%llx",n)); }

const char *TclList::append (gnuquad_t n)

{ return MvmTcl_DStringAppendElement(&tclString,CString(n)); }

const char *TclList::appendx (gnuquad_t n)

{ return MvmTcl_DStringAppendElement(&tclString,CString().format("0x%llx",n)); }
#endif

const char *TclList::append (void *ptr)

{ return MvmTcl_DStringAppendElement(&tclString,CString(ptr)); }

const char *TclList::append (int n)

{ return MvmTcl_DStringAppendElement(&tclString,CString(n)); }

const char *TclList::append (short n)

{ return MvmTcl_DStringAppendElement(&tclString,CString((int)n)); }

const char *TclList::append (unsigned short n)

{ return MvmTcl_DStringAppendElement(&tclString,CString((u_long)n)); }

const char *TclList::append (unsigned n)

{ return MvmTcl_DStringAppendElement(&tclString,CString((u_long)n)); }

const char *TclList::append (double g)

{ 
    CString num(g, "%f");
    num.trimExtraZeroes();
    return MvmTcl_DStringAppendElement(&tclString,num); 
}

const char *TclList::append (const TclList& tclist)

{ return MvmTcl_DStringAppendElement(&tclString,tclist.get()); }

int TclList::length () const

{ return MvmTcl_DStringLength(&tclString); }

const char *TclList::set (const char *s)

{
    clear();
    return append(s);
}

const char *TclList::get () const

{ return MvmTcl_DStringValue(&tclString); }

void TclList::clear ()

{
    MvmTcl_DStringFree(&tclString);
    MvmTcl_DStringInit(&tclString);
}

TclList& TclList::operator =(const TclList& src)

{
    MvmTcl_DStringFree(&tclString);
    MvmTcl_DStringInit(&tclString);

    if (MvmTcl_DStringLength(&src.tclString) > 0)
	MvmTcl_DStringAppend(&tclString,
			  MvmTcl_DStringValue(&src.tclString),
			  -1);
    return *this;
}

TclList& TclList::operator += (const TclList& tclist)

{
    append(tclist);
    return *this;
}

TclList& TclList::operator += (const char *s)

{
    MvmTcl_DStringAppend(&tclString,s,-1);
    return *this;
}

TclListParser::TclListParser (const TclList& tclist)

{
    argv = NULL;
    argc = 0;
    cursor = 0;
    MvmTcl_SplitList((char *)tclist.get(),
		  &argc,
		  &argv);
}

TclListParser::TclListParser (const char *s)

{
    argv = NULL;
    argc = 0;
    cursor = 0;
    MvmTcl_SplitList((char *)s,
		  &argc,
		  &argv);
}

TclListParser::TclListParser (const TclListParser& src)

{
    argv = NULL;
    argc = src.argc;
    cursor = src.cursor;

    if (argc > 0)
	{
	int dstart = argc * sizeof(char *);
	int length = dstart;
	
	for (int n = 0; n < argc; n++)
	    length += (strlen(src.argv[n]) + 1);

	char *buf = MvmTcl_Alloc(length);
	argv = (char **)buf;

	for (int n = 0; n < argc; n++)
	    {
	    argv[n] = strcpy(buf + dstart,src.argv[n]);
	    dstart += (strlen(src.argv[n]) + 1);
	    }
	}
}

TclListParser::~TclListParser ()
    
{
    if (argv)
	MvmTcl_Free((char *)argv);
}

void TclListParser::reset (int reverse)

{ cursor = reverse ? argc : 0; }

const char *TclListParser::prev ()

{
    if (cursor > 0)
	return argv[--cursor];

    return NULL;
}

const char *TclListParser::next ()

{
    if (cursor < argc)
	return argv[cursor++];

    return NULL;
}
