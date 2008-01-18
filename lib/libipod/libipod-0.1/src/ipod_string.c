/*
 * ipod_string.c
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <ipod/ipod_string.h>
#include <ipod/ipod_memory.h>
#include <ipod/ipod_error.h>
#include <stdio.h>

static unsigned long ipod_string_allocs;
static unsigned long ipod_string_frees;

char *ipod_string_new(void)
{
	char *s = ipod_memory_alloc(1);
	s[0] = '\0';
	ipod_string_allocs++;
	return s;
}

char *ipod_string_new_from(const char *src)
{
	if (src) {
		char *dst = (char *)ipod_memory_alloc(strlen(src)+1);
		strcpy(dst,src);
		ipod_string_allocs++;
		return dst;
	}
	return ipod_string_new();
}

char *ipod_string_new_from_array(const char *src, size_t length)
{
	if (src && length>0) {
		char *dst = (char *)ipod_memory_alloc(length+1);
		memmove(dst,src,length);
		dst[length] = '\0';
		ipod_string_allocs++;
		return dst;
	}
	return ipod_string_new();
}

char *ipod_string_set(char *s,const char *ss) {
	s = ipod_string_realloc(s,strlen(ss));
	strcpy(s,ss);
	return s;
}

void ipod_string_free(char *s)
{
	if (s)
		ipod_string_frees++;
	else
		ipod_error("ipod_string_free(): freeing NULL string\n");
	ipod_memory_free(s);
}

char *ipod_string_realloc(char *src, size_t length)
{
	src = (char *)ipod_memory_realloc(src,length+1);
	src[length] = '\0';
	return src;
}

char *ipod_string_zero(char *s)
{
	if (s)
		s = ipod_string_realloc(s,0);
	else
		s = ipod_string_new();
	s[0] = '\0';
	return s;
}

char *ipod_string_append(char *src,const char *a)
{
	size_t len;
	if (!src) {
		ipod_error("ipod_string_append(): NULL string, creating...\n");
		src = ipod_string_new();
	}
	len = strlen(src);
	src = (char *)ipod_string_realloc(src,len+strlen(a));
	strcpy(&src[len],a);
	return src;
}

void ipod_string_replace_char(char *src, const char a, const char b)
{
	if (src)
		while (*src) {
			if (*src==a)
				*src = b;
			src++;
		}
	else
		ipod_error("ipod_string_replace(): NULL string\n");
}

size_t ipod_string_utf16_to_utf8_length(const char *src, size_t numChars)
{
	size_t len = 0;
	while (numChars--) {
		unsigned short c = (src[1]<<8)+src[0];
		len++;
		if (c>0x7f) {
			len++;
			if (c>0x7ff)
				len++;
		}
		src+=2;
	}
	return len;
}

size_t ipod_string_utf16_to_utf8(const char *src, size_t numChars, char *dst, size_t maxLen)
{
	size_t bytes = 0;
	if (!src) return 0;
	if (!dst) return 0;
	if (maxLen<=0) return 0;
	if (numChars<=0) {
		dst[0] = '\0';
		return 0;
	}
	while (numChars-- && maxLen>0) {
		unsigned short c = (((unsigned char *)src)[1]<<8)+((unsigned char *)src)[0];
		src+=2;
		if (c<0x80) {
			*dst++ = c;
			maxLen--;
			bytes++;
			continue;
		}
		if (c<0x800) {
			*dst++ = 0xc0 | ((c>>6) & 0x1f);
			*dst++ = 0x80 | (c & 0x3f);
			maxLen-=2;
			bytes += 2;
			continue;
		}
		*dst++ = 0xe0 | ((c>>12) & 0xf);
		*dst++ = 0x80 | ((c>>6) & 0x3f);
		*dst++ = 0x80 | (c & 0x3f);
		bytes += 3;
		maxLen-=3;
	}
	if (maxLen>0) {
		*dst = '\0';
	}
	return bytes; // does not include terminating null
}

size_t ipod_string_utf8_to_utf16_length(const char *s)
{
	static char lengths[] = {1,1,1,1,1,1,1,1,0,0,0,0,2,2,3,4};
	size_t numChars = 0;
	while (*s) {
		unsigned char c = *s;
		int size;
		if ((c<0xf7) && (size=lengths[(c>>4) & 0xf])) {
			numChars++;
			if (size==4) numChars++;
			s += size;
		} else {
			s++;
		}
	}
	return numChars;
}

size_t ipod_string_utf8_to_utf16(const char *src, char *dst, size_t maxLen)
{
	static char lengths[] = {1,1,1,1,1,1,1,1,0,0,0,0,2,2,3,4};
	static char masks[] = {0x00,0x00,0x1f,0x0f,0x07};
	size_t numChars = 0;
	if (!src) return 0;
	if (!dst) return 0;
	if (maxLen<=0) return 0;
	while (*src && maxLen>0) {
		int size;
		unsigned short value;
		unsigned char c = *src++;
		if (c<0x80) {
			*dst++ = c;
			*dst++ = 0;
			numChars++;
			maxLen--;
			continue;
		}
		size = lengths[(c>>4) & 0xf];
		if (size==0) // invalid,skip
			continue;
		if (size==4) {
			*dst++ = '?';
			*dst++ = 0;
			numChars++;
			maxLen--;
			continue;
		}
		value = c & masks[size];
		if (size==3) {
			value = (value<<6) | ((*src++) & 0x3f);
		}
		value = (value<<6) | ((*src++) & 0x3f);
		*dst++ = value & 0xff;
		*dst++ = value>>8;
		numChars++;
		maxLen--;
	}
	return numChars;
}


char *ipod_string_utf8_from_utf16(const char *src,size_t numChars)
{
	char *dst;
	size_t bytes = ipod_string_utf16_to_utf8_length(src,numChars);
	dst = (char *)ipod_memory_alloc(bytes+1);
	ipod_string_utf16_to_utf8(src,numChars,dst,bytes+1);
	return dst;
}

char *ipod_string_utf16_from_utf8(const char *src,size_t *numChars)
{
	char *dst;
	*numChars = ipod_string_utf8_to_utf16_length(src);
	dst = (char *)ipod_memory_alloc(*numChars*2);
	ipod_string_utf8_to_utf16(src,dst,*numChars);
	return dst;
}

char *ipod_string_utf16_from_iso8859(const char *src,size_t *numChars)
{
	char *dst,*sp,*dp;
	*numChars = strlen(src);
	dst = (char *)ipod_memory_alloc((*numChars)*2);
	sp = (char *)src;
	dp = dst;
	while (*sp) {
		*dp++ = *sp++;
		*dp++ = 0;
	}
	return dst;
}

char *ipod_string_iso8859_from_utf16(const char *src,size_t numChars)
{
	char *sp,*dp,*dst = (char *)ipod_memory_alloc(numChars+1);
	sp = (char *)src;
	dp = dst;
	while (numChars--) {
		*dp++ = *sp++;
		sp++;
	}
	*dp = 0;
	return dst;
}

char *ipod_string_utf8_from_iso8859(const char *src)
{
	size_t numChars;
	char *tmp1 = ipod_string_utf16_from_iso8859(src,&numChars);
	char *tmp2 = ipod_string_utf8_from_utf16(tmp1,numChars);
	ipod_memory_free(tmp1);
	return tmp2;
}

char *ipod_string_iso8859_from_utf8(const char *src)
{
	size_t numChars;
	char *tmp1 = ipod_string_utf16_from_utf8(src,&numChars);
	char *tmp2 = ipod_string_iso8859_from_utf16(tmp1,numChars);
	ipod_memory_free(tmp1);
	return tmp2;
}

int ipod_string_compare_utf16(const char *a, size_t numCharsA, const char *b, size_t numCharsB)
{
	short *aa = (unsigned short *)a,*bb = (unsigned short *)b;
	size_t minLen = numCharsA<numCharsB?numCharsA:numCharsB;
	while (minLen-- >0) {
		unsigned short aaa = *aa;
		unsigned short bbb = *bb;
		if (aaa!=bbb)
			return (long)aaa-(long)bbb;
	}
	return numCharsA-numCharsB; 
}

void ipod_string_report(void)
{
	ipod_error("ipod_string_report(): ipod_string allocs %lu frees %lu delta %ld\n",
		ipod_string_allocs,ipod_string_frees,
		ipod_string_allocs-ipod_string_frees);
}
