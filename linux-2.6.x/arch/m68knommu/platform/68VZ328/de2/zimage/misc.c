
/*
 *  linux/arch/m68knommu/platform/MC68VZ328/de2/zimage/misc.c
 *
 *  Copyright (C) 2002 Georges Menie
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * gunzip wrapper based on :
 *
 * arch/sh/boot/compressed/misc.c
 * 
 * This is a collection of several routines from gzip-1.0.3 
 * adapted for Linux.
 *
 * malloc by Hannu Savolainen 1993 and Matthias Urlichs 1994
 *
 * Adapted for SH by Stuart Menefy, Aug 1999
 *
 * Modified to use standard LinuxSH BIOS by Greg Banks 7Jul2000
 */

/*
 * gzip declarations
 */

#define NULL 0

#define OF(args)  args
#define STATIC static

#define memzero(s, n)     memset ((s), 0, (n))

void outstring (const char *);
void exit (int);

typedef unsigned char uch;
typedef unsigned short ush;
typedef unsigned long ulg;

#define WSIZE 0x8000			/* Window size must be at least 32k, */
								/* and a power of two */

static uch window[WSIZE];		/* Sliding window buffer */

static ulg inptr = 0;			/* index of next byte to be processed in inbuf */
static ulg outcnt = 0;			/* bytes in output buffer */
static ulg bytes_out = 0;

/* Diagnostic functions */
#define Assert(cond,msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c,x)
#define Tracecv(c,x)

static void flush_window (void);
static void *malloc (int size);
static void free (void *where);
static void error (char *m);
static void gzip_mark (void **);
static void gzip_release (void **);

static const unsigned char *data_in;
static unsigned char *data_out;
static unsigned int data_in_len;

#define get_byte() ((inptr < data_in_len)?data_in[inptr++]:(error("ran out of input data\n"),0))
#define put_byte(c) *data_out++ = c

#include "../../../../../../lib/inflate.c"

#define HEAPSIZE (24*1024)
static unsigned char heap[HEAPSIZE];
static unsigned char *free_mem_ptr = heap;

static void *malloc (int size)
{
	void *p;

	if (size < 0)
		error ("Malloc error\n");
	if (free_mem_ptr == 0)
		error ("Memory error\n");

	free_mem_ptr = (unsigned char *) (((unsigned long) free_mem_ptr + 3) & ~3);	/* Align */

	p = free_mem_ptr;
	free_mem_ptr += size;

	if (free_mem_ptr >= &heap[HEAPSIZE])
		error ("\nOut of memory\n");

	return p;
}

static void free (void *where)
{								/* Don't care */
}

static void gzip_mark (void **ptr)
{
	*ptr = free_mem_ptr;
}

static void gzip_release (void **ptr)
{
	free_mem_ptr = *ptr;
}

/* ===========================================================================
 * Write the output window window[0..outcnt-1] and update crc and bytes_out.
 * (Used for the decompressed data only.)
 */
static void flush_window (void)
{
	ulg c = crc;				/* temporary variable */
	unsigned n;
	uch *in, ch;

	in = window;
	for (n = 0; n < outcnt; n++) {
		ch = *in++;
		put_byte (ch);
		c = crc_32_tab[((int) c ^ ch) & 0xff] ^ (c >> 8);
	}
	crc = c;
	bytes_out += outcnt;
	outcnt = 0;
	outstring (".");
}

static void error (char *x)
{
	outstring ("\r\n\r\n");
	outstring (x);
	outstring ("\r\n\r\n -- System halted\r\n");
	exit (1);
}

void memgunzip (unsigned char *dst, const unsigned char *src, unsigned int sz)
{
	data_out = dst;
	data_in = src;
	data_in_len = sz;
	makecrc ();
	gunzip ();
}
