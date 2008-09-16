/****************************************************************************
 * RRDtool 1.2.10  Copyright by Tobi Oetiker, 1997-2005
 ****************************************************************************
 * rrd_gfx_tiny.c  tiny graphics replacement to produce uncompressed gifs
 *                 requiring no external libs and minimal size
 *                 Copyright (C) 2005 David McCullough <davidm@snapgear.com>
  **************************************************************************/

/* #define DEBUG */

#ifdef DEBUG
# define DPRINTF(a...)  fprintf(stderr, a);
#else
# define DPRINTF(a...)
#endif

#include "rrd_tool.h"
#include "rrd_gfx.h"

#ifdef ENABLE_GIF
#include "rrd_afm.h"
#include "unused.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/byteorder.h>

typedef struct sImage *Image;

typedef int Colour;

/* Some definition to allow us to produce BMP image files */

typedef struct {
	unsigned char red;
	unsigned char green;
	unsigned char blue;
} __attribute__((packed)) COLOUR;

#define MAX_COLOUR	128
static int maxColour;
static COLOUR colour_table[MAX_COLOUR];

static int
find_nearest_color(gfx_color_t c)
{
	int r = (c >> 24) & 0xff;
	int g = (c >> 16) & 0xff;
	int b = (c >>  8) & 0xff;
	int a = (c >>  0) & 0xff;
	int i, j, m;
	unsigned int n;

	/*
	 * find an exact match
	 */
	for (i = 0; i < maxColour; i++) {
		if (colour_table[i].red == r &&
				colour_table[i].green == g &&
				colour_table[i].blue == b)
			return i;
	}
	/*
	 * add this colour
	 */
	if (maxColour < MAX_COLOUR) {
		i = maxColour++;
		colour_table[i].red = r;
		colour_table[i].green = g;
		colour_table[i].blue = b;
		return i;
	}

	/*
	 * find the closest match
	 */
	j = 0;
	n = 0xffffffff;
	for (i = 0; i < maxColour; i++) {
		m = (r - colour_table[i].red + 1) * (g - colour_table[i].green + 1) *
				(b - colour_table[i].blue + 1);
		if (m < 0)
			m = -m;
		if (m < n) {
			j = i;
			n = m;
		}
	}
	return j;
}

struct sImage {
	unsigned char	*data;
	unsigned short	 w;
	unsigned short	 h;
	int		 wh;
};

struct gifhdr {
	unsigned short width;
	unsigned short height;
	unsigned char flags;
	unsigned char background;
	unsigned char zero;
} __attribute__ ((packed));

struct imghdr {
	char		tag;
	unsigned short left;
	unsigned short top;
	unsigned short width;
	unsigned short height;
	unsigned char flags;
} __attribute__ ((packed));

static Image img;

static unsigned char font_8x8[] = {
/* 00 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ^@ */
/* 01 */  0x7e, 0x81, 0xa5, 0x81, 0xbd, 0x99, 0x81, 0x7e, /* ^A */
/* 02 */  0x7e, 0xff, 0xbd, 0xff, 0xc3, 0xe7, 0xff, 0x7e, /* ^B */
/* 03 */  0x6c, 0xfe, 0xfe, 0xfe, 0x7c, 0x38, 0x10, 0x00, /* ^C */
/* 04 */  0x10, 0x38, 0x7c, 0xfe, 0x7c, 0x38, 0x10, 0x00, /* ^D */
/* 05 */  0x00, 0x18, 0x3c, 0xe7, 0xe7, 0x3c, 0x18, 0x00, /* ^E */
/* 06 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 07 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 08 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 09 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0A */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0B */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0C */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0D */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0E */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 0F */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 10 */  0x00, 0x60, 0x78, 0x7e, 0x7e, 0x78, 0x60, 0x00, /* |> */
/* 11 */  0x00, 0x06, 0x1e, 0x7e, 0x7e, 0x1e, 0x06, 0x00, /* <| */
/* 12 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 13 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 14 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 15 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 16 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 17 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 18 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 19 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 1A */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 1B */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 1C */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 1D */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* 1E */  0x00, 0x18, 0x18, 0x3c, 0x3c, 0x7e, 0x7e, 0x00, /* /\ */
/* 1F */  0x00, 0x7e, 0x7e, 0x3c, 0x3c, 0x18, 0x18, 0x00, /* \/ */
/* 20 */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /*	 */
/* 21 */  0x18, 0x3c, 0x3c, 0x18, 0x18, 0x00, 0x18, 0x00, /* ! */
/* 22 */  0x6C, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, /* " */
/* 23 */  0x36, 0x36, 0x7F, 0x36, 0x7F, 0x36, 0x36, 0x00, /* # */
/* 24 */  0x0C, 0x3F, 0x68, 0x3E, 0x0B, 0x7E, 0x18, 0x00, /* $ */
/* 25 */  0x60, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x06, 0x00, /* % */
/* 26 */  0x38, 0x6C, 0x6C, 0x38, 0x6D, 0x66, 0x3B, 0x00, /* & */
/* 27 */  0x18, 0x18, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, /* ' */
/* 28 */  0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00, /* ( */
/* 29 */  0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00, /* ) */
/* 2A */  0x00, 0x18, 0x7E, 0x3C, 0x7E, 0x18, 0x00, 0x00, /* * */
/* 2B */  0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00, /* + */
/* 2C */  0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30, /* , */
/* 2D */  0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00, /* - */
/* 2E */  0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00, /* . */
/* 2F */  0x00, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00, 0x00, /* / */
/* 30 */  0x3C, 0x66, 0x6E, 0x7E, 0x76, 0x66, 0x3C, 0x00, /* 0 */
/* 31 */  0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, /* 1 */
/* 32 */  0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x7E, 0x00, /* 2 */
/* 33 */  0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00, /* 3 */
/* 34 */  0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x00, /* 4 */
/* 35 */  0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00, /* 5 */
/* 36 */  0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00, /* 6 */
/* 37 */  0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00, /* 7 */
/* 38 */  0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00, /* 8 */
/* 39 */  0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00, /* 9 */
/* 3A */  0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, /* : */
/* 3B */  0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, /* ; */
/* 3C */  0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00, /* < */
/* 3D */  0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00, /* = */ 
/* 3E */  0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00, /* > */
/* 3F */  0x3C, 0x66, 0x0C, 0x18, 0x18, 0x00, 0x18, 0x00, /* ? */
/* 40 */  0x3C, 0x66, 0x6E, 0x6A, 0x6E, 0x60, 0x3C, 0x00, /* @ */
/* 41 */  0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00, /* A */
/* 42 */  0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00, /* B */
/* 43 */  0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00, /* C */
/* 44 */  0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00, /* D */
/* 45 */  0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00, /* E */
/* 46 */  0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00, /* F */
/* 47 */  0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00, /* G */
/* 48 */  0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00, /* H */
/* 49 */  0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00, /* I */
/* 4A */  0x3E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00, /* J */
/* 4B */  0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00, /* K */
/* 4C */  0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00, /* L */
/* 4D */  0x63, 0x77, 0x7F, 0x6B, 0x6B, 0x63, 0x63, 0x00, /* M */
/* 4E */  0x66, 0x66, 0x76, 0x7E, 0x6E, 0x66, 0x66, 0x00, /* N */
/* 4F */  0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, /* O */
/* 50 */  0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00, /* P */
/* 51 */  0x3C, 0x66, 0x66, 0x66, 0x6A, 0x6C, 0x36, 0x00, /* Q */
/* 52 */  0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x00, /* R */
/* 53 */  0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00, /* S */
/* 54 */  0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, /* T */
/* 55 */  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00, /* U */
/* 56 */  0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, /* V */
/* 57 */  0x63, 0x63, 0x6B, 0x6B, 0x7F, 0x77, 0x63, 0x00, /* W */
/* 58 */  0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00, /* X */
/* 59 */  0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00, /* Y */
/* 5A */  0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00, /* Z */
/* 5B */  0x7C, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7C, 0x00, /* [ */
/* 5C */  0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00, /* \ */
/* 5D */  0x3E, 0x06, 0x06, 0x06, 0x06, 0x06, 0x3E, 0x00, /* ] */
/* 5E */  0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ^ */
/* 5F */  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, /* _ */
/* 60 */  0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ` */
/* 61 */  0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00, /* a */
/* 62 */  0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00, /* b */
/* 63 */  0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x00, /* c */
/* 64 */  0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00, /* d */
/* 65 */  0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00, /* e */
/* 66 */  0x1C, 0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x00, /* f */
/* 67 */  0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C, /* g */
/* 68 */  0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00, /* h */
/* 69 */  0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00, /* i */
/* 6A */  0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x70, /* j */
/* 6B */  0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00, /* k */
/* 6C */  0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00, /* l */
/* 6D */  0x00, 0x00, 0x36, 0x7F, 0x6B, 0x6B, 0x63, 0x00, /* m */
/* 6E */  0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00, /* n */
/* 6F */  0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00, /* o */
/* 70 */  0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, /* p */
/* 71 */  0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x07, /* q */
/* 72 */  0x00, 0x00, 0x6C, 0x76, 0x60, 0x60, 0x60, 0x00, /* r */
/* 73 */  0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00, /* s */
/* 74 */  0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x1C, 0x00, /* t */
/* 75 */  0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00, /* u */
/* 76 */  0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00, /* v */
/* 77 */  0x00, 0x00, 0x63, 0x6B, 0x6B, 0x7F, 0x36, 0x00, /* w */
/* 78 */  0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00, /* x */
/* 79 */  0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C, /* y */
/* 7A */  0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00, /* z */
/* 7B */  0x0C, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0C, 0x00, /* { */
/* 7C */  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, /* | */
/* 7D */  0x30, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x30, 0x00, /* } */
/* 7E */  0x31, 0x6B, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, /* ~ */
/* 7F */  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  /*  */
};

static void
initColours()
{
	maxColour = 1; /* index 0 is black */
	memset(colour_table, 0, sizeof(colour_table));
}

static Image newImage(int w, int h) {
	Image res;

	res = malloc(sizeof(struct sImage));
	if (res == NULL)
		return NULL;
	bzero(res, sizeof(struct sImage));
	res->wh = (res->w = w)*(res->h = h);
	res->data = malloc(res->wh);
	if (res->data == NULL) {
		free(res);
		return NULL;
	}
	bzero(res->data, res->wh);
	return res;
}


static void freeImage(Image i) {
	free(i->data);
	free(i);
}


/* Write the image out as a special non-compressed gif file.
 * This code is a bit ugly, but then so are the gif internals.  We limit
 * ourselves to 127 colours to save bit bashing the "compressed" output.
 */
static void saveImage(Image i, FILE *f) {
	struct gifhdr h;
	struct imghdr g;
	int j, k, p=0;

	//fprintf(f, "Content-type: image/gif\n\n");
	fprintf(f, "GIF87a");

	bzero(&h, sizeof(struct gifhdr));
	bzero(&g, sizeof(struct imghdr));
	g.tag = ',';
	g.width = h.width = __cpu_to_le16(i->w);
	g.height = h.height = __cpu_to_le16(i->h);
	h.flags = 0xe6;
	fwrite(&h, sizeof(struct gifhdr), 1, f);

	for (j=0; j<MAX_COLOUR; j++)
		fwrite(colour_table+j, 3, 1, f);

	fwrite(&g, sizeof(struct imghdr),1 , f);
	fputc(0x07, f);
	for (j=i->wh; j>0; j-=k) {
		k = (j>125)?125:j;
		fputc(k+1, f);
		fputc(0x80, f);
		fwrite(i->data+p, k, 1, f);
		p += k;
	}
	fputc(0x1, f);
	fputc(0x81, f);
	fputc(0, f);
	fputc(';', f);
}


/* Graphics primitives */
static inline void setpixel(Image i, int x, int y, Colour c) {
	if (x >= 0 && x < i->w && y >= 0 && y < i->h)
		i->data[x + y * i->w] = c;
}

static void fillbox(Image img, int x1, int y1, int x2, int y2, Colour c) {
	int i, j;
	int ix = 1, iy = 1;

	if (x2 < x1)
		ix = -1;
	if (y2 < y1)
		iy = -1;
	for (j = y1; ; j += iy) {
		for (i = x1; ; i += ix) {
			setpixel(img, i, j, c);
			if (i == x2)
				break;
		}
		if (j == y2)
			break;
	}
}

void
drawline(Image img, int x1, int y1, int x2, int y2, Colour c, int don, int dof)
{
	int i,dx,dy,sdx,sdy,dxabs,dyabs,x,y,px,py;
	int dasher;

	dx=x2-x1;      /* the horizontal distance of the line */
	dy=y2-y1;      /* the vertical distance of the line */
	dxabs=abs(dx);
	dyabs=abs(dy);
	sdx=dx < 0 ? -1 : 1;
	sdy=dy < 0 ? -1 : 1;
	x=dyabs>>1;
	y=dxabs>>1;
	px=x1;
	py=y1;

	setpixel(img, px, py, c);
	dasher = 1;

	if (dxabs>=dyabs) /* the line is more horizontal than vertical */
	{
		for(i=0;i<dxabs;i++)
		{
			y+=dyabs;
			if (y>=dxabs)
			{
				y-=dxabs;
				py+=sdy;
			}
			px+=sdx;
			if (!don || dasher++ < don)
				setpixel(img, px, py, c);
			else if (dasher > don + dof)
				dasher = 0;
		}
	}
	else /* the line is more vertical than horizontal */
	{
		for(i=0;i<dyabs;i++)
		{
			x+=dxabs;
			if (x>=dyabs)
			{
				x-=dyabs;
				px+=sdx;
			}
			py+=sdy;
			if (!don || dasher++ < don)
				setpixel(img, px, py, c);
			else if (dasher > don + dof)
				dasher = 0;
		}
	}
}


gfx_canvas_t *
gfx_new_canvas(void)
 {
    gfx_canvas_t *canvas = calloc(1, sizeof(gfx_canvas_t));
    canvas->firstnode = NULL;
    canvas->lastnode = NULL;
    canvas->imgformat = IF_PNG;
    canvas->interlaced = 0;
    canvas->zoom = 1.0;
    canvas->font_aa_threshold = -1.0;
    canvas->aa_type = AA_NORMAL;
    return canvas;
}

int
gfx_destroy(gfx_canvas_t *canvas)
{  
  gfx_node_t *next,*node = canvas->firstnode;
  while(node){
    next = node->next;
    free(node->path);
    free(node->text);
    free(node->filename);
    free(node);
    node = next;
  }
  free(canvas);
  return 0;
}

static gfx_node_t *
gfx_new_node(gfx_canvas_t *canvas, enum gfx_en type)
{
  gfx_node_t *node = calloc(1, sizeof(gfx_node_t));
  if (node == NULL) return NULL;
  node->type = type;
  node->color = 0x0;     /* color of element  0xRRGGBBAA  alpha 0xff is solid*/
  node->size = 0.0;       /* font size, line width */
  node->path = NULL;     /* path */
  node->points = 0;
  node->points_max = 0;
  node->closed_path = 0;
  node->filename = NULL; /* font or image filename */
  node->text = NULL;
  node->x = 0.0;
  node->y = 0.0;         /* position */
  node->angle = 0;  
  node->halign = GFX_H_NULL; /* text alignement */
  node->valign = GFX_V_NULL; /* text alignement */
  node->tabwidth = 0.0; 
  node->next = NULL; 
  if (canvas->lastnode != NULL){
      canvas->lastnode->next = node;
  }
  if (canvas->firstnode == NULL){
      canvas->firstnode = node;
  }  
  canvas->lastnode = node;
  return node;
}

double
gfx_get_text_width(
	gfx_canvas_t *canvas,
    double start,
	char *font,
	double size,
    double tabwidth,
	char *text,
	int rotation)
{
	char *tp;
	int n = 0;

	switch ((int) rotation) {
	case 270: return 8;
	}

	for (tp = text; *tp; tp++) {
		switch (*tp) {
		case '\t':
			n += 8 * (int) tabwidth;
			break;
		default:
			n += 8;
			break;
		}
	}
	return n;
}

double
gfx_get_text_height(
	gfx_canvas_t *canvas,
    double start,
	char *font,
	double size,
    double tabwidth,
	char *text,
	int rotation)
{
	char *tp;
	int n = 0;

	switch ((int) rotation) {
	case 270: break;
	default: return 8;
	}

	for (tp = text; *tp; tp++) {
		switch (*tp) {
		case '\t':
			n += 8 * (int) tabwidth;
			break;
		default:
			n += 8;
			break;
		}
	}
	return n;
}

gfx_node_t *
gfx_new_text(
	gfx_canvas_t *canvas,
	double x,
	double y,
	gfx_color_t color,
	char *font,
	double size,
	double tabwidth,
	double angle,
	enum gfx_h_align_en h_align,
	enum gfx_v_align_en v_align,
	char* text)
{
   gfx_node_t *node = gfx_new_node(canvas, GFX_TEXT);
   
   node->text = strdup(text);
   node->size = size;
   node->filename = strdup(font);
   node->x = x;
   node->y = y;
   node->angle = angle;   
   node->color = color;
   node->tabwidth = tabwidth;
   node->halign = h_align;
   node->valign = v_align;
   return node;
}

gfx_node_t *
gfx_new_line(
	gfx_canvas_t *canvas,
	double X0, double Y0, 
	double X1, double Y1,
 	double width, gfx_color_t color)
{
  return gfx_new_dashed_line(canvas, X0, Y0, X1, Y1, width, color, 0, 0);
}

gfx_node_t *
gfx_new_dashed_line(
	gfx_canvas_t *canvas,
	double X0, double Y0,
	double X1, double Y1,
	double width, gfx_color_t color,
	double dash_on, double dash_off)
{
  ArtVpath *vec;
  gfx_node_t *node = gfx_new_node(canvas, GFX_LINE);
  if (node == NULL) return NULL;

  vec = calloc(3, sizeof(ArtVpath));
  if (vec == NULL) return NULL;

  vec[0].code = ART_MOVETO_OPEN;
  vec[0].x = X0;
  vec[0].y = Y0;
  vec[1].code = ART_LINETO;
  vec[1].x = X1;
  vec[1].y = Y1;
  vec[2].code = ART_END;
  vec[2].x = 0;
  vec[2].y = 0;
  
  node->points = 3;
  node->points_max = 3;
  node->color = color;
  node->size  = width;
  node->dash_on = dash_on;
  node->dash_off = dash_off;
  node->path  = vec;
  return node;
}

gfx_node_t *
gfx_new_area(
	gfx_canvas_t *canvas, 
	double X0, double Y0,
	double X1, double Y1,
	double X2, double Y2,
	gfx_color_t color)
{
  ArtVpath *vec;
  gfx_node_t *node = gfx_new_node(canvas, GFX_AREA);
  if (node == NULL) return NULL;

  vec = calloc(5, sizeof(ArtVpath));
  if (vec == NULL) return NULL;

  vec[0].code = ART_MOVETO;
  vec[0].x = X0;
  vec[0].y = Y0;
  vec[1].code = ART_LINETO;
  vec[1].x = X1;
  vec[1].y = Y1;
  vec[2].code = ART_LINETO;
  vec[2].x = X2;
  vec[2].y = Y2;
  vec[3].code = ART_LINETO;
  vec[3].x = X0;
  vec[3].y = Y0;
  vec[4].code = ART_END;
  vec[4].x = 0;
  vec[4].y = 0;
  
  node->points = 5;
  node->points_max = 5;
  node->color = color;
  node->path  = vec;

  return node;
}

/* add a point to a line or to an area */
int
gfx_add_point(gfx_node_t *node, double x, double y)
{
  if (node == NULL) return 1;

  if (node->type == GFX_AREA) {
    double X0 = node->path[0].x;
    double Y0 = node->path[0].y;
	ArtVpath *vec = art_new(ArtVpath, node->points_max + 1);
    node->points -= 2;
	memcpy(vec, node->path, sizeof(ArtVpath) * node->points_max);
	art_free(node->path);
	node->path = vec;
	node->points_max++;
	node->path[node->points].code = ART_LINETO;
	node->path[node->points].x = x;
	node->path[node->points++].y = y;
	node->path[node->points].code = ART_LINETO;
	node->path[node->points].x = X0;
	node->path[node->points++].y = Y0;
	node->path[node->points].code = ART_END;
	node->path[node->points].x = 0;
	node->path[node->points++].y = 0;
  } else if (node->type == GFX_LINE) {
	ArtVpath *vec = art_new(ArtVpath, node->points_max + 1);
    node->points -= 1;
	memcpy(vec, node->path, sizeof(ArtVpath) * node->points_max);
	art_free(node->path);
	node->path = vec;
	node->points_max++;
	node->path[node->points].code = ART_LINETO;
	node->path[node->points].x = x;
	node->path[node->points++].y = y;
	node->path[node->points].code = ART_END;
	node->path[node->points].x = 0;
	node->path[node->points++].y = 0;
  } else {
    /* can only add point to areas and lines */
    return 1;
  }
  return 0;
}

void
gfx_close_path(gfx_node_t *node)
{
	node->closed_path = 1;
    if (node->path[0].code == ART_MOVETO_OPEN)
		node->path[0].code = ART_MOVETO;
}

int
pointInArea(int points, ArtVpath *point, double x, double y)
{
  int i, j, c = 0;
  for (i = 0, j = points-1; i < points; j = i++) {
	if ((((point[i].y <= y) && (y < point[j].y)) ||
		 ((point[j].y <= y) && (y < point[i].y))) &&
		(x < (point[j].x - point[i].x) * (y - point[i].y) /
			(point[j].y - point[i].y) + point[i].x))
	  c = !c;
  }
  return c;
}

static void
drawtext(Image img, char *s, int x, int y, Colour c)
{
	int i, j;
	unsigned char *fp;

	while (*s) {
		fp = &font_8x8[(*s & 0x7f) * 8];
		for (i = 0; i < 8; i++) {
			for (j = 0; j < 8; j++) {
				if (*fp & (1 << j))
					setpixel(img, x + (7 - j), y + i, c);
			}
			fp++;
		}
		s++;
		x += 8;
	}
}

static void
drawtext_270(Image img, char *s, int x, int y, Colour c)
{
	int i, j;
	unsigned char *fp;

	while (*s) {
		fp = &font_8x8[(*s & 0x7f) * 8];
		for (i = 0; i < 8; i++) {
			for (j = 0; j < 8; j++) {
				if (*fp & (1 << j))
					setpixel(img, x + (7 - i), y + (7 - j), c);
			}
			fp++;
		}
		s++;
		y += 8;
	}
}

int
gfx_render(
	gfx_canvas_t *canvas,
	art_u32 width,
	art_u32 height,
	gfx_color_t background,
	FILE *fp)
{
    gfx_node_t *node = canvas->firstnode;    
    unsigned long pys_width = width * canvas->zoom;
    unsigned long pys_height = height * canvas->zoom;
	int i, j;
    
	img = newImage(width, height);

	initColours();

    while (node) {
        switch (node->type) {
        case GFX_AREA: {
			int minx = width, miny = height, maxx = 0, maxy = 0;
			for (i = 0; i < node->points - 1; i++) {
				if ((int)node->path[i].x < minx)
					minx = (int)node->path[i].x;
				if ((int)node->path[i].y < miny)
					miny = (int)node->path[i].y;
				if ((int)node->path[i].x > maxx)
					maxx = (int)node->path[i].x;
				if ((int)node->path[i].y > maxy)
					maxy = (int)node->path[i].y;
			}
			// very slow area fill
			for (i = minx; i < maxx; i++)
				for (j = miny; j < maxy; j++)
					if (pointInArea(node->points -1, node->path,
								(double) i, (double) j))
						setpixel(img, i, j, find_nearest_color(node->color));
			} break;
        case GFX_LINE:
		   for (i = 0; i < node->points; i++) {
			 ArtVpath *vec = node->path + i;
			 switch (vec->code) {
			   case ART_MOVETO_OPEN: /* fall-through */
			   case ART_MOVETO:
				 break;
			   case ART_LINETO:
				 if (i > 0) {
					 drawline(img, 
							 (int)vec[-1].x, (int)vec[-1].y,
							 (int)vec[0].x,    (int)vec[0].y,
							 find_nearest_color(node->color),
							 (int)node->dash_on, (int) node->dash_off);
				 }
				 break;
			   case ART_CURVETO:
				 fprintf(stderr, "cannot handle CURVETO"); /* unsupported */
				 break;
			   case ART_END:
				 break;
			 }
		   }
		   break;
        case GFX_TEXT: {
			int x = (int)node->x, y = (int)node->y;
			int w = gfx_get_text_width(img, 0.0, node->filename,
					node->size, node->tabwidth, node->text, node->angle);
			int h = gfx_get_text_height(img, 0.0, node->filename,
					node->size, node->tabwidth, node->text, node->angle);

			switch (node->halign) {
			case GFX_H_RIGHT:  x -= w; break;
			case GFX_H_CENTER: x -= w/2; break;
			case GFX_H_LEFT:   break;
			case GFX_H_NULL:   break;
			}
			switch(node->valign){
			case GFX_V_TOP:    break;
			case GFX_V_CENTER: y -= h/2; break;
			case GFX_V_BOTTOM: y -= h; break;
			case GFX_V_NULL:   break;          
			}
			switch ((int) node->angle) {
			case 270:
			  drawtext_270(img,node->text,x,y,find_nearest_color(node->color));
			  break;
			default:
			  drawtext(img, node->text, x, y, find_nearest_color(node->color));
			  break;
			}
			} break;
        }
        node = node->next;
    }  

	saveImage(img, fp);
	freeImage(img);
	img = NULL;
    return 0;    
}

#endif /* ENABLE_GIF */
