/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

/* the following code was taken from a free software utility that I don't remember the name. */
/* sorry */

#ifdef HAVE_CONFIG_H
#include "mediastreamer-config.h"
#endif

#ifndef waveheader_h
#define waveheader_h

typedef struct uint16scheme
{
    unsigned char lo_byte;
    unsigned char hi_byte;
} uint16scheme_t;

typedef struct uint32scheme
{
    uint16_t lo_int;
    uint16_t hi_int;
} uint32scheme_t;


/* all integer in wav header must be read in least endian order */
static inline uint16_t _readuint16(uint16_t a)
{
    uint16_t res;
    uint16scheme_t *tmp1=(uint16scheme_t*)(void*)&a;

    ((uint16scheme_t *)(&res))->lo_byte=tmp1->hi_byte;
    ((uint16scheme_t *)(&res))->hi_byte=tmp1->lo_byte;
    return res;
}

static inline uint32_t _readuint32(uint32_t a)
{
    uint32_t res;
    uint32scheme_t *tmp1=(uint32scheme_t*)(void*)&a;

    ((uint32scheme_t *)((void*)&res))->lo_int=_readuint16(tmp1->hi_int);
    ((uint32scheme_t *)((void*)&res))->hi_int=_readuint16(tmp1->lo_int);
    return res;
}

#ifdef WORDS_BIGENDIAN
#define le_uint32(a) (_readuint32((a)))
#define le_uint16(a) (_readuint16((a)))
#define le_int16(a) ( (int16_t) _readuint16((uint16_t)((a))) )
#else
#define le_uint32(a) (a)
#define le_uint16(a) (a)
#define le_int16(a) (a)
#endif

typedef struct _riff_t {
	char riff[4] ;	/* "RIFF" (ASCII characters) */
	uint32_t  len ;	/* Length of package (binary, little endian) */
	char wave[4] ;	/* "WAVE" (ASCII characters) */
} riff_t;

/* The FORMAT chunk */

typedef struct _format_t {
	char  fmt[4] ;		/* "fmt_" (ASCII characters) */
	uint32_t   len ;	/* length of FORMAT chunk (always 0x10) */
	uint16_t  type;		/* codec type*/
	uint16_t channel ;	/* Channel numbers (0x01 = mono, 0x02 = stereo) */
	uint32_t   rate ;	/* Sample rate (binary, in Hz) */
	uint32_t   bps ;	/* Average Bytes Per Second */
	uint16_t blockalign ;	/*number of bytes per sample */
	uint16_t bitpspl ;	/* bits per sample */
} format_t;

/* The DATA chunk */

typedef struct _data_t {
	char data[4] ;	/* "data" (ASCII characters) */
	int  len ;	/* length of data */
} data_t;

typedef struct _wave_header_t
{
	riff_t riff_chunk;
	format_t format_chunk;
	data_t data_chunk;
} wave_header_t;


#define wave_header_get_rate(header)		le_uint32((header)->format_chunk.rate)
#define wave_header_get_channel(header)		le_uint16((header)->format_chunk.channel)

#endif
