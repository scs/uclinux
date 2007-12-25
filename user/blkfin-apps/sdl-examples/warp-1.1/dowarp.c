/*-----------------------------------------------------------------------
	Warp-SDL 1.1

	Simple DirectMedia Layer demo
	Realtime picture 'gooing'

	dowarp.c: warp routines

	written by Emmanuel Marty <core@mirus.fr>
	1.0: November 1st, 1997
		initial version
	1.1: November 9th, 1997
		support for 8,15,16,24,32 bpp
		usage of GGI datatypes

	modified by Sam Lantinga <slouken@devolution.com>
	1.1.4: April 13th, 1998
		modified for SDL

	Released under GNU Public License
-----------------------------------------------------------------------*/

#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include "SDL.h"
#include "warp.h"

#ifndef M_PI
#define M_PI	3.14159265358979323846
#endif

void initSinTable (struct warp *w) {
	Sint32	*tptr, *tsinptr;
	double	i;

	tsinptr = tptr = w->sintable;

	for (i = 0; i < 1024; i++)
		*tptr++ = (int) (sin (i*M_PI/512) * 32767);

	for (i = 0; i < 256; i++)
		*tptr++ = *tsinptr++;
}

void initOffsTable (struct warp *w) {
	Sint32	width, height, len, y;
	Uint8	*source;
	void	**offptr;

	offptr = w->offstable;
	width  = w->src->w; height = w->src->h;
	source = (Uint8 *) w->src->pixels;
	len    = w->src->pitch;

	for (y = 0; y < height; y++) {
		*offptr++ = (void *) source;
		source += len;
	}
}
      
void initDistTable (struct warp *w) {
	Sint32	halfw, halfh, *distptr;
	double	x,y,m;

	halfw = w->src->w >> 1;
	halfh = w->src->h >> 1;

	distptr = w->disttable;

	m = sqrt ((double)(halfw*halfw + halfh*halfh));

	for (y = -halfh; y < halfh; y++)
		for (x= -halfw; x < halfw; x++)
			*distptr++ = ((int)
				( (sqrt (x*x+y*y) * 511.9999) / m)) << 1;
}

struct warp *initWarp (SDL_Surface *src) {
	struct warp	*w;

	if ( (w = (struct warp *) malloc (sizeof (struct warp))) ) {
		if ( (w->offstable = malloc (src->h * sizeof (char *))) ) {

			if ( (w->disttable = malloc (src->w *
                                                     src->h *
						  sizeof (int))) ) {
				w->src = src;
				initSinTable (w);
				initOffsTable (w);
				initDistTable (w);

				return (w);
			}
			free (w->offstable);
		}
		free (w);
	}
	return (NULL);
}

void disposeWarp (struct warp *w) {
	if (w) {
		free (w->disttable);
		free (w->offstable);
		free (w);
	}
}

void doWarp8bpp (struct warp *w, int xw, int yw, int cw) {
	Sint32 c,i, x,y, dx,dy, maxx, maxy;
	Sint32 width, height, skip, *ctable, *ctptr, *distptr;
	Sint32 *sintable, *disttable;
	Uint8  *destptr, **offstable;

	ctptr = ctable = &(w->ctable[0]);
	sintable = &(w->sintable[0]);
	offstable = (Uint8 **) w->offstable;
	distptr = disttable = w->disttable;
	width = w->src->w;
	height = w->src->h;
	destptr = (Uint8 *) w->framebuf;
	skip = w->dst->pitch-w->src->w;

	c = 0;

	for (x = 0; x < 512; x++) {
		i = (c >> 3) & 0x3FE;
		*ctptr++ = ((sintable[i] * yw) >> 15);
		*ctptr++ = ((sintable[i+256] * xw) >> 15);
		c += cw;
	}

	maxx = width - 1; maxy = height - 1;

	for (y = 0; y < height; y++) {
         for (x = 0; x < width; x++) {
		i = *distptr++;
		dx = ctable [i+1] + x;
		dy = ctable [i] + y;
                                
		if (dx < 0) dx = 0;
		else if (dx > maxx) dx = maxx;

		if (dy < 0) dy = 0;
		else if (dy > maxy) dy = maxy;
                                
                *destptr++ = * (offstable[dy] + dx);
        }
	destptr += skip;
       }
}

void doWarp16bpp (struct warp *w, int xw, int yw, int cw) {
        Sint32 c,i, x,y, dx,dy, maxx, maxy;
        Sint32 width, height, skip, *ctable, *ctptr, *distptr;
        Sint32 *sintable, *disttable;
        Uint16 *destptr, **offstable;

        ctptr = ctable = &(w->ctable[0]);
        sintable = &(w->sintable[0]);
        offstable = (Uint16 **) w->offstable;
        distptr = disttable = w->disttable;
        width = w->src->w;
        height = w->src->h;
        destptr = (Uint16 *) w->framebuf;
	skip = (w->dst->pitch/2)-w->src->w;

        c = 0;

        for (x = 0; x < 512; x++) {
                i = (c >> 3) & 0x3FE;
                *ctptr++ = ((sintable[i] * yw) >> 15);
                *ctptr++ = ((sintable[i+256] * xw) >> 15);
                c += cw;
        }

        maxx = width - 1; maxy = height - 1;

        for (y = 0; y < height; y++) {
         for (x = 0; x < width; x++) {
                i = *distptr++;
                dx = ctable [i+1] + x;
                dy = ctable [i] + y;

                if (dx < 0) dx = 0;
                else if (dx > maxx) dx = maxx;

                if (dy < 0) dy = 0;
                else if (dy > maxy) dy = maxy;

                *destptr++ = * (offstable[dy] + dx);
        }
	destptr += skip;
       }
}

void doWarp24bpp (struct warp *w, int xw, int yw, int cw) {
        Sint32 c,i, x,y, dx,dy, maxx, maxy;
        Sint32 width, height, skip, *ctable, *ctptr, *distptr;
        Sint32 *sintable, *disttable;
        Uint8 *destptr, **offstable, *pptr;
 
        ctptr = ctable = &(w->ctable[0]);
        sintable = &(w->sintable[0]);
        offstable = (Uint8 **) w->offstable;
        distptr = disttable = w->disttable;
        width = w->src->w;
        height = w->src->h;
        destptr = (Uint8 *) w->framebuf;
	skip = w->dst->pitch-w->src->w*3;

        c = 0;
 
        for (x = 0; x < 512; x++) {   
                i = (c >> 3) & 0x3FE;
                *ctptr++ = ((sintable[i] * yw) >> 15);
                *ctptr++ = ((sintable[i+256] * xw) >> 15);
                c += cw;
        }
    
        maxx = width - 1; maxy = height - 1;

        for (y = 0; y < height; y++) {
         for (x = 0; x < width; x++) {
                i = *distptr++;
                dx = ctable [i+1] + x;
                dy = ctable [i] + y;
                
                if (dx < 0) dx = 0;
                else if (dx > maxx) dx = maxx;

                if (dy < 0) dy = 0;
                else if (dy > maxy) dy = maxy;

		pptr = offstable[dy]+dx+dx+dx;
		*destptr++ = *pptr++;
		*destptr++ = *pptr++;
		*destptr++ = *pptr++;		
        }
	destptr += skip;
       }
}

void doWarp32bpp (struct warp *w, int xw, int yw, int cw) {
        Sint32 c,i, x,y, dx,dy, maxx, maxy;
        Sint32 width, height, skip, *ctable, *ctptr, *distptr;
        Sint32 *sintable, *disttable;
        Uint32 *destptr, **offstable;

        ctptr = ctable = &(w->ctable[0]);
        sintable = &(w->sintable[0]);
        offstable = (Uint32 **) w->offstable;
        distptr = disttable = w->disttable;
        width = w->src->w;
        height = w->src->h;
        destptr = (Uint32 *) w->framebuf;
	skip = w->dst->pitch/4-w->src->w;

        c = 0;

        for (x = 0; x < 512; x++) {
                i = (c >> 3) & 0x3FE;
                *ctptr++ = ((sintable[i] * yw) >> 15);
                *ctptr++ = ((sintable[i+256] * xw) >> 15);
                c += cw;
        }

        maxx = width - 1; maxy = height - 1;

        for (y = 0; y < height; y++) {
         for (x = 0; x < width; x++) {
                i = *distptr++;
                dx = ctable [i+1] + x;
                dy = ctable [i] + y;

                if (dx < 0) dx = 0;
                else if (dx > maxx) dx = maxx;

                if (dy < 0) dy = 0;
                else if (dy > maxy) dy = maxy;

                *destptr++ = * (offstable[dy] + dx);
        }
	destptr += skip;
       }
}

