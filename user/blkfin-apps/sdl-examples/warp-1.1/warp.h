/*-----------------------------------------------------------------------
	Warp-SDL

	Simple DirectMedia Layer demo
	Realtime picture 'gooing'

	warp.h: definitions for warping

	written by Emmanuel Marty <emarty@mirus.fr>
	November 1st, 1997

	modified for SDL by Sam Lantinga <slouken@devolution.com>
	April 13, 1998

	Released under GNU Public License
-----------------------------------------------------------------------*/

#ifndef WARP_H

struct warp {
	SDL_Surface *src;
	SDL_Surface *dst;
	void *offstable;
	Sint32 *disttable;
	void *framebuf;
	Sint32 ctable [1024];
	Sint32 sintable [1024+256];
};

#endif
