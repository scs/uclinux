/*-----------------------------------------------------------------------
	Warp-SDL 1.1

	Simple DirectMedia Layer demo
	Realtime picture 'gooing'

	main.c: main program

	written by Emmanuel Marty <core@mirus.fr>
	1.0: November 1st, 1997
		initial version
	1.1: November 9th, 1997
		support for any resolution
		support for 8,15,16,24,32 bpp
		color depth conversion
		usage of GGI datatypes
	1.1.3: November 12th, 1997
		moved color depth conversion code to color.c

	modified for SDL by Sam Lantinga <slouken@devolution.com>
	1.1.4: April 13th, 1998
		initial modification

	Released under GNU Public License
-----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include "SDL.h"
#include <math.h>
#include "warp.h"

#ifndef M_PI
#define M_PI	3.14159265358979323846
#endif

/*	dowarp.c */

extern	struct warp *initWarp(SDL_Surface *src);
extern	void	disposeWarp (struct warp *w);
extern	void	doWarp8bpp  (struct warp *w, int xw, int yw, int cw);
extern  void    doWarp16bpp (struct warp *w, int xw, int yw, int cw);
extern	void	doWarp24bpp (struct warp *w, int xw, int yw, int cw);
extern  void    doWarp32bpp (struct warp *w, int xw, int yw, int cw); 

/*	main program	*/

main (int argc, char **argv)
{
	SDL_Surface *screen;
	SDL_Surface *picture, *convert;
	struct warp *w;
	int    xw, yw, cw, tval;
	void (*doWarp)(struct warp *w, int xw, int yw, int cw);

	if ( SDL_Init(SDL_INIT_VIDEO) < 0 ) {
		fprintf(stderr, "Couldn't initialize SDL: %s\n",SDL_GetError());
		exit(2);
	}
	atexit(SDL_Quit);

	/* Load the picture that will be warped */
	if ( argv[1] == NULL ) {
		argv[1] = "leeloo.bmp";
	}
	picture = SDL_LoadBMP(argv[1]);
	if ( picture == NULL ) {
		fprintf(stderr, "Couldn't load %s: %s\n",
						argv[1], SDL_GetError());
		exit(1);
	}

	/* Since doWarp() is mucking with the pixels directly, it's almost
	   always faster to create the surface in system memory and let SDL 
	   perform a blit than to go over the video bus for each pixel.
	 */
	screen = SDL_SetVideoMode(picture->w, picture->h, 8,
			(SDL_ANYFORMAT|SDL_FULLSCREEN|SDL_DOUBLEBUF));
	if ( screen == NULL ) {
		fprintf(stderr, "Couldn't set video mode %dx%d: %s\n",
				picture->w, picture->h, SDL_GetError());
		SDL_FreeSurface(picture);
		exit(3);
	}
	SDL_WM_SetCaption("Warp Demo by Emmanuel Marty", "warp");

	/* Seed the palette, don't worry if it doesn't take */
	if ( picture->format->palette ) {
		SDL_SetColors(screen, picture->format->palette->colors, 0,
					picture->format->palette->ncolors);
	}

	/* Convert the picture to the display format for speed */
	convert = SDL_ConvertSurface(picture, screen->format, SDL_SWSURFACE);
	SDL_FreeSurface(picture);
	if ( convert == NULL ) {
		fprintf(stderr, "Couldn't convert image: %s\n", SDL_GetError());
		exit(3);
	}
	picture = convert;

	/* Ignore app focus and mouse motion events */
	SDL_EventState(SDL_ACTIVEEVENT, SDL_IGNORE);
	SDL_EventState(SDL_MOUSEMOTION, SDL_IGNORE);

	/* Warp the image until we get an event (button, key, quit) */
	w = initWarp(picture);
	if ( w == NULL ) {
		fprintf(stderr, "Couldn't initialize warp structure\n");
		SDL_FreeSurface(picture);
		exit(4);
	}
	w->dst = screen;
	switch (screen->format->BytesPerPixel) {
		case 1:
			doWarp = doWarp8bpp;
			break;
		case 2:
			doWarp = doWarp16bpp;
			break;
		case 3:
			doWarp = doWarp24bpp;
			break;
		case 4:
			doWarp = doWarp32bpp;
			break;
		default:
			fprintf(stderr, "Unknown BytesPerPixel: %d\n",
						screen->format->BytesPerPixel);
			exit(3);
	}
	tval = 0;
	while ( SDL_PollEvent(NULL) == 0 ) {

		/* Lock the video surface */
		if ( SDL_LockSurface(screen) < 0 ) {
			continue;
		}

		/* Calculate the next warp step */
		xw  = (int) (sin((tval+100)*M_PI/128) * 30);
		yw  = (int) (sin((tval)*M_PI/256) * -35);
		cw  = (int) (sin((tval-70)*M_PI/64) * 50);
		xw += (int) (sin((tval-10)*M_PI/512) * 40);
		yw += (int) (sin((tval+30)*M_PI/512) * 40);

		/* Get the current framebuffer pointer */
		w->framebuf = (Uint8 *)screen->pixels;

		/* WARP!  (assuming display bpp hasn't changed) */
		doWarp(w, xw, yw, cw);

		/* Unlock and update the screen */
		SDL_UnlockSurface(screen);
		SDL_Flip(screen);

		/* Update tval for the next round... */
		tval = (tval+1) & 511;
	}
	SDL_FreeSurface(picture);
	exit(0);
}
