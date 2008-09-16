/*Fun with sierpinski-like patterns*/
#include <stdlib.h>
#include <stdio.h>
#include "SDL.h"

#define MAX 200          /*this controls the duration*/

main(int argc, char *argv[])
{
int x,y,i;
float param=0;
long max=MAX;
Uint32   pixel;
Uint8   *bits, bpp;
SDL_Rect **modes;
/*initialisation part*/
	SDL_Surface *screen;
	if (SDL_Init (SDL_INIT_VIDEO) < 0)
		{
		fprintf(stderr, "no init possible : %s\n", SDL_GetError());
		exit(1);
		}
	/*clean up on exit*/
	atexit(SDL_Quit);
	/*initialize*/
	screen = SDL_SetVideoMode(400, 300, 16, SDL_SWSURFACE);
	if ( screen == NULL)
		{
		screen = SDL_SetVideoMode(10, 10, 16, SDL_SWSURFACE);
		if ( screen == NULL )
			{
			fprintf(stderr, "Couldn't set display mode: %s\n",
                                     SDL_GetError());
			SDL_Quit();
			return 1;
			}

		/* Get available fullscreen/hardware modes */
		modes = SDL_ListModes(NULL, SDL_FULLSCREEN|SDL_SWSURFACE);
		SDL_FreeSurface(screen);

		/* Check is there are any modes available */
		if (modes == (SDL_Rect **)0)
			{
			printf("No modes available! \n");
			SDL_Quit();
			return 1;
			}

		/* Check if or resolution is restricted */
		if (modes == (SDL_Rect **) - 1)
			{
			printf("All resolutions available. \n");
			SDL_Quit();
			return 1;
			}
		/* Print valid modes */
		printf("Available Modes \n");
		for (i = 0; modes[i]; ++i)
			printf("  %d x %d\n", modes[i]->w, modes[i]->h);

		screen = SDL_SetVideoMode(modes[i-1]->w, modes[i-1]->h, 16, SDL_SWSURFACE);
		if ( screen == NULL )
			{
			fprintf(stderr, "Couldn't set %i x %i: %s\n",
				modes[i-1]->w, modes[i-1]->h,SDL_GetError());
			return 1;
			}
		}

/*ignore mouse / focus events*/
SDL_EventState(SDL_ACTIVEEVENT, SDL_IGNORE);
SDL_EventState(SDL_MOUSEMOTION, SDL_IGNORE);
/*we can draw now*/
bpp = screen->format->BytesPerPixel;
x=y=1;
/*main loop*/
while (param<=max)
	{
	for (x=0; x<=screen->w; ++x) /*Those two loops are for the x,y coords*/
	for (y=0;y<=screen->h; ++y)
		{
		pixel=(x|y)*(param/200)+pixel/3;  /*Color of the current pixel
						modify it for great fun !*/
		bits = ((Uint8 *)screen->pixels)+y*screen->pitch+x*bpp;
		*((Uint16 *)(bits)) = (Uint16)pixel;
		}
	SDL_UpdateRect(screen, 0, 0, 0, 0);         /*updates the whole window*/
	if (param>=(max-1))                                /*restart param to1 if it is too big*/
		param=1;
	if (SDL_PollEvent(NULL) !=0)	/*stop the program if an event is input,
					exept the ones defined at the beginning*/
		break;
	++param;		/*incr. param*/
	}

}
