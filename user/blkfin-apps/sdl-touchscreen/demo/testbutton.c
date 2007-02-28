
/* Simple program:  Draw a bitmap as background, draw another bitmap image as button.
 * Then click the button using mouse (or touch screen) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SDL.h"

SDL_Surface * LoadImage(char *file)
{
	SDL_Surface *temp, *image;

	/* Load the image */
	image = SDL_LoadBMP(file);
	if ( image == NULL ) {
		fprintf(stderr, "Couldn't load %s: %s", file, SDL_GetError());
		return NULL;
	}
	
	printf("Image %s loaded\n", file);
	
	/* Set transparent pixel as the pixel at (0,0) */
	if ( image->format->palette ) {
		SDL_SetColorKey(image, (SDL_SRCCOLORKEY|SDL_RLEACCEL), *(Uint8 *)image->pixels);
	}
       	
	/* Convert to video format */
	temp = SDL_DisplayFormat(image);
       	SDL_FreeSurface(image);
	if ( temp == NULL ) {
		fprintf(stderr, "Couldn't convert background: %s\n", SDL_GetError());
		return NULL;
	}
	return temp;
}

int draw_button(SDL_Surface *screen, SDL_Surface *button)
{
	SDL_Rect dst;

	dst.x = (screen->w - button->w) / 2;
	dst.y = (screen->h - button->h) / 2;
	dst.w = button->w;
	dst.h = button->h;
	SDL_BlitSurface(button, NULL, screen, &dst);
	SDL_UpdateRects(screen, 1, &dst);
}

int button_clicked(SDL_Surface *screen, SDL_Surface *button, int x, int y)
{
	int button_x = (screen->w - button->w) / 2;
	int button_y = (screen->h - button->h) / 2;

	if ( (x > button_x) && (x < (button_x + button->w) )
		&& (y > button_y) && (y < (button_y + button->h)))
	{
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	SDL_Surface *screen;
	SDL_Surface *background;
	SDL_Surface *button_on;
	SDL_Surface *button_off;
	SDL_Surface *button_now;
	Uint8  video_bpp;
	Uint32 videoflags;
	int i, k, done;
	SDL_Event event;
	Uint8 *buffer;
	Uint16 *buffer16;
        Uint16 color;
        Uint8  gradient;

	SDL_VideoInfo * info;
	SDL_PixelFormat *vfmt;
	
	/* Initialize SDL */
	if ( SDL_Init(SDL_INIT_VIDEO) < 0 ) {
		fprintf(stderr, "Couldn't initialize SDL: %s\n",SDL_GetError());
		exit(1);
	}
	atexit(SDL_Quit);

	video_bpp = 0;
	videoflags = SDL_SWSURFACE;

	/* Set 240x320 video mode */
	if ( (screen=SDL_SetVideoMode(240,320,video_bpp,videoflags)) == NULL ) {
		fprintf(stderr, "Couldn't set 240x320x%d video mode: %s\n",
						video_bpp, SDL_GetError());
		exit(2);
	}
	
	info = SDL_GetVideoInfo();
	vfmt = info->vfmt;
	printf("Video Mode: BitsPerPixel: %d, BytesPerPixel: %d," 
		"Rmask: 0x%X, Gmask: 0x%X, Bmask: 0x%X, Amask: 0x%x,"
	        "alpha: 0x%X, colorkey:0x%X\n",
		vfmt->BitsPerPixel, vfmt->BytesPerPixel, 
		vfmt->Rmask, vfmt->Gmask, vfmt->Bmask, vfmt->Amask, 
		vfmt->alpha, vfmt->colorkey);
	
	/* Load the background bitmap */
	background = LoadImage("linux.bmp");
	if ( background ) {
		SDL_Rect dst;
		dst.x = 0;
		dst.y = 0;
		dst.w = background->w;
		dst.h = background->h;
		SDL_BlitSurface(background, NULL, screen, &dst);
		SDL_UpdateRects(screen, 1, &dst);
	} else {
		fprintf(stderr, "Cannot load linux.bmp\n");
		exit(3);
	}

	/*
	vfmt = background->format;
	printf("Surface Info: BitsPerPixel: %d, BytesPerPixel: %d," 
		"Rmask: 0x%X, Gmask: 0x%X, Bmask: 0x%X, Amask: 0x%x,"
	        "alpha: 0x%X, colorkey:0x%X\n",
		vfmt->BitsPerPixel, vfmt->BytesPerPixel, 
		vfmt->Rmask, vfmt->Gmask, vfmt->Bmask, vfmt->Amask, 
		vfmt->alpha, vfmt->colorkey);
	*/

	/* Load the button */
	button_on = LoadImage("button_on.bmp");
	if ( ! button_on ) {
		fprintf(stderr, "Cannot load button_on.bmp\n");
		exit(3);
	}
	
	button_off = LoadImage("button_off.bmp");
	if ( ! button_off ) {
		fprintf(stderr, "Cannot load button_off.bmp\n");
		exit(3);
	}

	draw_button(screen, button_on);
	button_now = button_on;

	printf("now click the icon..., press any key to quit\n");

	/* Wait for a keystroke */
	done = 0;
	while ( !done ) {
		/* Check for events */
		while ( SDL_PollEvent(&event) ) {
			switch (event.type) {
				case SDL_MOUSEBUTTONDOWN: {
					if(button_clicked (screen, button_now, 
							event.button.x, event.button.y))
						if(button_now == button_on) {
							draw_button(screen, button_off);
							button_now = button_off;
						} else {
							draw_button(screen, button_on);
							button_now = button_on;
						}
					}
					break;
				case SDL_KEYDOWN:
					/* Any key press quits the app... */
					done = 1;
					break;
				case SDL_QUIT:
					done = 1;
					break;
				default:
					break;
			}
		}
	}
	SDL_FreeSurface(background);
	SDL_FreeSurface(button_on);
	SDL_FreeSurface(button_off);
	
	return(0);
}
