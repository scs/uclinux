/* views - view images exclusive with SDM
* Copyright (C) cappa <cappa@referee.at>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "include/views.h"

void sdlerror(void)
{
	printf("%s\n", SDL_GetError());
}

void settitle(const char *format, ...)
{
	va_list list;
	char title[1024];

	va_start(list, format);
	vsprintf(title, format, list);
	va_end(list);
	SDL_WM_SetCaption(title, NULL);
}

void setdisplay(SDL_Surface *image)
{
	SDL_Surface *display;
	if(fs == 1)
	{
		display = SDL_SetVideoMode(image->w,image->h,16,SDL_HWSURFACE|SDL_FULLSCREEN);
	} else {
		display = SDL_SetVideoMode(image->w,image->h,16,SDL_HWSURFACE);
	}
	if(!display)
	{
		sdlerror();
		die();
	}
	SDL_BlitSurface(image, NULL, display, NULL);
	settitle("%s (%dx%d) - %s %s", current, image->w, image->h, PACKAGE, VERSION);
	SDL_Flip(display);
}

int chkkey(SDL_KeyboardEvent key)
{
	int val=0;
	SDL_Surface *image;

	image = loadimage(current,1);
	switch(key.keysym.sym)
	{
		case SDLK_ESCAPE:
			val = 1;
			break;
		case SDLK_f:
			fs=1;
			setdisplay(image);
			break;
		case SDLK_n:
			fs=0;
			setdisplay(image);
			break;
		case SDLK_PAGEDOWN:
			image = loadimage(nextfile(current), SDLK_PAGEDOWN);
			setdisplay(image);
			break;
		case SDLK_PAGEUP:
			image = loadimage(lastfile(current), SDLK_PAGEUP);
			setdisplay(image);
			break;
		default:
			break;
	}
	return val;
}

SDL_Surface *loadimage(char *filename, int direction)
{
	SDL_Surface *image;
	is_file(filename);

	while(!(image = IMG_Load(filename)))
	{
		if(!image)
		{
			sdlerror();
			switch(direction)
			{
				case SDLK_PAGEDOWN:
					filename = nextfile(filename);
					break;
				case SDLK_PAGEUP:
					filename = lastfile(filename);
					break;
				default:
					 filename = lastfile(filename);
					 break;
			}
		}
	}
	strcpy(current, filename);
	return image;
	
}
