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
#ifdef HAVE_WGET

void getwithwget(char *url)
{
	SDL_Surface *image;
        SDL_Event event;
	
	char *wget;
	char *newfile;
	int quit=0;

	wget = char_alloc();
	newfile = char_alloc();

	sprintf(newfile, "%s/%s", TMP_DIR, basename(url));
	
	sprintf(wget, "%s -O %s %s > /dev/null 2>&1", "wget", newfile, url);
	if(system(wget))
	{
		geterror("Can't get file %s", url);
		unlink(newfile);
		die();
	}


	image = loadimage(newfile,1);
	if(!image)
		sdlerror();
	
	setdisplay(image);
	
	while ( quit == 0)
	{
		while( SDL_PollEvent(&event))
		{
			switch(event.type)
			{
				case SDL_QUIT:
					quit = 1;
					break;
				case SDL_KEYDOWN:
					 quit = wgetchkkey(event.key, image);
					 break;
			}
		}
		SDL_Delay(100);
	}

        SDL_FreeSurface(image);
        SDL_Quit();
	unlink(newfile);
}

int wgetchkkey(SDL_KeyboardEvent key, SDL_Surface *image)
{
	switch(key.keysym.sym)
	{
		case SDLK_ESCAPE:
			return 1;
			break;
		case SDLK_f:
			fs=1;
			break;
		case SDLK_n:
			fs=0;
			break;
		default:
			break;
	}
	setdisplay(image);
		 
}

#endif
