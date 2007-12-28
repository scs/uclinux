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

int main(int argc, char **argv)
{
        SDL_Surface *image;
        SDL_Event event;

	int quit = 0;
	char c;
	extern char *optarg;
	extern int optind;
	char *filename;

	filename = char_alloc();
	filename = argv[1];
	
	while (1) {
#ifdef HAVE_GETOPT_H
		int option_index = 0;

		static struct option long_options[] = {
			{"url", 1, 0, 'u'},
			{"fs", 0, 0, 'f'},
			{"longhelp", 0,0,'l'},
			{"version", 0,0,'v'},
			{"help", 0,0,'h'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "fu:lvh",
				long_options, &option_index);
#else
	c = getopt(argc, argv, "fu:lvh");
#endif
		if(c == -1)
			break;

		switch(c) {
			case 'u':
				getwithwget(optarg);
				death();
				break;
			case 'h':
				help();
				break;
			case 'v':
				version();
				break;
			case 'l':
				longhelp();
				break;
			case 'f':
				fs=1;
				break;
			default:
				none();
				break;
		}
	}

	if(argc < 2)
	{
		none();
	}
	
	image = loadimage(filename,1);

	if ((SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO)) < 0)
	{
		sdlerror();
		die();
	}
	
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
					quit = chkkey(event.key);
					break;
			}
		}
		SDL_Delay(100);
	}
	SDL_FreeSurface(image);
	SDL_Quit();
	return 0;
}
