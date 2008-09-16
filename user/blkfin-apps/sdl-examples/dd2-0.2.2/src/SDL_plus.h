/*

    Dodgin' Diamond 2, a shot'em up arcade
    Copyright (C) 2003,2004 Juan J. Martinez <jjm@usebox.net>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/
#ifndef __SDL_PLUS__
#define __SDL_PLUS__

#include "SDL.h"
#include "engine.h"

SDL_Surface *loadBMP(char *file);
void writeNumber(SDL_Surface *src, SDL_Surface *dst, int x, int y, int number, int padd);
void drawPanel(SDL_Surface *src, SDL_Surface *dst, pDesc *player);
void writeCString(SDL_Surface *src, SDL_Surface *dst, int x, int y, char *str, int color);
char SDLK2ascii(int sym);

#endif
