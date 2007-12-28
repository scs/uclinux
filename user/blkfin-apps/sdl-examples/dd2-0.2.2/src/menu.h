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
#ifndef _MENU_H_
#define _MENU_H_

void drawGetName(char *name, int place, int playern);
int getName(char *name, int place, int playern);

void drawHiscores(int max);
int hiscores();

void drawConfigure(int option);
int configure();

void drawMenu(int option);
int menu();

void drawCredits();
int credits();

#define NUM_EFX		8

#endif
