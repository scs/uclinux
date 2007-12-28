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
#ifndef _CFG_H_
#define _CFG_H_

#define NO_SOUND	0
#define SOUND_LOW	1
#define SOUND_MED	2
#define SOUND_HI	3

#define KEYBOARD	0
#define JOYSTICK	1

typedef struct score {
	char name[9];
	int stage;
	int score;
} score;

typedef struct cfgStruct {
	int	sound;

	int control[2];

	int fullscreen;
} cfg;

int loadCFG(char *path, cfg *c);
int saveCFG(char *path, cfg *c);

int loadScore(char *path, score *hisc);
int saveScore(char *path, score *hisc);

#endif
