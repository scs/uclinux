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
#include <stdio.h>
#include <string.h>

#include "cfg.h"

int
loadCFG(char *path, cfg *c)
{
	FILE *f;
	char buffer[512];
	
	/* defaults */
	c->sound=SOUND_HI;
	c->control[0]=KEYBOARD;
	c->control[1]=KEYBOARD;
	c->fullscreen=0;
	
	f=fopen(path,"rt");
	if(!f)
		return 0;
	
	if(fscanf(f,"%511[^\n]\n",buffer)!=1) {
		fclose(f);
		return 0;
	}
	if(strcmp(buffer,"BEGIN")) {
		fclose(f);
		return 0;
	}
	if(fscanf(f,"SOUND=%i\nCONTROL_1=%i\nCONTROL_2=%i\nFULL_SCREEN=%i\n",
			&c->sound,&c->control[0],&c->control[1], &c->fullscreen)!=4) {
		fclose(f);
		return 0;
	}
	if(fscanf(f,"%511[^\n]\n",buffer)!=1) {
		fclose(f);
		return 0;
	}

	if(strcmp(buffer,"END")) {
		fclose(f);
		return 0;
	}
	
	fclose(f);

	return 1;
}

int
saveCFG(char *path, cfg *c)
{
	FILE *f;	
	
	f=fopen(path,"wt");
	if(!f)
		return 0;
	
	fprintf(f,"BEGIN\n");
	
	fprintf(f,"SOUND=%i\nCONTROL_1=%i\nCONTROL_2=%i\nFULL_SCREEN=%i\n",
			c->sound,c->control[0],c->control[1], c->fullscreen);
	
	fprintf(f,"END\n");

	fclose(f);

	return 1;
}

int
loadScore(char *path, score *hisc)
{
	FILE *f;
	int i,j;
	score swp;

	/* init to defaults */
	for(i=0;i<10;i++) {
		strcat(hisc[i].name,"nobody");
		hisc[i].stage=10-i;
		hisc[i].score=10000-(i*1000);
	}

	f=fopen(path,"rt");
	if(!f)
		return 0;

	for(i=0;i<10;i++)
		if(fscanf(f,"%8[^:]:%i:%i\n", hisc[i].name, &hisc[i].stage,
			&hisc[i].score)!=3) {
				fclose(f);
				return 0;
		}

	fclose(f);

	/* it's needed the score is ordered */
	for(i=0;i<9;i++)
		for(j=i;j<10;j++) {
			if(hisc[i].score<hisc[j].score) {
				swp=hisc[i];
				hisc[i]=hisc[j];
				hisc[j]=swp;
			} else
				if(hisc[i].score==hisc[j].score &&
					hisc[i].stage<hisc[j].stage) {
					swp=hisc[i];
					hisc[i]=hisc[j];
					hisc[j]=swp;
				}
		}

	return 1;
}

int
saveScore(char *path, score *hisc)
{
	FILE *f;
	int i;

	f=fopen(path,"wt");
	if(!f)
		return 0;

	for(i=0;i<10;i++)
		fprintf(f,"%s:%i:%i\n", hisc[i].name, hisc[i].stage,
			hisc[i].score);
	fclose(f);
	return 1;
}
