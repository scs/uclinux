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
#include"SDL_plus.h"
#include<string.h>

SDL_Surface *
loadBMP(char *file)
{
	SDL_Surface *a,*b;

	a=SDL_LoadBMP(file);
	if(!a)
		return NULL;
	b=SDL_DisplayFormat(a);
	if(!b)
		return NULL;

	SDL_FreeSurface(a);
	return b;
}

void
writeNumber(SDL_Surface *src, SDL_Surface *dst, int x, int y, int number, int padd)
{
	SDL_Rect a,b;
	char buffer[32],fmt[16];
	int i;

	sprintf(fmt,"%%.%ii",padd);
	sprintf(buffer,fmt,number);
	
	a.y=y;
	a.w=8;
	a.h=12;
	b.y=73;
	b.w=8;
	b.h=12;
	for(i=0;i<strlen(buffer);i++) {
		a.x=x+i*8;
		b.x=101+(buffer[i]-'0')*9;
		SDL_BlitSurface(src, &b, dst, &a);
	}
}

void 
drawPanel(SDL_Surface *src, SDL_Surface *dst, pDesc *player)
{
	SDL_Rect a,b;
	int i;
	
	a.x=0;
	a.y=0;
	
	b.x=2;
	b.y=83;
	b.h=34;
	b.w=95;
	SDL_BlitSurface(src, &b, dst, &a);

	a.x=SCREENW-b.w;
	b.x=2;
	b.y=47;	
	SDL_BlitSurface(src, &b, dst, &a);
	
	/* GAME OVER */
	if(!player[0].shield && !player[1].shield) {
		a.x=(SCREENW/2)-70;
		a.y=(SCREENH/2)-10;
		b.x=100;
		b.y=89;
		b.h=19;
		b.w=140;	
		SDL_BlitSurface(src, &b, dst, &a);
		return;
	}
	
	for(i=0;i<2;i++) {
		
		if(!player[i].shield)
			continue;

		switch(player[i].weapon) {
			case 0:
				b.x=47;
			break;
			case 1:
				b.x=53;
			break;
			case 2:
				b.x=59;
			break;
		}
		a.x=30;
		a.y=6;
		b.w=5;
		b.h=10;
		b.y=24;

		if(i) {
			a.x=SCREENW-35;
			writeNumber(src,dst,a.x-10,a.y-1,player[i].level+1,1);
			writeNumber(src,dst,a.x-15,a.y+14,player[i].score,6);
		} else {
			writeNumber(src,dst,a.x+b.w+2,a.y-1,player[i].level+1,1);
			writeNumber(src,dst,2,a.y+14,player[i].score,6);
		}

		SDL_BlitSurface(src, &b, dst, &a);

		b.y=62;
		b.w=(player[i].shield*38)/10;
		b.h=9;
		a.y=4;		
		if(i) {
			b.x=139;
			a.x=SCREENW-(54+38)+(38-b.w);
		} else {
			b.x=100;
			a.x=54;
		}
		SDL_BlitSurface(src, &b, dst, &a);
	}
}


/* x,y, w,h for each leter */
static const struct font_descr_struct {

	char key;
	SDL_Rect font_rect;
	
} font_descr[]= {
	{ 'a', { 288,0,12,17 } }, /* a */
	{ 'b', { 302,0,11,17 } }, /* b */
	{ 'c', { 314,0,11,17 } }, /* c */
	{ 'd', { 327,0,11,17 } }, /* d */
	{ 'e', { 340,0,11,17 } }, /* e */
	{ 'f', { 354,0,7,17 } }, /* f */
	{ 'g', { 362,0,11,17 } }, /* g */
	{ 'h', { 376,0,10,17 } }, /* h */
	{ 'i', { 389,0,6,17 } }, /* i */
	{ 'j', { 396,0,9,17 } }, /* j */
	{ 'k', { 408,0,11,17 } }, /* k */
	{ 'l', { 421,0,6,17 } }, /* l */
	{ 'm', { 430,0,14,17 } }, /* m */
	{ 'n', { 446,0,10,17 } }, /* n */
	{ 'o', { 458,0,11,17 } }, /* o */
	{ 'p', { 472,0,11,17 } }, /* p */
	{ 'q', { 484,0,11,17 } }, /* q */
	{ 'r', { 498,0,7,17 } }, /* r */
	{ 's', { 506,0,9,17 } }, /* s */
	{ 't', { 517,0,7,17 } }, /* t */
	{ 'u', { 527,0,10,17 } }, /* u */
	{ 'v', { 539,0,10,17 } }, /* v */
	{ 'w', { 550,0,14,17 } }, /* w */
	{ 'x', { 566,0,10,17 } }, /* x */
	{ 'y', { 579,0,10,17 } }, /* y */
	{ 'z', { 591,0,11,17 } }, /* z */
	{ '0', { 604,0,13,17 } }, /* 0 */
	{ '1', { 620,0,6,17 } }, /* 1 */
	{ '2', { 628,0,9,17 } }, /* 2 */
	{ '3', { 640,0,8,17 } }, /* 3 */
	{ '4', { 651,0,10,17 } }, /* 4 */
	{ '5', { 663,0,8,17 } }, /* 5 */
	{ '6', { 674,0,10,17 } }, /* 6 */
	{ '7', { 686,0,9,17 } }, /* 7 */
	{ '8', { 698,0,9,17 } }, /* 8 */
	{ '9', { 709,0,11,17 } }, /* 9 */
	{ '+', { 722,0,9,17 } }, /* HUD */
	{ '.', { 437,39,9,17 } }, /* . */
	{ 0, { 0,0,0,0 } }

};

/* ONLY supports lowcase letters */
void
writeCString(SDL_Surface *src, SDL_Surface *dst, int x, int y, char *str, int color)
{
  int i,j;
  SDL_Rect a,b;

  /* that's damn slow, but portable to different character sets */
  for(i=0,a.x=x,a.y=y;i<strlen(str);i++) {
  	for(j=0; font_descr[j].key && j!=-1; j++) {
		if(font_descr[j].key==str[i]) {
			b=font_descr[j].font_rect;
			if(color)
				b.y+=19;
			SDL_BlitSurface(src, &b, dst, &a);
			a.x+=b.w;
			j=-2;
		}
	}
	if(j>0)
		a.x+=12;

  }

  return;
}

/* ugly!!!! needs review */
char
SDLK2ascii(int sym)
{
	switch(sym) {
		default:
		break;
		case SDLK_a:
			return 'a';
		case SDLK_b:
			return 'b';
		case SDLK_c:
			return 'c';
		case SDLK_d:
			return 'd';
		case SDLK_e:
			return 'e';
		case SDLK_f:
			return 'f';
		case SDLK_g:
			return 'g';
		case SDLK_h:
			return 'h';
		case SDLK_i:
			return 'i';
		case SDLK_j:
			return 'j';
		case SDLK_k:
			return 'k';
		case SDLK_l:
			return 'l';
		case SDLK_m:
			return 'm';
		case SDLK_n:
			return 'n';
		case SDLK_o:
			return 'o';
		case SDLK_p:
			return 'p';
		case SDLK_q:
			return 'q';
		case SDLK_r:
			return 'r';
		case SDLK_s:
			return 's';
		case SDLK_t:
			return 't';
		case SDLK_u:
			return 'u';
		case SDLK_v:
			return 'v';
		case SDLK_w:
			return 'w';
		case SDLK_x:
			return 'x';
		case SDLK_y:
			return 'y';
		case SDLK_z:
			return 'z';
		case SDLK_0:
			return '0';
		case SDLK_1:
			return '1';
		case SDLK_2:
			return '2';
		case SDLK_3:
			return '3';
		case SDLK_4:
			return '4';
		case SDLK_5:
			return '5';
		case SDLK_6:
			return '6';
		case SDLK_7:
			return '7';
		case SDLK_8:
			return '8';
		case SDLK_9:
			return '9';
	}

	return ' ';
}

