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
#ifndef __ENGINE__
#define __ENGINE__

#ifndef DD2_DATA
#define DD2_DATA="./data"
#endif

#include "SDL.h"
#include "SDL_mixer.h"

/* player data */
typedef struct pdesc {
	SDL_Rect			*f;		/* description for frames */
	int				ftime;
	int				cftime;
	int				nf;		/* number of frames */
	int				cf;		/* current frame */

	int				x,y;
	int				incx,incy;
	
	int				companion;
	long				t;
	int				cinc;
	float				cx,cy;
	
	int				joy;
	int				keys[5];
	int				fire;
	int				firef;

	unsigned long 		score;
	char			stage;
	char			shield;
	char			weapon;	/* 0,1,2 */
	char			level;	/* 0,1,2, ... */
} pDesc;

/* fire data */
typedef struct fdesc {
	char			own;	/* 0: nobody, 1 player 2: enemy */
	pDesc			*player;
	int				type;
	int				ftime;
	int				cftime;	

	float			x,y;
	float			incx,incy;
	
	struct fdesc	*n;
} fDesc;

/* visual efect data */
typedef struct vdesc {
	int				type;
	int				ftime;
	int				cftime;	

	int				x,y;
	int				nf;
	int				cf;
	SDL_Rect		f[4];		/* description for frames */
	
	struct vdesc	*n;
} vDesc;

/*  object data */
typedef struct odesc {
	int				type;

	int				ftime,cf;
	float				x,y;
	
	struct odesc	*n;
} oDesc;

/* enemies */
typedef struct edesc {
	int				type;
	int				ftime;
	int				cftime;

	float			x,y;
	int				score;
	int				shield;

	int				init;
	int				var[10];
	
	void			(*ia)(struct edesc *e);
	void			(*draw)(struct edesc *e);
	int				(*hit)(struct edesc *e, int x, int y);

	struct edesc	*n;
} eDesc;

void engine_init();
void engine_release();
void engine_player(pDesc *p);

void engine_fire();
void engine_add_fire(int from, int type, int x, int y, float incx, float incy, pDesc *p);

void engine_vefx();
void engine_add_vefx(int type, int x, int y);

void engine_obj();
void engine_add_obj(int type, int x, int y);

void engine_enemy();
void engine_add_enemy(int type, int x, int y);

/* disc 1 */
void enemy_type1(eDesc *e);
void enemy_type1d(eDesc *e);
int enemy_type1h(eDesc *e, int x, int y);

/* ship 1 */
void enemy_type2(eDesc *e);
void enemy_type2d(eDesc *e);
int enemy_type2h(eDesc *e, int x, int y);

/* ship 2 */
void enemy_type3(eDesc *e);
#define enemy_type3d enemy_type2d
#define enemy_type3h enemy_type2h

/* provider 1 */
void enemy_type4(eDesc *e);
void enemy_type4d(eDesc *e);
int enemy_type4h(eDesc *e, int x, int y);

/* fast ship 1 */
void enemy_type5(eDesc *e);
void enemy_type5d(eDesc *e);
int enemy_type5h(eDesc *e, int x, int y);

/* boss 1 */
void enemy_type6(eDesc *e);
void enemy_type6d(eDesc *e);
int enemy_type6h(eDesc *e, int x, int y);

/* energy mine */
void enemy_type7(eDesc *e);
void enemy_type7d(eDesc *e);
#define enemy_type7h enemy_type5h

/* shootter */
void enemy_type8(eDesc *e);
void enemy_type8d(eDesc *e);
#define enemy_type8h enemy_type5h

/* energy mine carrier */
void enemy_type9(eDesc *e);
void enemy_type9d(eDesc *e);
int enemy_type9h(eDesc *e, int x, int y);

/* boss 2 */
void enemy_type10(eDesc *e);
void enemy_type10d(eDesc *e);
int enemy_type10h(eDesc *e, int x, int y);

/* ship 3 */
void enemy_type11(eDesc *e);
void enemy_type11d(eDesc *e);
#define enemy_type11h enemy_type2h

void circle_path(int x, int y, int r, int t, float *rx, float *ry);

#define SCREENW	320
#define SCREENH	200

/* efx */
#define VFX_SHIELD	1
#define VFX_EXPLO	2
#define VFX_EXPLOB	3
#define VFX_SHUP	4
#define VFX_POW		5
#define VFX_STAGE	6
#define VFX_MEXPLO	7

/* objects */
#define OBJ_WEAPON1		1
#define OBJ_WEAPON2		2
#define OBJ_WEAPON3		3
#define OBJ_SHIELD		4
#define OBJ_COMPANION	5
#define OBJ_LAST		5
#define OBJ_FIRST		1

#endif
