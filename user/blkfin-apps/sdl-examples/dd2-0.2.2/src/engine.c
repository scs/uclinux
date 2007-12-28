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
#define _ENGINE_CORE_
#include"main.h"
#include"engine.h"
#include"SDL_plus.h"
#include"SDL_mixer.h"

#include<stdlib.h>
#include<string.h>
#include<math.h>

extern SDL_Surface *screen, *gfx;

extern Mix_Chunk *efx[2];
extern Mix_Music *bgm, *bgm_boss;
extern int sound;

int firstInit=0;
bool boss=false;

pDesc player[2];

fDesc fire[256];
fDesc *ffree=fire, *fused=NULL;

vDesc vefx[256];
vDesc *vfree=vefx, *vused=NULL;

oDesc objects[16];
oDesc *ofree=objects, *oused=NULL;

eDesc enemy[64];
eDesc *efree=enemy, *eused=NULL;

long int actCnt=0, actIdx=0;

struct actionStruct {
	long int	a;
	int			type;
	int			x,y;
} *act=NULL;


void
engine_init()
{
	int i,j;
	FILE *fd;
	char comm[32];
	char buffer[512];

	/* that should be init once */
	if(!firstInit) {
		player[0].f=(SDL_Rect *)malloc(sizeof(SDL_Rect)*2);
		if(!player[0].f) {
			fprintf(stderr,"ENGINE_ERROR: memory\n");
			exit(-1);
		}
		player[1].f=(SDL_Rect *)malloc(sizeof(SDL_Rect)*2);
		if(!player[1].f) {
			fprintf(stderr,"ENGINE_ERROR: memory\n");
			exit(-1);
		}
		player[0].f[0].x=2;
		player[0].f[0].y=2;
		player[0].f[0].w=20;
		player[0].f[0].h=20;

		player[0].f[1].x=24;
		player[0].f[1].y=2;
		player[0].f[1].w=20;
		player[0].f[1].h=20;

		player[0].nf=2;
		/* player[0].joy=0; */

		player[0].keys[0]=SDLK_LEFT;
		player[0].keys[1]=SDLK_RIGHT;
		player[0].keys[2]=SDLK_UP;
		player[0].keys[3]=SDLK_DOWN;
#ifndef ALT_FIRE
		player[0].keys[4]=SDLK_RCTRL;
#else
		player[0].keys[4]=SDLK_m;
#endif
		player[1].f[0].x=2;
		player[1].f[0].y=24;
		player[1].f[0].w=20;
		player[1].f[0].h=20;

		player[1].f[1].x=24;
		player[1].f[1].y=24;
		player[1].f[1].w=20;
		player[1].f[1].h=20;

		player[1].nf=2;
		/* player[1].joy=0; */

		player[1].keys[0]=SDLK_a;
		player[1].keys[1]=SDLK_d;
		player[1].keys[2]=SDLK_w;
		player[1].keys[3]=SDLK_s;
		player[1].keys[4]=SDLK_LCTRL;

		firstInit=1;
	}

/* now follows the stuff that must be setup each play */
	
	player[0].cf=0;
	player[0].score=0;
	//player[0].shield=0;
	player[0].weapon=0;
	player[0].level=0;
	player[0].x=100;
	player[0].y=160;
	player[0].incx=0;
	player[0].incy=0;
	player[0].fire=0;
	player[0].firef=0;	
	player[0].ftime=2;
	player[0].cftime=0;

	player[0].companion=0;
	player[0].t=0;
	player[0].cinc=1;

/* ********************* */

	player[1].cf=0;
	player[1].score=0;
	//player[1].shield=0;
	player[1].weapon=0;
	player[1].level=0;
	player[1].x=200;
	player[1].y=160;
	player[1].incx=0;
	player[1].incy=0;
	player[1].fire=0;
	player[1].firef=0;
	player[1].ftime=2;
	player[1].cftime=0;

	player[1].companion=0;
	player[1].t=0;
	player[1].cinc=1;

/* ********************* */

	for(i=0;i<64;i++)
		enemy[i].n=&enemy[i+1];
	enemy[i].n=NULL;

	for(i=0;i<256;i++)
	{
		fire[i].n=&fire[i+1];
		vefx[i].n=&vefx[i+1];
	}
	fire[i].n=NULL;
	vefx[i].n=NULL;

	for(i=0;i<15;i++)
		objects[i].n=&objects[i+1];
	objects[i].n=NULL;

	ffree=fire;
	fused=NULL;

	vfree=vefx;
	vused=NULL;

	ofree=objects;
	oused=NULL;

	efree=enemy;
	eused=NULL;
	
	actCnt=0;
	actIdx=0;

	/* load the actions */
	sprintf(buffer,"%s/game.act",DD2_DATA);
	fd=fopen(buffer,"rt");
	if(!fd) {
		fprintf(stderr,"ENGINE_ERROR: unable to open act file\n");
		exit(-1);
	}

	if(fscanf(fd,"ITEMS=%i\n",&j)!=1) {
		fprintf(stderr,"ENGINE_ERROR: bad act file, error at line 1\n");
		exit(-1);
	}
	
	if(act)
		free(act);

	act=(struct actionStruct *)malloc(sizeof(struct actionStruct)*j);
	if(!act) {
		fprintf(stderr,"ENGINE_ERROR: memory\n");
		exit(-1);
	}
	
	for(i=0;i<j;i++)
		if(fscanf(fd,"%li - %i (%i,%i) %32[^\n]\n", &act[i].a, &act[i].type,
			 &act[i].x, &act[i].y, comm)!=5) {
			fprintf(stderr,"ENGINE_ERROR: bad act file, error at line %i\n", i+2);
			exit(-1);
		}

	fclose(fd);
}

void
engine_release()
{
	int i;

	for(i=0;i<2;i++)
		if(player[i].f)
			free(player[i].f);
			
	if(act)
		free(act);
}

void
engine_obj()
{
	oDesc *ot,*otp;
	SDL_Rect a,b;
	int i;
	
	/* process all the objects */
	for(otp=ot=oused;ot;) {
		ot->y+=0.25;
		if(ot->ftime)
			ot->ftime--;
		else {
			ot->ftime=10;
			ot->cf=ot->cf ? 0 : 1;
			if(ot->y>SCREENH) {
				if(ot==oused) {
					otp=ofree;
					ofree=oused;
					oused=oused->n;
					ofree->n=otp;
					otp=ot=oused;
					continue;					
				} else {
					otp->n=ot->n;
					ot->n=ofree;
					ofree=ot;
					ot=otp->n;
					continue;
				}
			}
		}

		a.x=ot->x;
		a.y=ot->y;
		b.w=20;
		b.h=20;
		
		switch(ot->type) {
			default:
			case OBJ_SHIELD:
				b.x=200;
				b.y=24;
			break;
			case OBJ_WEAPON1:
				b.x=90;
				b.y=24;
			break;
			case OBJ_WEAPON2:
				b.x=112;
				b.y=24;
			break;
			case OBJ_WEAPON3:
				b.x=134;
				b.y=24;
			break;
			case OBJ_COMPANION:
				b.x=178;
				b.y=24;
			break;
		}

		SDL_BlitSurface(gfx, &b, screen, &a);

		if(ot->cf) {
			b.x=68;
			b.y=24;
			SDL_BlitSurface(gfx, &b, screen, &a);
		}

		for(i=0;i<2;i++)
			if(player[i].shield)
				if(ot->x+10>player[i].x && ot->x+10<player[i].x+20 &&
					ot->y+10>player[i].y && ot->y+10<player[i].y+20) {
						switch(ot->type) {
							default:
							break;
							case OBJ_SHIELD:
								if(player[i].shield<10) {
									player[i].shield+=3;
									if(player[i].shield>10)
										player[i].shield=10;
									engine_add_vefx(VFX_SHUP,ot->x,ot->y);
								} else {
									player[i].score+=300;
									if(efx[7])
										Mix_PlayChannel(-1,efx[7],0);
								}
							break;
							case OBJ_WEAPON1:
								if(player[i].weapon!=0) {
									player[i].weapon=0;
									player[i].level--;
									if(player[i].level<0)
										player[i].level=0;
									engine_add_vefx(VFX_POW,ot->x,ot->y);
								} else {
									if(player[i].level<4) {
										player[i].level++;
										engine_add_vefx(VFX_POW,ot->x,ot->y);
									} else {
										player[i].score+=100;
										if(efx[7])
											Mix_PlayChannel(-1,efx[7],0);
									}
								}
							break;
							case OBJ_WEAPON2:
								if(player[i].weapon!=1) {
									player[i].weapon=1;
									player[i].level--;
									if(player[i].level<0)
										player[i].level=0;
									engine_add_vefx(VFX_POW,ot->x,ot->y);
								} else {
									if(player[i].level<4) {
										player[i].level++;
										engine_add_vefx(VFX_POW,ot->x,ot->y);
									} else {
										player[i].score+=100;
										if(efx[7])
											Mix_PlayChannel(-1,efx[7],0);
									}
								}
							break;
							case OBJ_WEAPON3:
								if(player[i].weapon!=2) {
									player[i].weapon=2;
									player[i].level--;
									if(player[i].level<0)
										player[i].level=0;
									engine_add_vefx(VFX_POW,ot->x,ot->y);
								} else {
									if(player[i].level<4) {
										player[i].level++;
										engine_add_vefx(VFX_POW,ot->x,ot->y);
									} else {
										player[i].score+=100;
										if(efx[7])
											Mix_PlayChannel(-1,efx[7],0);
									}
								}
							break;
							case OBJ_COMPANION:
								if(!player[i].companion) {
									player[i].companion=1;
									player[i].t=0;
									player[i].cinc=1;
									circle_path(player[i].x+10,player[i].y+10,30,player[i].t,&player[i].cx,&player[i].cy);
									engine_add_vefx(VFX_POW,ot->x,ot->y);
								} else {
									player[i].score+=250;
									if(efx[7])
										Mix_PlayChannel(-1,efx[7],0);
								}
							break;
						}
						ot->y=SCREENW+20;
				}

		otp=ot;
		ot=ot->n;
	}
}

void
engine_add_obj(int type, int x, int y)
{
	oDesc *ot;

	if(ofree==NULL) {
		fprintf(stderr,"PANIC!!!! ofree reached limit\n");
		exit(-1);
	}
	
	if(oused==NULL) {
		oused=ofree;
		ofree=ofree->n;
		oused->n=NULL;
	} else {
		ot=oused;
		oused=ofree;
		ofree=ofree->n;
		oused->n=ot;
	}
	
	oused->type=type;
	oused->x=x;
	oused->y=y;
	oused->ftime=10;
	oused->cf=0;
}

void
engine_vefx()
{
	vDesc *vt,*vtp;
	SDL_Rect a,b;

	/* process all the efx */
	for(vtp=vt=vused;vt;) {
		if(vt->cftime<vt->ftime)
			vt->cftime++;
		else {
			vt->cftime=0;
			if(vt->cf+1==vt->nf) {
				if(vt==vused) {
					vtp=vfree;
					vfree=vused;
					vused=vused->n;
					vfree->n=vtp;
					vtp=vt=vused;
					continue;
				} else {
					vtp->n=vt->n;
					vt->n=vfree;
					vfree=vt;
					vt=vtp->n;
					continue;
				}
			} else
				vt->cf++;
		}

		if(vt->type!=VFX_STAGE) {
			a.x=vt->x;
			a.y=vt->y;
			b.x=vt->f[vt->cf].x;
			b.y=vt->f[vt->cf].y;
			b.w=vt->f[vt->cf].w;
			b.h=vt->f[vt->cf].h;
			SDL_BlitSurface(gfx, &b, screen, &a);
		} else { /* just the STAGE N banner */
			char stage[16];
			sprintf(stage,"stage %i",vt->y);
			writeCString(gfx, screen, 125, 1,  stage, 0);
		}

		vtp=vt;
		vt=vt->n;
	}
}

void
engine_add_vefx(int type, int x, int y)
{
	vDesc *vt;

	if(vfree==NULL) {
		fprintf(stderr,"PANIC!!!! vfree reached limit\n");
		exit(-1);
	}

	if(vused==NULL) {
		vused=vfree;
		vfree=vfree->n;
		vused->n=NULL;
	} else {
		vt=vused;
		vused=vfree;
		vfree=vfree->n;
		vused->n=vt;
	}

	vused->type=type;
	vused->x=x;
	vused->y=y;
	vused->cftime=0;

	switch(type) {
		default:
		case VFX_SHIELD:
			vused->ftime=4;
			vused->nf=4;
			vused->cf=0;

			vused->f[0].x=46;
			vused->f[0].y=2;
			vused->f[0].w=20;
			vused->f[0].h=20;
			vused->f[1]=vused->f[0];
			vused->f[1].x=68;
			vused->f[2]=vused->f[0];
			vused->f[2].x=90;
			vused->f[3]=vused->f[0];
			vused->f[3].x=112;
			if(efx[3])
				Mix_PlayChannel(-1,efx[3],0);
		break;
		case VFX_EXPLO:
			vused->ftime=4;
			vused->nf=4;
			vused->cf=0;

			vused->f[0].x=134;
			vused->f[0].y=2;
			vused->f[0].w=20;
			vused->f[0].h=20;
			vused->f[1]=vused->f[0];
			vused->f[1].x=156;
			vused->f[2]=vused->f[0];
			vused->f[2].x=178;
			vused->f[3]=vused->f[0];
			vused->f[3].x=200;
			if(efx[6])
				Mix_PlayChannel(-1,efx[6],0);
		break;
		case VFX_EXPLOB:
			vused->ftime=4;
			vused->nf=3;
			vused->cf=0;

			vused->f[0].x=222;
			vused->f[0].y=2;
			vused->f[0].w=20;
			vused->f[0].h=20;
			vused->f[1]=vused->f[0];
			vused->f[1].x=244;
			vused->f[2]=vused->f[0];
			vused->f[2].x=266;
			if(efx[4])
				Mix_PlayChannel(-1,efx[4],0);
		break;
		case VFX_SHUP:
			vused->ftime=80;
			vused->nf=1;
			vused->cf=0;

			vused->f[0].x=222;
			vused->f[0].y=24;
			vused->f[0].w=45;
			vused->f[0].h=10;
			if(efx[7])
				Mix_PlayChannel(-1,efx[7],0);
		break;
		case VFX_POW:
			vused->ftime=80;
			vused->nf=1;
			vused->cf=0;

			vused->f[0].x=222;
			vused->f[0].y=35;
			vused->f[0].w=45;
			vused->f[0].h=10;
			if(efx[7])
				Mix_PlayChannel(-1,efx[7],0);
		break;
		case VFX_STAGE: /* special vefx */
			vused->ftime=250;
			vused->nf=1;
			vused->cf=0;
			if(player[0].shield)
				player[0].stage++;
			if(player[1].shield)
				player[1].stage++;
		break;
		case VFX_MEXPLO:
			engine_add_vefx(VFX_EXPLO, x-20, y);
			engine_add_vefx(VFX_EXPLO, x, y-20);
			engine_add_vefx(VFX_EXPLO, x, y+20);
			engine_add_vefx(VFX_EXPLO, x+20, y);
		break;

	}
}

void
engine_add_fire(int from, int type, int x, int y, float incx, float incy, pDesc *p)
{
	fDesc *ft;

	if(ffree==NULL) {
		fprintf(stderr,"PANIC!!!! ffree reached limit\n");
		exit(-1);
	}

	if(fused==NULL) {
		fused=ffree;
		ffree=ffree->n;
		fused->n=NULL;
	} else {
		ft=fused;
		fused=ffree;
		ffree=ffree->n;
		fused->n=ft;
	}

	fused->own=from;
	fused->type=type;
	fused->x=x;
	fused->y=y;
	fused->incx=incx;
	fused->incy=incy;
	fused->cftime=0;
	fused->player=p;

	/* set speed */
	switch(type) {
		default:
		case 0:
			fused->incx*=8;
			fused->incy*=8;
			fused->ftime=2;
		break;
		case 3:
		case 1:
			fused->incx*=10;
			fused->incy*=10;
			fused->ftime=2;
		break;
		case 2:
			fused->incx*=12;
			fused->incy*=12;
			fused->ftime=2;
		break;
		case 5:
		case 4:
			fused->incx*=4;
			fused->incy*=4;
			fused->ftime=2;
		break;
		case 6:
			fused->incx*=5;
			fused->incy*=5;
			fused->ftime=2;
		break;
	}
}

void
engine_fire()
{
	fDesc *ft,*ftp;
	eDesc *e;
	oDesc *o;
	SDL_Rect a,b;
	int i,j;

	/* process all the fires */
	for(ftp=ft=fused;ft;) {
		if(ft->cftime<ft->ftime)
			ft->cftime++;
		else {
			ft->cftime=0;
			ft->x+=ft->incx;
			ft->y+=ft->incy;
		}
		/* check if goes out the screen */
		if(ft->x<0 || ft->x>SCREENW
		   || ft->y<0 || ft->y>SCREENH) {
				if(ft==fused) {
					ftp=ffree;
					ffree=fused;
					fused=fused->n;
					ffree->n=ftp;
					ftp=ft=fused;
					continue;
				} else {
					ftp->n=ft->n;
					ft->n=ffree;
					ffree=ft;
					ft=ftp->n;
					continue;
				}
		}
		/* walls */
		if(ft->x<30 || ft->x>SCREENW-25) {
			engine_add_vefx(VFX_EXPLOB,ft->x-12,ft->y-12);
			ft->y=-20;
		}
		/* players */
		if(ft->own!=1) {
			for(i=0,j=0;i<2;i++)
				if(player[i].shield)
					if(ft->x>player[i].x && ft->x<player[i].x+20 &&
						ft->y>player[i].y && ft->y<player[i].y+20) {
							engine_add_vefx(VFX_EXPLOB,ft->x-12,ft->y-12);
							j++;
							player[i].shield--;
							if(player[i].shield)
								engine_add_vefx(VFX_SHIELD,player[i].x,player[i].y);
							else
								engine_add_vefx(VFX_EXPLO,player[i].x,player[i].y);
					}
			if(j)
				ft->y=-10;
		}
		/* enemies */
		if(ft->own!=2) {
			for(e=eused; e; e=e->n) {
				if(e->shield) {
					if((e->hit)(e,ft->x+2,ft->y+2)) {
							engine_add_vefx(VFX_EXPLOB,ft->x-12,ft->y-12);
														
							ft->y=-20;
							e->shield--;
							if(!e->shield) {
								engine_add_vefx(VFX_EXPLO,e->x+6,e->y+6);
								ft->player->score+=e->score;

								if(e->type==6)
									engine_add_vefx(VFX_MEXPLO,e->x+46,e->y+26);
								if(e->type==10)
									engine_add_vefx(VFX_MEXPLO,e->x+55,e->y+26);
							} 
							else
								ft->player->score+=e->score/(ft->player->level+1);
					}
				}
			}
		}
		/* object change */
		if(ft->own!=2) {
			for(o=oused; o; o=o->n)
				if(ft->x+2>o->x && ft->x+2<o->x+20 &&
					ft->y+2>o->y && ft->y+2<o->y+20) {
					if(o->type<OBJ_LAST)
						o->type++;
					else
						o->type=OBJ_FIRST;
					engine_add_vefx(VFX_EXPLOB,ft->x-12,ft->y-12);
					ft->y=-20;
				}
		}

		/* companion */
		if(ft->own!=1) {
			for(i=0;i<2;i++)
				if(player[i].shield && player[i].companion)
					if(ft->x+2>player[i].cx && ft->x+2<player[i].cx+4 &&
						ft->y+2>player[i].cy && ft->y+2<player[i].cy+4) {
						engine_add_vefx(VFX_EXPLOB,player[i].cx-10,player[i].cy-10);
						player[i].companion=0;
					}
		}

		switch(ft->type) {
			default:
			case 0:
				b.x=47;
				b.y=24;
				b.w=5;
				b.h=10;
			break;
			case 1:
				b.x=53;
				b.y=24;
				b.w=5;
				b.h=10;
			break;
			case 2:
				b.x=59;
				b.y=24;
				b.w=5;
				b.h=10;
			break;
			case 3:
				b.x=47;
				b.y=35;
				b.w=5;
				b.h=9;
			break;
			case 4:
				b.x=58;
				b.y=36;
				b.w=4;
				b.h=4;
			break;
			case 5:
				b.x=734;
				b.y=1;
				b.w=5;
				b.h=5;
			break;
			case 6:
				b.x=740;
				b.y=1;
				b.w=5;
				b.h=6;
			break;
		}
		a.x=ft->x;
		a.y=ft->y;
		SDL_BlitSurface(gfx, &b, screen, &a);

		ftp=ft;
		ft=ft->n;
	}
}

void
engine_player(pDesc *p)
{
	SDL_Rect a,b;
	eDesc *e;

/* calc move */

if(p->cftime<p->ftime)
	p->cftime++;
else {
	p->cftime=0;
	if(p->incx) {
		if(p->incx>0) {
			if(p->x+4<SCREENW-40)
				p->x+=4;
			else {
				p->shield--;
				if(p->shield)
					engine_add_vefx(VFX_SHIELD,p->x,p->y);
				else
					engine_add_vefx(VFX_EXPLO,p->x,p->y);
			}
		} else {
			if(p->x-4>20)
				p->x-=4;
			else {
				p->shield--;
				if(p->shield)
					engine_add_vefx(VFX_SHIELD,p->x,p->y);
				else
					engine_add_vefx(VFX_EXPLO,p->x,p->y);
			}
		}
	}

	if(p->incy) {
		if(p->incy>0) {
			if(p->y+4<SCREENH-20)
				p->y+=4;
		} else {
			if(p->y-4>40)
				p->y-=4;
		}
	}

	/* enemy hit */
	for(e=eused; e; e=e->n) {
		if(e->shield) {
			/* just 4 point, player size hardcoded (!) */
			if((e->hit)(e,p->x+5,p->y+5) || (e->hit)(e,p->x+15,p->y+5) ||
				(e->hit)(e,p->x+15,p->y+15) || (e->hit)(e,p->x+5,p->y+15) ) {
					if(p->shield)
						engine_add_vefx(VFX_SHIELD,p->x,p->y);
					else
						engine_add_vefx(VFX_EXPLO,p->x,p->y);

					e->shield--;
					p->shield--;
					if(!e->shield)
						engine_add_vefx(VFX_EXPLO,e->x+6,e->y+6);
			}
			/* and companion */
			if(p->companion) {
				if((e->hit)(e,p->cx+3,p->cy+3)) {
						engine_add_vefx(VFX_EXPLOB,p->cx-10,p->cy-10);
						e->shield--;
						p->companion=0;
						if(!e->shield)
							engine_add_vefx(VFX_EXPLO,e->x+6,e->y+6);
				}
			}
		}
	}	

	/* fire */
	if(p->fire==1) {
		p->fire++;

		if(p->firef!=0)
			p->firef=0;
		else
			p->firef=1;		
		
		switch(p->weapon) {
			default:
			case 0:
				switch(p->level) {
					default:
					case 0:
						engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
					break;
					case 1:
						if(p->firef)
							engine_add_fire(1,p->weapon,p->x+4,p->y,0,-1,p);
						else
							engine_add_fire(1,p->weapon,p->x+12,p->y,0,-1,p);
					break;
					case 2:
						if(p->firef)
							engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
						engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
						engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
					break;
					case 3:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+4,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0,-1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
						}
					break;
					case 4:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.20,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.20,-1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+14,p->y,0.10,-1,p);
						}
					break;
				}
				if(efx[1])
					Mix_PlayChannel(-1,efx[1],0);
			break;
			case 1:
				switch(p->level) {
					default:
					case 0:
						engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
					break;
					case 1:
						if(p->firef)
							engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
						else {
							engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y+8,-0.25,1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y+8,0.25,1,p);
						}
					break;
					case 2:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y+8,-0.25,1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y+8,0.25,1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
						}
					break;
					case 3:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+4,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y+8,-0.25,1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y+8,0.25,1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
						}
					break;
					case 4:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+8,p->y,0,-1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y+8,-0.25,1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y+8,0.25,1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.20,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.20,-1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+14,p->y,0.10,-1,p);
						}
					break;
				}
				if(efx[0])
					Mix_PlayChannel(-1,efx[0],0);
			break;
			case 2:
				switch(p->level) {
					default:
					case 0:
						engine_add_fire(1,p->weapon,p->x+8,p->y-10,0,-1,p);
					break;
					case 1:
						if(p->firef)
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
						else
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
					break;
					case 2:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
						} else
							engine_add_fire(1,p->weapon,p->x+8,p->y-10,0,-1,p);
					break;
					case 3:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.25,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.25,-1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
						}
					break;
					case 4:
						if(p->firef) {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.25,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.25,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.45,-1,p);
						} else {
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.45,-1,p);
							engine_add_fire(1,p->weapon,p->x+4,p->y,-0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+12,p->y,0.10,-1,p);
							engine_add_fire(1,p->weapon,p->x+8,p->y-10,0,-1,p);
						}
					break;
				}
				if(efx[2])
					Mix_PlayChannel(-1,efx[2],0);
			break;
		}
		
		if(p->companion) {
			engine_add_fire(1,3,p->cx+2,p->cy-8,0,-1,p);
			if(efx[5])
				Mix_PlayChannel(-1,efx[5],0);
		}
	}
	
	/* next frame */
	p->cf++;
	if(p->cf==p->nf)
		p->cf=0;
		
	if(p->companion) {
		if(p->incx && p->incx!=p->cinc)
			p->cinc=p->incx;

		p->t+=10*p->cinc;
	}
}

/* player sprite */
a.x=p->x;
a.y=p->y;

b.x=p->f[p->cf].x;
b.y=p->f[p->cf].y;
b.w=p->f[p->cf].w;
b.h=p->f[p->cf].h;
SDL_BlitSurface(gfx, &b, screen, &a);

/* companion */
if(p->companion) {
	a.x=p->cx;
	a.y=p->cy;

	b.x=162;
	b.y=30;
	b.w=7;
	b.h=7;
	SDL_BlitSurface(gfx, &b, screen, &a);
	
	if(p->cx<25 || p->cx>SCREENW-32) {
		engine_add_vefx(VFX_EXPLOB,p->cx-10,p->cy-10);
		p->companion=0;
	} else {
		circle_path(p->x+10,p->y+10,30,p->t,&p->cx,&p->cy);
		p->cx-=4;
		p->cy-=4;
	}
}

}

void
circle_path(int x, int y, int r, int t, float *rx, float *ry)
{
	*rx=floor((double)r*cos((double)t/100)+(double)x);
	*ry=floor((double)r*sin((double)t/100)+(double)y);
}

void
engine_enemy()
{
	eDesc *et,*etp;

	if(!boss)
	{
		/* check action */
		actCnt++;
		while(actCnt==act[actIdx].a)
			if(act[actIdx].type) {
				engine_add_enemy(act[actIdx].type, act[actIdx].x, act[actIdx].y);
				actIdx++;
				actCnt=0;
			} else {/* if the type == 0 then it's a vefx */
			       /* x value holds the kind and y holds type data */
				engine_add_vefx(act[actIdx].x, act[actIdx].x, act[actIdx].y);
				actIdx++;
				actCnt=0;
			}

		/* temporal loop */
		if(actCnt>1000) {
			actCnt=0;
			actIdx=0;
		}
	}

	/* process all the enemies */
	for(etp=et=eused;et;) {
		if(et->cftime<et->ftime)
			et->cftime++;
		else {
			et->cftime=0;
			if(!et->shield) {

				if(et->type==4)
					engine_add_obj(OBJ_WEAPON1, et->x+20, et->y+20);

				if(et->type==6 || et->type==10)
				{
					boss=false;
					if(sound)
						Mix_FadeInMusic(bgm,-1,2000);

					engine_add_obj(OBJ_SHIELD, et->x+46, et->y+26);
				}

				if(et->type==7 || et->type==9)
				{
					engine_add_fire(2,5,et->x+16,et->y+16,-1,0.5,NULL);
					engine_add_fire(2,5,et->x+16,et->y+16,1,-0.5,NULL);
					engine_add_fire(2,5,et->x+16,et->y+16,0.5,1,NULL);
					engine_add_fire(2,5,et->x+16,et->y+16,-0.5,-1,NULL);

					engine_add_fire(2,5,et->x+16,et->y+16,0.5,-1,NULL);
					engine_add_fire(2,5,et->x+16,et->y+16,-0.5,1,NULL);
					engine_add_fire(2,5,et->x+16,et->y+16,1,0.5,NULL);
					engine_add_fire(2,5,et->x+16,et->y+16,-1,-0.5,NULL);
				}
				
				if(et==eused) {
					etp=efree;
					efree=eused;
					eused=eused->n;
					efree->n=etp;
					etp=et=eused;
					continue;
				} else {
					etp->n=et->n;
					et->n=efree;
					efree=et;
					et=etp->n;
					continue;
				}
			}
			/* IA */
			(et->ia)(et);
		}

		/* DRAW */
		(et->draw)(et);

		etp=et;
		et=et->n;
	}
}

void
engine_add_enemy(int type, int x, int y)
{
	eDesc *et;

	if(efree==NULL) {
		fprintf(stderr,"PANIC!!!! efree reached limit\n");
		exit(-1);
	}

	if(eused==NULL) {
		eused=efree;
		efree=efree->n;
		eused->n=NULL;
	} else {
		et=eused;
		eused=efree;
		efree=efree->n;
		eused->n=et;
	}

	eused->type=type;
	eused->x=x;
	eused->y=y;
	eused->cftime=0;
	eused->ftime=2;
	eused->init=0;
	memset(eused->var,0,sizeof(int)*10);

	switch(type) {
		default:
			fprintf(stderr,"FATAL: undefined enemy!\n");
			exit(-1);
		break;
		case 1:
			eused->shield=2;
			eused->score=10;
			eused->ia=enemy_type1;
			eused->draw=enemy_type1d;
			eused->hit=enemy_type1h;
		break;
		case 2:
			eused->shield=1;
			eused->score=5;
			eused->ia=enemy_type2;
			eused->draw=enemy_type2d;
			eused->hit=enemy_type2h;
		break;
		case 3:
			eused->shield=1;
			eused->score=10;
			eused->ia=enemy_type3;
			eused->draw=enemy_type3d;
			eused->hit=enemy_type3h;
		break;
		case 4:
			eused->shield=20;
			eused->score=25;
			eused->ia=enemy_type4;
			eused->draw=enemy_type4d;
			eused->hit=enemy_type4h;
		break;
		case 5:
			eused->shield=2;
			eused->score=15;
			eused->ia=enemy_type5;
			eused->draw=enemy_type5d;
			eused->hit=enemy_type5h;
		break;
		case 6:
			eused->shield=250;
			eused->score=30;
			eused->ia=enemy_type6;
			eused->draw=enemy_type6d;
			eused->hit=enemy_type6h;
			boss=true;
			if(sound)
				Mix_FadeInMusic(bgm_boss,-1,2000);
		break;
		case 7:
			eused->shield=1;
			eused->score=25;
			eused->ia=enemy_type7;
			eused->draw=enemy_type7d;
			eused->hit=enemy_type7h;
		break;
		case 8:
			eused->shield=8;
			eused->score=5;
			eused->ia=enemy_type8;
			eused->draw=enemy_type8d;
			eused->hit=enemy_type8h;
		break;
		case 9:
			eused->shield=20;
			eused->score=20;
			eused->ia=enemy_type9;
			eused->draw=enemy_type9d;
			eused->hit=enemy_type9h;
		break;
		case 10:
			eused->shield=500;
			eused->score=40;
			eused->ia=enemy_type10;
			eused->draw=enemy_type10d;
			eused->hit=enemy_type10h;
			boss=true;
			if(sound)
				Mix_FadeInMusic(bgm_boss,-1,2000);
		break;
		case 11:
			eused->shield=1;
			eused->score=5;
			eused->ia=enemy_type11;
			eused->draw=enemy_type11d;
			eused->hit=enemy_type11h;
		break;
	}
}

/* ********************************************* */

void
enemy_type1(eDesc *e)
{
	int i;
	float m[2]={1.0f,1.0f};
	/*
	   var 0 -> radian
	   var 1 -> loop time

	   var 2,3 -> fire

	   var 4,5 -> frames (for fire)
	*/

	if(e->init<3) {
		if(e->var[3]==60) {
			e->var[2]=1;
			e->var[3]=20;
		} else
			e->var[3]++;

		if(e->var[2]) {
			for(i=0;i<2;i++)
				if(player[i].shield) {
					if(e->y<player[i].y) {
						if((player[i].y+10)-(e->y+28)!=0)
							m[i]=(double)((player[i].x+10)-(e->x+14))/(double)((player[i].y+10)-(e->y+28));
					} else {
						if((e->y-4)-(player[i].y+10)!=0)
							m[i]=(double)((player[i].x+10)-(e->x+14))/(double)((e->y-4)-(player[i].y+10));
					}
				}
			if(abs(m[0])<abs(m[1])) {
				i=0;
			} else
				i=1;

			if(abs(m[i])<0.3) {
				if(e->y<player[i].y)
					engine_add_fire(2,4,e->x+14,e->y+28,m[i],1,NULL);
				else
					engine_add_fire(2,4,e->x+14,e->y-4,m[i],-1,NULL);
				e->var[2]=0;
				e->var[4]=1;
				e->var[5]=8;
			}
		}
	}


	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=6;
			if(e->y==64) {
				e->init++;
				e->var[0]=325;
				e->var[1]=0;
			}
		break;
		case 1:
			circle_path(140,76,80,e->var[0],&e->x,&e->y);
			e->var[0]-=7;
			if(e->var[1]!=140)
				e->var[1]++;
			else
				e->init++;
		break;
		case 2:
			if(e->y>-32)
				e->y-=6;
			else
				e->init++;
		break;
	}

	if(e->var[5]) {
		e->var[5]--;
		if(!e->var[5]) {
			e->var[4]=0;
		}
	}
}

void
enemy_type1d(eDesc *e)
{
	SDL_Rect b[2]={{ 1,134,32,32 },{ 36,134,32,32 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]], screen, &a);
}

int
enemy_type1h(eDesc *e, int x, int y)
{
	return (x>e->x && x<e->x+40 && y>e->y && y<e->y+40);
}

/* ********************************************* */

void
enemy_type2(eDesc *e)
{
  int i;
	/*
	 	4 -> frame control
		0 -> direction
		1 -> fire
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=2;
			if(e->y>40) {
				e->init++;
				if(e->x>160)
					e->var[0]=0;
				else
					e->var[0]=1;
			}
		break;
		case 1:
			if(e->y>SCREENH)
				e->init++;
			else
				e->y+=2;

			if(e->var[0]) {
				if(e->x+4>SCREENW-50)
					e->var[0]=0;
				else
					e->x+=4;
			} else {
				if(e->x-4<30)
					e->var[0]=1;
				else
					e->x-=4;
			}

			for(i=0;!e->var[1] && i<2;i++)
				if(player[i].shield)
					if(abs(player[i].x-e->x)<8 && player[i].y>e->y) {
						engine_add_fire(2,4,e->x+10,e->y+20,0,+1.5,NULL);
						e->var[1]=1;
					}
		break;
	}

	e->var[4]=e->var[4] ? 0 : 1;

}

void
enemy_type2d(eDesc *e)
{
	SDL_Rect b[2]={{ 75,139,24,18 },{ 110,139,24,18 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]], screen, &a);
}

int
enemy_type2h(eDesc *e, int x, int y)
{
	return (x>e->x && x<e->x+24 && y>e->y && y<e->y+18);
}

/* ********************************************* */

void
enemy_type3(eDesc *e)
{
  int i;
	/*
	 	4 -> frame control
		1 -> fire
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			if(e->y>SCREENH)
				e->init++;
			else
				e->y+=3;

			for(i=0;!e->var[1] && i<2;i++)
				if(player[i].shield)
					if(abs(player[i].x-e->x)<8 && player[i].y>e->y) {
						engine_add_fire(2,4,e->x+10,e->y+20,0,+1.5,NULL);
						e->var[1]=1;
					}

		break;
	}

	e->var[4]=e->var[4] ? 0 : 1;

}

/* ********************************************* */

void
enemy_type4(eDesc *e)
{
  int i;
  float m[2]={1.0f,1.0f};
  
	/*
		1 -> fire cycle
		2 -> timer
	 	4,5 -> frame control
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=2;
			if(e->y>20) {
				e->init++;
				e->var[5]=2;
				e->var[1]++;
			}
		break;
		case 1:
			e->y+=0.5;
			e->var[2]++;
			if(e->var[2]>150)
				e->init++;
		break;
		case 2:
			e->y+=2;
			e->var[5]=0;
			e->var[1]=0;
		break;
	}

	if(e->var[1]>0) {
		switch(e->var[1]) {
			case 2:
				engine_add_fire(2,5,e->x+22,e->y+20,1,1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,1,-1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,-1,1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,-1,-1,NULL);
				engine_add_vefx(VFX_EXPLOB,e->x+14,e->y+11);
				if(efx[1])
					Mix_PlayChannel(-1,efx[1],0);
			break;
			case 8:
				engine_add_fire(2,5,e->x+22,e->y+20,0.5,1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,0.5,-1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,-0.5,1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,-0.5,-1,NULL);
				engine_add_vefx(VFX_EXPLOB,e->x+14,e->y+11);
				if(efx[1])
					Mix_PlayChannel(-1,efx[1],0);
			break;
			case 14:
				engine_add_fire(2,5,e->x+22,e->y+20,1,0.5,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,1,-0.5,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,-1,0.5,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,-1,-0.5,NULL);
				engine_add_vefx(VFX_EXPLOB,e->x+14,e->y+11);
				if(efx[1])
					Mix_PlayChannel(-1,efx[1],0);
			break;
			case 20:
				engine_add_fire(2,5,e->x+22,e->y+20,-1,0,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,1,0,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,0,1,NULL);
				engine_add_fire(2,5,e->x+22,e->y+20,0,-1,NULL);
				engine_add_vefx(VFX_EXPLOB,e->x+14,e->y+11);
				if(efx[1])
					Mix_PlayChannel(-1,efx[1],0);
			break;
			case 25:
			case 30:
			case 35:
				for(i=0;i<2;i++)
					if(player[i].shield) {
						if(e->y<player[i].y) {
							if((player[i].y+10)-(e->y+21)!=0)
								m[i]=(double)((player[i].x+10)-(e->x+21))/(double)((player[i].y+10)-(e->y+21));
						} else {
							if((e->y+21)-(player[i].y+10)!=0)
								m[i]=(double)((player[i].x+10)-(e->x+21))/(double)((e->y+21)-(player[i].y+10));
						}
					}
				if(abs(m[0])<abs(m[1])) {
					i=0;
				} else
					i=1;

				if(abs(m[i])<0.3) {
					if(e->y<player[i].y)
						engine_add_fire(2,4,e->x+22,e->y+39,m[i],1,NULL);
					else
						engine_add_fire(2,4,e->x+22,e->y+39,m[i],-1,NULL);
				}
			break;
		}
		if(e->var[1]>40)
			e->var[1]=1;
		else
			e->var[1]++;
	}
	
	e->var[4]=e->var[4] ? 0 : 1;

}

void
enemy_type4d(eDesc *e)
{
	SDL_Rect b[4]={{ 246,83,47,47 },{ 297,83,47,47 },{ 348,83,47,47 },{ 399,83,47,47 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]+e->var[5]], screen, &a);
}

int
enemy_type4h(eDesc *e, int x, int y)
{
	return (x>e->x && x<e->x+48 && y>e->y && y<e->y+48);
}

/* ********************************************* */

void
enemy_type5(eDesc *e)
{
	/*
	 	4 -> frame control
		0 -> direction
		1 -> fire
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->init++;
			e->var[1]=(int)e & 0x0f; /* pseudo random :) */
		case 1:
			if(e->y>SCREENH)
				e->init++;
			else
				e->y+=4;

			if(e->var[0]) {
				if(e->x+5>SCREENW-50)
					e->var[0]=0;
				else
					e->x+=5;
			} else {
				if(e->x-5<30)
					e->var[0]=1;
				else
					e->x-=5;
			}

			if(e->var[1]>16) {
				engine_add_fire(2,6,e->x+8,e->y+20,0,+1.5,NULL);
				engine_add_fire(2,6,e->x+21,e->y+20,0,+1.5,NULL);
				e->var[1]=0;
			}
			e->var[1]++;
		break;
	}

	e->var[4]=e->var[4] ? 0 : 1;

}

void
enemy_type5d(eDesc *e)
{
	SDL_Rect b[2]={{ 141,139,32,32 },{ 176,139,32,32 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]], screen, &a);
}

int
enemy_type5h(eDesc *e, int x, int y)
{
	return (x>e->x && x<e->x+32 && y>e->y && y<e->y+32);
}

/* ********************************************* */

void
enemy_type6(eDesc *e)
{
  int i;
  float m[2]={1.0f,1.0f};
  
	/*
		1 -> fire cycle
		2 -> timer
		3 -> fire type
	 	4 -> frame control
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=2;
			if(e->y==20) {
				e->init++;
				e->var[1]=1;
			}
		break;
		case 1:
		break;
		case 2:
			e->y+=2;
			e->x-=2;
			if(e->x<25)
				e->init++;
		break;
		case 3:
			e->y-=2;
			e->x+=2;
			if(e->y==20)
				e->init++;
		break;
		case 4:
			e->y+=2;
			e->x+=2;
			if(e->x>223)
				e->init++;
		break;
		case 5:
			e->y-=2;
			e->x-=2;
			if(e->y==20)
			{
				e->init=1;
				e->var[1]=1;
				e->var[3]=0;
			}
		break;
	}

	if(e->var[1]>0) {
		if(e->var[3]==0)
			switch(e->var[1]) {
				case 2:
					engine_add_fire(2,5,e->x+10,e->y+26,1,1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,1,-1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,-1,1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,-1,-1,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2,e->y+18);

					engine_add_fire(2,5,e->x+10+49,e->y+26,1,1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,1,-1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,-1,1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,-1,-1,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2+49,e->y+18);

					if(efx[1])
						Mix_PlayChannel(-1,efx[1],0);
				break;
				case 8:
					engine_add_fire(2,5,e->x+10,e->y+26,0.5,1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,0.5,-1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,-0.5,1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,-0.5,-1,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2,e->y+18);

					engine_add_fire(2,5,e->x+10+49,e->y+26,0.5,1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,0.5,-1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,-0.5,1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,-0.5,-1,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2+49,e->y+18);

					if(efx[1])
						Mix_PlayChannel(-1,efx[1],0);
				break;
				case 14:
					engine_add_fire(2,5,e->x+10,e->y+26,1,0.5,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,1,-0.5,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,-1,0.5,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,-1,-0.5,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2,e->y+18);
					
					engine_add_fire(2,5,e->x+10+49,e->y+26,1,0.5,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,1,-0.5,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,-1,0.5,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,-1,-0.5,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2+49,e->y+18);
					
					if(efx[1])
						Mix_PlayChannel(-1,efx[1],0);
				break;
				case 20:
					engine_add_fire(2,5,e->x+10,e->y+26,-1,0,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,1,0,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,0,1,NULL);
					engine_add_fire(2,5,e->x+10,e->y+26,0,-1,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2,e->y+18);

					engine_add_fire(2,5,e->x+10+49,e->y+26,-1,0,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,1,0,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,0,1,NULL);
					engine_add_fire(2,5,e->x+10+49,e->y+26,0,-1,NULL);
					engine_add_vefx(VFX_EXPLOB,e->x+2+49,e->y+18);

					if(efx[1])
						Mix_PlayChannel(-1,efx[1],0);
				break;
				case 25:
				case 30:
				case 35:
					for(i=0;i<2;i++)
						if(player[i].shield) {
							if(e->y<player[i].y) {
								if((player[i].y+10)-(e->y+21)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+21))/(double)((player[i].y+10)-(e->y+21));
							} else {
								if((e->y+21)-(player[i].y+10)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+21))/(double)((e->y+21)-(player[i].y+10));
							}
						}
					if(abs(m[0])<abs(m[1])) {
						i=0;
					} else
						i=1;

					if(abs(m[i])<0.3) {
						if(e->y<player[i].y)
							engine_add_fire(2,4,e->x+35,e->y+38,m[i],1,NULL);
						else
							engine_add_fire(2,4,e->x+35,e->y+38,m[i],-1,NULL);
					}
				break;
			}
		else
		{

			switch(e->var[1]) {
				case 2:
				case 14:
					engine_add_fire(2,6,e->x+20,e->y+40,0,+1.5,NULL);
					engine_add_fire(2,6,e->x+20+27,e->y+40,0,+1.5,NULL);
					if(efx[5])
						Mix_PlayChannel(-1,efx[5],0);
				break;
				case 35:
					for(i=0;i<2;i++)
						if(player[i].shield) {
							if(e->y<player[i].y) {
								if((player[i].y+10)-(e->y+21)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+21))/(double)((player[i].y+10)-(e->y+21));
							} else {
								if((e->y+21)-(player[i].y+10)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+21))/(double)((e->y+21)-(player[i].y+10));
							}
						}
					if(abs(m[0])<abs(m[1])) {
						i=0;
					} else
						i=1;

					if(abs(m[i])<0.3) {
						if(e->y<player[i].y)
							engine_add_fire(2,4,e->x+35,e->y+38,m[i],1,NULL);
						else
							engine_add_fire(2,4,e->x+35,e->y+38,m[i],-1,NULL);
					}
				break;
				default:
				break;
			}
		}

		if(e->var[1]>40)
		{
			e->var[1]=1;
			if(e->var[3]==0)
			{
				e->init++;
				e->var[3]=1;
			}
		}
		else
			e->var[1]++;
	}
	
	e->var[4]++;
	if(e->var[4]>3)
		e->var[4]=0;

}

void
enemy_type6d(eDesc *e)
{
	SDL_Rect b[4]={{ 664,41,73,52 },{ 664,95,73,52 },{ 664,149,73,52 },{ 664,95,73,52 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]], screen, &a);
}

int
enemy_type6h(eDesc *e, int x, int y)
{
	return (x>e->x && x<e->x+73 && y>e->y && y<e->y+52);
}

/* ********************************************* */

void
enemy_type7(eDesc *e)
{
	/*
		1 -> timer
	 	4 -> frame control
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y++;
			if(e->y>SCREENH)
				e->init++;
		break;
	}

	e->var[1]++;
	if(e->var[1]==2)
	{
		e->var[1]=0;
		e->var[4]++;
		if(e->var[4]>3)
			e->var[4]=0;
	}

}

void
enemy_type7d(eDesc *e)
{
	SDL_Rect b[4]={{ 211,134,32,32 },{ 246,134,32,32 },{ 211,169,32,32 },{ 246,169,32,32 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]], screen, &a);
}

/* ********************************************* */

void
enemy_type8(eDesc *e)
{
	int k;

	/*
	 	0 -> timer
	 	4 -> frame control
		5 -> fire timer
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=4;
			if(e->y>20)
			{
				e->var[0]=80;
				e->init++;
			}
		break;
		case 1:
			e->var[5]--;

			k=-1;
			if(player[0].shield)
				k=0;
				
			if(player[1].shield)
			{
				if(k==-1)
					k=1;
				else
					if(abs(player[1].x-e->x)>abs(player[0].x-e->x))
						k=1;
			}

			if(k!=-1)
			{

				if(abs(e->x-player[k].x)<16)
				{
					if(e->var[5]<0)
					{
						if(efx[5])
							Mix_PlayChannel(-1,efx[5],0);
						engine_add_fire(2,6,e->x+5,e->y+23,0,2,NULL);
						engine_add_fire(2,6,e->x+22,e->y+23,0,2,NULL);
						e->var[5]=6;
					}
				}


				if(abs(e->x-player[k].x)>8)
				{
					if(e->x>player[k].x)
						e->var[1]=-2;
					else
						e->var[1]=+2;

					if(e->x+e->var[1]<SCREENW-55 && e->x+e->var[1]>30)
						e->x+=e->var[1];
				}

				e->var[0]--;
				if(e->var[0]==0)
					e->init++;
			}
			else
				e->init++;
		break;
		case 2:
			e->var[5]--;

			if(e->y>SCREENH)
			{
				e->init++;
				break;
			}
			else
				e->y+=2;

			if(e->var[1]>0) {
				if(e->x+4>SCREENW-55)
					e->var[1]=0;
				else
					e->x+=4;
			} else {
				if(e->x-4<30)
					e->var[1]=1;
				else
					e->x-=4;
			}

			k=0;
			if(player[0].shield)
				k=(int)(abs(e->x-player[0].x)<16);
			if(player[1].shield)
				k+=(int)(abs(e->x-player[0].x)<16);
			if(k>0)
			{
				if(e->var[5]<0)
				{
					if(efx[5])
						Mix_PlayChannel(-1,efx[5],0);
					engine_add_fire(2,6,e->x+5,e->y+23,0,2,NULL);
					engine_add_fire(2,6,e->x+22,e->y+23,0,2,NULL);
					e->var[5]=6;
				}
			}
		break;

	}

	e->var[4]=e->var[4] ? 0 : 1;
}

void
enemy_type8d(eDesc *e)
{
	SDL_Rect b[2]={{ 141,169,32,32 },{ 176,169,32,32 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]], screen, &a);
}


/* ********************************************* */

void
enemy_type9(eDesc *e)
{
	/*
	 	0 -> status
		1 -> timer
	 	4 -> frame control
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=2;
			if(e->y>40)
				e->init++;
		break;
		case 1:
			e->var[1]++;
			if(e->var[1]>10)
			{
				engine_add_vefx(VFX_EXPLOB,e->x,e->y);
				engine_add_enemy(7, e->x-8, e->y-8);
				
				engine_add_vefx(VFX_EXPLOB,e->x+32,e->y);
				engine_add_enemy(7, e->x+32, e->y-8);
				
				engine_add_vefx(VFX_EXPLOB,e->x-2,e->y+41);
				engine_add_enemy(7, e->x-8, e->y+28);

				engine_add_vefx(VFX_EXPLOB,e->x+32,e->y+41);
				engine_add_enemy(7, e->x+32, e->y+28);
				e->init++;
				e->var[0]=2;
			}
		break;
		case 2:
			e->y-=2;
			if(e->y<-41)
				e->init++;
		break;
	}

	e->var[4]=e->var[4] ? 0 : 1;
}

void
enemy_type9d(eDesc *e)
{
	SDL_Rect b[4]={{ 450,248,48,41 },{ 501,248,48,41 },{ 552,248,48,41 },{ 603,248,48,41 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[0]+e->var[4]], screen, &a);
}

int
enemy_type9h(eDesc *e, int x, int y)
{
	if(e->var[0]==0)
		return (x>e->x && x<e->x+48 && y>e->y && y<e->y+41);
	else
		return (x>e->x+11 && x<e->x+48-11 && y>e->y+11 && y<e->y+41-11);
}

/* ********************************************* */

void
enemy_type10(eDesc *e)
{
  int i;
  float m[2]={1.0f,1.0f};

	/*
	 	0 -> status
		1 -> timer 
		2 -> dir
		3 -> timer
	 	4 -> frame control
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->y+=2;
			if(e->y==30) {
				e->init++;
				e->var[1]=60;
				e->var[3]=0;
			}
		break;
		case 1:
			e->var[3]++;

			e->var[1]--;
			if(e->var[1]==0)
			{
				e->init++;
				e->var[1]=150;
				e->var[3]=0;
			}
			else
			{
				if(e->var[3]==10)
				{
					e->var[3]=0;
					if(e->var[0]==0)
					{
						engine_add_fire(2,5,e->x+6,e->y+32,-1,0.5,NULL);
						engine_add_fire(2,5,e->x+6,e->y+32,1,-0.5,NULL);
						engine_add_fire(2,5,e->x+6,e->y+32,0.5,1,NULL);
						engine_add_fire(2,5,e->x+6,e->y+32,-0.5,-1,NULL);

						engine_add_fire(2,5,e->x+6,e->y+32,0.5,-1,NULL);
						engine_add_fire(2,5,e->x+6,e->y+32,-0.5,1,NULL);
						engine_add_fire(2,5,e->x+6,e->y+32,1,0.5,NULL);
						engine_add_fire(2,5,e->x+6,e->y+32,-1,-0.5,NULL);

						engine_add_vefx(VFX_EXPLOB,e->x-1,e->y+25);
					}
					if(e->var[0]<2)
					{
						engine_add_fire(2,5,e->x+6+91,e->y+32,-1,0.5,NULL);
						engine_add_fire(2,5,e->x+6+91,e->y+32,1,-0.5,NULL);
						engine_add_fire(2,5,e->x+6+91,e->y+32,0.5,1,NULL);
						engine_add_fire(2,5,e->x+6+91,e->y+32,-0.5,-1,NULL);

						engine_add_fire(2,5,e->x+6+91,e->y+32,0.5,-1,NULL);
						engine_add_fire(2,5,e->x+6+91,e->y+32,-0.5,1,NULL);
						engine_add_fire(2,5,e->x+6+91,e->y+32,1,0.5,NULL);
						engine_add_fire(2,5,e->x+6+91,e->y+32,-1,-0.5,NULL);

						engine_add_vefx(VFX_EXPLOB,e->x+90,e->y+25);
					}

					for(i=0;i<2;i++)
						if(player[i].shield) {
							if(e->y<player[i].y) {
								if((player[i].y+10)-(e->y+21)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+52))/(double)((player[i].y+10)-(e->y+24));
							} else {
								if((e->y+21)-(player[i].y+10)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+52))/(double)((e->y+24)-(player[i].y+10));
							}
						}
					if(abs(m[0])<abs(m[1])) {
						i=0;
					} else
						i=1;

					if(abs(m[i])<0.3) {
						if(e->y<player[i].y)
							engine_add_fire(2,4,e->x+52,e->y+24,m[i],1,NULL);
						else
							engine_add_fire(2,4,e->x+52,e->y+24,m[i],-1,NULL);
					}
				}
			}
		break;
		case 2:
			e->var[1]--;
			e->var[3]++;
			
			if(e->var[1]==0)
			{
				e->var[2]=0;
				if(e->var[0]!=2)
					e->init++;
			}
			else
			{
				if(e->var[2]==0)
				{
					if(e->var[0]!=2)
						e->x-=2;
					else
						e->x-=4;
					if(e->x<30)
						e->var[2]=1;
				}
				else
				{
					if(e->var[0]!=2)
						e->x+=2;
					else
						e->x+=4;
					if(e->x>SCREENW-30-110)
						e->var[2]=0;
				}

				if(e->var[3]==18)
				{
					e->var[3]=0;
					if(e->var[0]==0)
					{
						engine_add_fire(2,6,e->x+13,e->y+37,0,+1.5,NULL);
					}
					if(e->var[0]<2)
					{
						engine_add_fire(2,6,e->x+90,e->y+37,0,+1.5,NULL);
						if(efx[5])
							Mix_PlayChannel(-1,efx[5],0);
					}
				}

				if(e->var[3]==0 || e->var[3]==10)
				{
					for(i=0;i<2;i++)
						if(player[i].shield) {
							if(e->y<player[i].y) {
								if((player[i].y+10)-(e->y+21)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+52))/(double)((player[i].y+10)-(e->y+24));
							} else {
								if((e->y+21)-(player[i].y+10)!=0)
									m[i]=(double)((player[i].x+10)-(e->x+52))/(double)((e->y+24)-(player[i].y+10));
							}
						}
					if(abs(m[0])<abs(m[1])) {
						i=0;
					} else
						i=1;

					if(abs(m[i])<0.3) {
						if(e->y<player[i].y)
							engine_add_fire(2,4,e->x+52,e->y+24,m[i],1,NULL);
						else
							engine_add_fire(2,4,e->x+52,e->y+24,m[i],-1,NULL);
					}
				}
			}
		break;
		case 3:
			if(e->var[2]==0)
			{
				e->y+=2;
				if(e->y>140)
					e->var[2]=1;
			}
			else
			{
				e->y-=2;
				if(e->y==30)
				{
					if(e->var[0]!=2)
						e->init=1;
					else
						e->init=2;
					e->var[1]=60;
					e->var[3]=0;
				}
			}
		break;
	}

	e->var[4]=e->var[4] ? 0 : 1;
}

void
enemy_type10d(eDesc *e)
{
	SDL_Rect b[4]={{ 664,203,55,52 },{ 718,203,55,52 },{ 664,257,55,52 },{ 718,257,55,52 }};
	SDL_Rect c[4]={{ 664,311,25,36 },{ 724,311,25,36 },{ 688,311,25,36 },{ 748,311,25,36 }};
	SDL_Rect a;

	if(e->shield>100)
	{
		a.x=e->x;
		a.y=e->y;

		SDL_BlitSurface(gfx, &b[2*e->var[4]], screen, &a);
	}
	else
	{
		a.x=e->x+30;
		a.y=e->y;

		SDL_BlitSurface(gfx, &c[e->var[4]], screen, &a);
	
		if(e->var[0]==0)
		{
			engine_add_vefx(VFX_MEXPLO,e->x,e->y+20);
			e->var[0]=1;
		}
	}

	if(e->shield>75)
	{
		a.x=e->x+54;
		a.y=e->y;

		SDL_BlitSurface(gfx, &b[(2*e->var[4])+1], screen, &a);
	}
	else
	{
		a.x=e->x+54;
		a.y=e->y;

		SDL_BlitSurface(gfx, &c[2+e->var[4]], screen, &a);

		if(e->var[0]==1)
		{
			engine_add_vefx(VFX_MEXPLO,e->x+90,e->y+20);
			e->var[0]=2;
		}
	}
}

int
enemy_type10h(eDesc *e, int x, int y)
{
	switch(e->var[0])
	{
		default:
			return (x>e->x && x<e->x+110 && y>e->y && y<e->y+36) ||
				(x>e->x && x<e->x+36 && y>e->y && y<e->y+52) ||
				(x>e->x+72 && x<e->x+110 && y>e->y && y<e->y+52);
		break;
		case 1:
			return (x>e->x+32 && x<e->x+110 && y>e->y && y<e->y+36) ||
				(x>e->x+72 && x<e->x+110 && y>e->y && y<e->y+52);
		break;
		case 2:
			return (x>e->x+32 && x<e->x+80 && y>e->y && y<e->y+36);
		break;
	}
}

/* ********************************************* */

void
enemy_type11(eDesc *e)
{
  int i;
	/*
	 	4 -> frame control
		2 -> frame mod
		0 -> direction
		1 -> fire
		3 -> direction y
	*/
	switch(e->init) {
		default:
			e->shield=0;
		break;
		case 0:
			e->var[3]=-2;
			e->init++;
		break;
		case 1:
			if(e->var[2] && e->y>SCREENH)
				e->init++;
			else
				e->y+=e->var[3];

			if(e->y<-32)
				e->init++;
			
			if(e->var[0]) {
				if(e->x+4>SCREENW-50)
					e->var[0]=0;
				else
					e->x+=4;
			} else {
				if(e->x-4<30)
					e->var[0]=1;
				else
					e->x-=4;
			}

			if(e->var[2])
				for(i=0;!e->var[1] && i<2;i++)
					if(player[i].shield)
						if(abs(player[i].x-e->x)<8 && player[i].y>e->y) {
							engine_add_fire(2,4,e->x+10,e->y+20,0,+1.5,NULL);
							e->var[1]=1;
						}
		break;
		case 2:
			e->var[2]=2;
			e->var[3]=3;
			e->init=1;
		break;
	}

	e->var[4]=e->var[4] ? 0 : 1;

}

void
enemy_type11d(eDesc *e)
{
	SDL_Rect b[4]={{ 75,178,24,18 },{ 110,178,24,18 },
		{ 75,139,24,18 },{ 110,139,24,18 }};
	SDL_Rect a;

	a.x=e->x;
	a.y=e->y;

	SDL_BlitSurface(gfx, &b[e->var[4]+e->var[2]], screen, &a);
}

