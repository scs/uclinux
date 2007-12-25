/* 
 * SDLRoids - An Astroids clone.
 * 
 * Copyright (c) 2000 David Hedbor <david@hedbor.org>
 * 	based on xhyperoid by Russel Marks.
 * 	xhyperoid is based on a Win16 game, Hyperoid by Edward Hutchins 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 */

/*
 * sdl.c - Graphics handling for SDL.
 */

#include "config.h"
RCSID("$Id: sdl.c,v 1.18 2001/03/27 23:23:52 neotron Exp $");

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>
#include <SDL.h>
#include <string.h>

#include "misc.h"	/* for POINT */
#include "getargs.h"
#include "graphics.h"
#include "sdlsound.h"
#include "roidsupp.h"


static SDL_Joystick *joystick = NULL;
static int num_buttons = 0;

#define NUM_BITMAPS	18
/* Loaded BMPs... */
SDL_Surface *bitmaps[NUM_BITMAPS];

static char *gfxname[] = {
  "bmp/num0.bmp",
  "bmp/num1.bmp",
  "bmp/num2.bmp",
  "bmp/num3.bmp",
  "bmp/num4.bmp",
  "bmp/num5.bmp",
  "bmp/num6.bmp",
  "bmp/num7.bmp",
  "bmp/num8.bmp",
  "bmp/num9.bmp",  
  "bmp/blank.bmp",
  "bmp/bomb.bmp",
  "bmp/level.bmp",
  "bmp/life.bmp",
  "bmp/plus.bmp",
  "bmp/score.bmp",
  "bmp/shield.bmp",
  "bmp/icon.bmp",
};

/* indicies in above array */
#define BMP_NUM0	0
#define BMP_NUM1	1
#define BMP_NUM2	2
#define BMP_NUM3	3
#define BMP_NUM4	4
#define BMP_NUM5	5
#define BMP_NUM6	6
#define BMP_NUM7	7
#define BMP_NUM8	8
#define BMP_NUM9	9
#define BMP_BLANK	10
#define BMP_BOMB	11
#define BMP_LEVEL	12
#define BMP_LIFE	13
#define BMP_PLUS	14
#define BMP_SCORE	15
#define BMP_SHIELD	16
#define BMP_ICON	17

#define R colortable.colors[current_color].r
#define G colortable.colors[current_color].g
#define B colortable.colors[current_color].b

static Uint32 colors[16];
static SDL_Surface *screen;
static SDL_Palette colortable;

static int maxx=0, maxy=0, minx=-1, miny=-1;
static int offx=0, offy=0;

static int current_x = 0, current_y = 0;
static Uint32 current_color; /* current color */
/* this leaves 16 lines at the top for score etc. */
static int width = 480 , height = 480, mindimhalf = 240;

/* We will at most redraw MAX_OBJS*2+2 in a frame. The eraser, the new object 
 * and the special case - the new/old shield locations.
 */
static SDL_Rect rects[MAX_OBJS*2+2];
static int rec_counter=0;

/* this oddity is needed to simulate the mapping the original used a
 * Windows call for. MAX_COORD is a power of 2, so when optimised
 * this isn't too evil.
 */
#define USE_CONV_TABLE
#ifdef USE_CONV_TABLE
#define MAX_DRAW_COORD (MAX_COORD+1000)

/* Tables to translate virtual coord to actual coord */
static Sint16 coord2x[MAX_DRAW_COORD*2], coord2y[MAX_DRAW_COORD*2];
static Sint16 *conv_coord2x = coord2x + MAX_DRAW_COORD;
static Sint16 *conv_coord2y = coord2y + MAX_DRAW_COORD;

#define calc_convx(i,x)	coord2x[i] = ((mindimhalf+(x)*(mindimhalf)/MAX_COORD))
#define calc_convy(i,y)	coord2y[i] = ((mindimhalf-(y)*(mindimhalf)/MAX_COORD))

#define convx(x) conv_coord2x[x]
#define convy(y) conv_coord2y[y]
#else
#define convx(x) ((mindimhalf+(x)*(mindimhalf)/MAX_COORD))
#define convy(y) ((mindimhalf-(y)*(mindimhalf)/MAX_COORD))
#endif

#define convr(r)        ((width*r)/MAX_COORD)

static float joy_x = 0.0, joy_y = 0.0;
static int *joy_button;
float IsKeyDown(int key)
{
  Uint8 *keystate;
  keystate = SDL_GetKeyState(NULL);
  switch(key)
  {
   case KEY_F1:		return keystate[SDLK_F1];
   case KEY_TAB:	return keystate[SDLK_TAB]
			  || (ARG_JSHIELD < num_buttons &&
			      joy_button[ARG_JSHIELD]); 
   case KEY_S:		return keystate[SDLK_s]
			  || (ARG_JBOMB < num_buttons
			      && joy_button[ARG_JBOMB]); 
   case KEY_LEFT:	return keystate[SDLK_LEFT]
			  ? 1 : (joy_x < 0 ? -joy_x : 0 ); 
   case KEY_RIGHT:	return keystate[SDLK_RIGHT]
			  ? 1 : (joy_x > 0 ? joy_x :0); 
   case KEY_DOWN:	return keystate[SDLK_DOWN]
			  ? 1 : (joy_y > 0 ? joy_y : 0 ); 
   case KEY_UP:		return keystate[SDLK_UP]
			  ? 1 : (joy_y < 0 ? -joy_y : 0 ); 
   case KEY_SPACE:	return keystate[SDLK_SPACE]
			  || (ARG_JFIRE < num_buttons
			      && joy_button[ARG_JFIRE]);  
   case KEY_ESC:	return keystate[SDLK_ESCAPE]; 
   default:
    return 0;
  }

}

void fast_putpixel1(Uint16 x, Uint16 y, Uint32 pixel)
{
  *((Uint8 *)screen->pixels + y * screen->pitch + x) = pixel;
}
void fast_putpixel2(Uint16 x, Uint16 y, Uint32 pixel)
{
  *((Uint16 *)screen->pixels + y * screen->pitch/2 + x) = pixel;
}

void fast_putpixel3(Uint16 x, Uint16 y, Uint32 pixel) 
{ 
    Uint8 *pix = (Uint8 *)screen->pixels + y * screen->pitch + x * 3; 
    if(SDL_BYTEORDER == SDL_BIG_ENDIAN) { 
        pix[2] = pixel; 
        pix[1] = pixel >> 8; 
        pix[0] = pixel >> 16; 
    } else { 
        pix[0] = pixel; 
        pix[1] = pixel >> 8; 
        pix[2] = pixel >> 16; 
    } 
} 
void fast_putpixel4(Uint16 x, Uint16 y, Uint32 pixel)
{
  *((Uint32 *)screen->pixels + y * screen->pitch/4 + x) = pixel;
}
void (*fast_putpixel)(Uint16 x, Uint16 y, Uint32 pixel);

inline static void _sdl_drawpixel(int x, int y, int r, int g, int b)
{
  Uint8 *bits, bpp;
  Uint32 pixel = SDL_MapRGB(screen->format, r, g, b);
  /*  printf("Drawing %dx%d in %d,%d,%d\n", x, y, r, g, b); */
  bpp = screen->format->BytesPerPixel;
  bits = ((Uint8 *)screen->pixels)+y*screen->pitch+x*bpp;

  /* Set the pixel */
  switch(bpp)
  {
   case 1:
    *((Uint8 *)(bits)) = (Uint8)pixel;
    break;
   case 2:
    *((Uint16 *)(bits)) = (Uint16)pixel;
    break;
   case 3: { /* Format/endian independent */
     Uint8 r, g, b;

     r = (pixel>>screen->format->Rshift)&0xFF;
     g = (pixel>>screen->format->Gshift)&0xFF;
     b = (pixel>>screen->format->Bshift)&0xFF;
     *((bits)+screen->format->Rshift/8) = r; 
     *((bits)+screen->format->Gshift/8) = g;
     *((bits)+screen->format->Bshift/8) = b;
   }
   break;
   case 4:
    *((Uint32 *)(bits)) = (Uint32)pixel;
    break;
  }
}

static void sdl_drawpixel(int x, int y)
{
  if(x >= width || x < 0 ||
     y >= height || y < 0) {
    return;
  } 
  x += offx;
  y += offy;
  if(x > maxx) maxx = x;
  if(y > maxy) maxy = y;
  if(minx < 0 || x < minx)   minx = x;
  if(miny < 0 || y < miny)   miny = y;
  /* Fast method */
  (*fast_putpixel)(x, y, colors[current_color]);
}

/* Draw a circle in the current color. Based off the version in SGE. */
static inline void drawcircle(Sint16 x, Sint16 y, Sint32 r)
{
  Sint32 cx = 0;
  Sint32 cy = r;
  Sint32 df = 1 - r;
  Sint32 d_e = 3;
  Sint32 d_se = -2 * r + 5;
  do {
    sdl_drawpixel(x+cx, y+cy);
    sdl_drawpixel(x-cx, y+cy);
    sdl_drawpixel(x+cx, y-cy);
    sdl_drawpixel(x-cx, y-cy);
    sdl_drawpixel(x+cy, y+cx);
    sdl_drawpixel(x+cy, y-cx);
    sdl_drawpixel(x-cy, y+cx);
    sdl_drawpixel(x-cy, y-cx);
    
    if (df < 0)  {
      df   += d_e;
      d_e  += 2;
      d_se += 2;
    } else {
      df   += d_se;
      d_e  += 2;
      d_se += 4;
      cy--;
    }
    cx++;
  } while(cx <= cy);
}

/* absolute value of a */
#define ABS(a)		(((a)<0) ? -(a) : (a))

/* take binary sign of a, either -1, or 1 if >= 0 */
#define SGN(a)		(((a)<0) ? -1 : 1)

/* Draw an horizontal line in the current color */
inline void draw_horzline(Sint16 x1, Sint16 x2, Sint32 y)
{
  int i;
  if (x1 < x2) {
    for (i = x1; i <= x2; i++)
      sdl_drawpixel(i, y);
  } else {
    for (i = x2; i <= x1; i++)
      sdl_drawpixel(i, y);
  }  
  return;
}

/* Draw an vertical line in the current color */
inline void draw_vertline(Sint16 x, Sint16 y1, Sint32 y2)
{
  int i;
  if (y1 < y2) {
    for (i = y1; i <= y2; i++)
      sdl_drawpixel(x, i);
  } else {
    for (i = y2; i <= y1; i++)
      sdl_drawpixel(x, i);
  }  
  return;
}

/* Draw a line between two coordinates */
inline void drawline(int x1,int y1,int x2,int y2)
{
  int d, x, y, ax, ay, sx, sy, dx, dy;
  if((dx = x2 - x1) == 0) { /* vertical line */
    draw_vertline(x1, y1, y2);
    return;
  }
  if((dy = y2 - y1) == 0) { /* horizontal line */
    draw_horzline(x1, x2, y1);
    return;
  }
  ax = ABS(dx)<<1;  sx = SGN(dx);
  ay = ABS(dy)<<1;  sy = SGN(dy);

  x = x1;
  y = y1;
  if (ax>ay)
  {		/* x dominant */
    d = ay-(ax>>1);
    for(;;)
    {
      sdl_drawpixel(x,y);
      if (x==x2) return;
      if (d>=0)
      {
	y += sy;
	d -= ax;
      }
      x += sx;
      d += ay;
    } 
  } else {			/* y dominant */
    d = ax-(ay>>1);
    for (;;) 
    {
      sdl_drawpixel(x,y);
      if (y==y2) return;
      if (d>=0)
      {
	x += sx;
	d -= ay;
      }
      y += sy;
      d += ax;
    }
  }
}

inline void MoveTo(int x,int y)
{
  current_x = convx(x);
  current_y = convy(y);
}


/* Scaling blit function by Greg Velichansky */
inline Uint32 ifloor(Uint32 i)
{
  return i & 0xFFFF0000;
}

inline Uint32 iceil(Uint32 i)
{
  return (i & 0xFFFF) ? i : ifloor(i) + (1<<16);
}


/* The most pedantic-a%& getpixel and putpixel ever, hopefully. */
/* There may still be endianness bugs! These will be fixed after adequte testing. XXX XXX XXX */
inline int SDL_GetPixel (SDL_Surface *f, Uint32 x, Uint32 y,
			 Uint8 *r, Uint8 *g, Uint8 *b)
{
  /*const Uint32 mask[] = {0x0, 0xff, 0xffff, 0xffffff, 0xffffffff};*/
  Uint32 pixel;
  
  Uint8 *pp;
  
  int n; /* general purpose 'n'. */
  
  if (f == NULL) return -1;

  pp = (Uint8 *) f->pixels;

  if (x >= f->w || y >= f->h) return -1;

  pp += (f->pitch * y);

  pp += (x * f->format->BytesPerPixel);

  /* we do not lock the surface here, it would be inefficient XXX */
  /* this reads the pixel as though it was a big-endian integer XXX */
  /* I'm trying to avoid reading part the end of the pixel data by
   * using a data-type that's larger than the pixels */
  for (n = 0, pixel = 0; n < f->format->BytesPerPixel; ++n, ++pp)
  {
#if SDL_BYTEORDER == SDL_LIL_ENDIAN
    pixel >>= 8;
    pixel |= *pp << (f->format->BitsPerPixel - 8);
#else
    pixel |= *pp;
    pixel <<= 8;
#endif
  }

  SDL_GetRGB(pixel, f->format, r, g, b);
  return 0;
}


int SDL_FastScaleBlit(SDL_Surface *src, SDL_Rect *sr,
		      SDL_Surface *dst, SDL_Rect *dr)
{
  Uint8 r, g, b;
  Uint32 rs, gs, bs; /* sums. */
  
  /* temp storage for large int multiplies. Uint64 doen't exist anywhere */
  double farea; 
  Uint32 area;

  Uint32 sx, sy;
  Uint32 dsx, dsy;

  Uint32 wsx, wsy;

  Uint32 x, y; /* x and y, for sub-area */

  Uint32 tx, ty; /* normal integers */
  Uint32 lx, ly; /* normal integers */

  Uint32 w, e, n, s; /* temp variables, named after compass directions */

  if (src == NULL || sr == NULL || dst == NULL || dr == NULL) return -1;

  if (!dr->w || !dr->h) return -1;


  /* TODO FIXME check for possible overflows! */

  wsx = dsx = (sr->w << 16) / dr->w;
  if (!(wsx & 0xFFFF0000)) wsx = 1 << 16;
  wsy = dsy = (sr->h << 16) / dr->h;
  if (!(wsy & 0xFFFF0000)) wsy = 1 << 16;

  lx = dr->x + dr->w;
  ly = dr->y + dr->h;

  /* lazy multiplication. Hey, it's only once per blit. :P */
  farea = ((double)wsx) * ((double)wsy);
  farea /= (double)(1 << 16);
  area = (Uint32) farea;

  /* For optimization, those setup routines should be moved into
   * SDL_ScaleTiledBitmap() for that function.
   */

  for (ty = dr->y, sy = sr->y << 16; ty < ly; ++ty, sy+=dsy)
  {
    for (tx = dr->x, sx = sr->x << 16; tx < lx; ++tx, sx+=dsx)
    {
      rs = gs = bs = 0;
      for (y = ifloor(sy); iceil(sy + wsy) > y; y += (1<<16))
      {
	for (x = ifloor(sx); iceil(sx + wsx) > x; x += (1<<16))
	{
	  w = (x > sx) ? 0 : sx - x;
	  n = (y > sy) ? 0 : sy - y;

	  e = (sx+wsx >= x+(1<<16)) ? 1<<16 : sx+wsx - x;
	  s = (sy+wsy >= y+(1<<16)) ? 1<<16 : sy+wsy - y;

	  if (w > e || s < n) continue;

#define gsx ((x >> 16) >= sr->x+sr->w ? sr->x+sr->w-1 : x >> 16)
#define gsy ((y >> 16) >= sr->y+sr->h ? sr->y+sr->h-1 : y >> 16)

	  SDL_GetPixel (src, gsx, gsy, &r, &g, &b);

	  rs += ((e - w)>>8) * ((s - n)>>8) * r;
	  gs += ((e - w)>>8) * ((s - n)>>8) * g;
	  bs += ((e - w)>>8) * ((s - n)>>8) * b;
	}
      }
      rs /= area;
      gs /= area;
      bs /= area;

      r = (Uint8) rs;
      g = (Uint8) gs;
      b = (Uint8) bs;

      (*fast_putpixel)(tx, ty, SDL_MapRGB(screen->format, r, g, b));
    }
  }

  return 0;
#undef gsx
#undef gsy
}

void unlock_graphics()
{
  if ( SDL_MUSTLOCK(screen) ) {
    SDL_UnlockSurface(screen);
  }
}
inline void lock_graphics() {
  if ( SDL_MUSTLOCK(screen) ) {
    if ( SDL_LockSurface(screen) < 0 ) {
      return;
    }
  }
}

inline void ResetRefreshCoords()
{
  minx = miny = -1;
  maxx = maxy = 0;
}

inline void RedrawObject() {
  if(minx >= 0) {
    rects[rec_counter].x = minx;
    rects[rec_counter].y = miny;
    rects[rec_counter].w = maxx-minx+1;
    rects[rec_counter].h = maxy-miny+1;
    rec_counter++;
  }
}

static int is_poly=0;
inline void LineTo(int x,int y)
{
  x = convx(x); y = convy(y);
  drawline(current_x,current_y,x,y);
  current_x=x;
  current_y=y;
}


inline void Polyline(POINT *pts,int n)
{
  int f;
  if(n<2) return;
  is_poly = 1;
  MoveTo(pts->x,pts->y);
  pts++;
  for(f = 1; f < n; f++, pts++)
    LineTo(pts->x, pts->y);
}

inline void Circle(Sint16 x, Sint16 y, Sint32 r)
{
  x = convx(x);
  y = convy(y);  
  
  drawcircle(x, y,convr(r));
}

/* doesn't set current_[xy] because hyperoid.c doesn't need it to */
inline void SetPixel(Sint16 x, Sint16 y,Uint32 c)
{
  current_color = c;
  x = convx(x);
  y = convy(y);  
  sdl_drawpixel(x,y);
}


inline void set_colour(int c)
{
  current_color = c;
}


/* SetIndicator - set a quantity indicator */

int SetIndicator( char * npBuff, char bitmap, int nQuant )
{
  if (nQuant > 5)
  {
    *npBuff++ = bitmap; *npBuff++ = bitmap;
    *npBuff++ = bitmap; *npBuff++ = bitmap;
    *npBuff++ = BMP_PLUS;
  }
  else
  {
    int nBlank = 5 - nQuant;
    while (nQuant--) *npBuff++ = bitmap;
    while (nBlank--) *npBuff++ = BMP_BLANK;
  }
  return( 5 );
}


/* score_graphics - draw score and rest of status display */

static int force_score_redraw = 1;
void score_graphics(int level,int score,int lives,int shield,int bomb)
{
  SDL_Rect src, dest;
  static int olevel=-1, oscore=-1, olives=-1, oshield=-1, obomb=-1;
  static char szScore[40];
  static char ozScore[40];
  char szBuff[sizeof(szScore)];
  char *npBuff = szBuff;
  int nLen, x, myoffx=0, mywidth, xysize;
  float scale;
  if(!force_score_redraw &&
     level == olevel && score == oscore &&
     lives == olives && shield == oshield && bomb == obomb)
    return;
  olevel = level;  oscore = score; 	       
  olives = lives;  oshield = shield; 
  obomb = bomb;
  if(force_score_redraw) {
    memset(ozScore, NUM_BITMAPS, 40);
    force_score_redraw = 0;
  }

  *npBuff++ = BMP_LEVEL;
  sprintf( npBuff, "%2.2d", level );
  while (isdigit( *npBuff ))
    *npBuff = (char)(*npBuff + BMP_NUM0 - '0'), ++npBuff;
  *npBuff++ = BMP_BLANK;
  *npBuff++ = BMP_SCORE;
  sprintf( npBuff, "%7.7d", score );
  while (isdigit( *npBuff ))
    *npBuff = (char)(*npBuff + BMP_NUM0 - '0'), ++npBuff;
  *npBuff++ = BMP_BLANK;
  *npBuff++ = BMP_SHIELD;
  sprintf( npBuff, "%3.3d", shield );
  while (isdigit( *npBuff ))
    *npBuff = (char)(*npBuff + BMP_NUM0 - '0'), ++npBuff;
  *npBuff++ = BMP_BLANK;
  npBuff += SetIndicator( npBuff, BMP_LIFE, lives );
  npBuff += SetIndicator( npBuff, BMP_BOMB, bomb );
  nLen = npBuff - szBuff;
  
  mywidth = nLen * 16;
  if(mywidth > screen->w) {
    scale = (float)screen->w / (float)mywidth;
    xysize = (int)floor(16.0 * scale);
  } else {
    myoffx = (screen->w - mywidth)/2;
    if(myoffx > offx) myoffx = offx;
    xysize = 16;
  }
  src.w = src.h = 16;
  src.x = src.y = 0;
  dest.w = dest.h = xysize;
  dest.y = offy - 2 - xysize;
  if(dest.y < 0) dest.y = 0;

  for(x = 0;x < nLen; x++) {
    if(ozScore[x] != szBuff[x]) {
      ozScore[x] = szBuff[x];
      dest.x = myoffx + x*xysize;
      if(xysize != 16) {
	SDL_FastScaleBlit(bitmaps[ (int)szBuff[x] ], &src,
			  screen, &dest);
      } else {
	SDL_BlitSurface(bitmaps[ (int)szBuff[x] ], &src,
			screen, &dest);
      }
      SDL_UpdateRect(screen, dest.x, dest.y, xysize, xysize);
    }
  }
}

int bmp2surface(int num)
{
  int i;
  SDL_Surface *loaded, *converted;
  
  if((loaded = SDL_LoadBMP(gfxname[num])) ||
     (loaded = SDL_LoadBMP(datafilename(NULL, gfxname[num]))) ||
     (loaded = SDL_LoadBMP(datafilename(DATADIR, gfxname[num]))) ||
     (loaded = SDL_LoadBMP(datafilename(bindir, gfxname[num])))) {
    /* Ugly hack to set the "transparent" color to black :-) */
    if(loaded->format->BytesPerPixel == 1) {
      for(i = 0; i < loaded->format->palette->ncolors; i++)
      {
	/* Make the "transparent" color black... */
	if(loaded->format->palette->colors[i].r == 255 &&
	   loaded->format->palette->colors[i].g == 0   &&
	   loaded->format->palette->colors[i].b == 255) {
	  loaded->format->palette->colors[i].r =
	    loaded->format->palette->colors[i].g = 
	    loaded->format->palette->colors[i].b = 0;
	  break;
	}
      }
    }
    converted = SDL_DisplayFormat(loaded);
    SDL_FreeSurface(loaded);
    bitmaps[num] = converted;
    return 1;
  } else {
    fprintf(stderr, "Error loading image %s!\n", gfxname[num]);
    return 0;
  }
}

void load_images()
{
  int f;
  for(f = 0; f < NUM_BITMAPS; f++) {
    if(!bmp2surface(f)) { 
      exit(1);
    }
  }
}

void init_colours(int *palrgb)
{
  SDL_Color clut[16];
  colortable.ncolors = 256;
  colortable.colors = malloc(256 * sizeof(SDL_Color));
  for(current_color=0; current_color < 16; current_color++)
  {
    R = ((palrgb[current_color*3  ]<<8)|palrgb[current_color*3  ]);
    G = ((palrgb[current_color*3+1]<<8)|palrgb[current_color*3+1]);
    B = ((palrgb[current_color*3+2]<<8)|palrgb[current_color*3+2]); 
    if ( screen->format->palette ) {
      clut[current_color].r = R;
      clut[current_color].g = G;
      clut[current_color].b = B;
    }
    colors[current_color] = SDL_MapRGB(screen->format, R, G, B);
  }
  if ( screen->format->palette ) {
    SDL_SetColors(screen, clut, 0, 16);
  }  
}

void draw_boundary_box()
{
#ifdef USE_CONV_TABLE
  int i;
#endif
  int myoffy, myoffx;

  lock_graphics();

  set_colour(RED);
  offx=offy=0;
  if(width < (height - 16)) {
    myoffy = (height-width)/2;
    myoffx = 0;
    drawline(myoffx, myoffy+16, myoffx+width, myoffy+16);
    drawline(myoffx, myoffy+width+15, myoffx+width, myoffy+width+15);
    drawline(myoffx, myoffy+16, myoffx, myoffy+width+15);
    drawline(myoffx+width-1, myoffy+16, myoffx+width-1, myoffy+width+15);
    
    height = width;    
  }
  else {
    myoffx = (width-height)/2 + 8;
    myoffy = 0;
    
    drawline(myoffx, 16, myoffx+height-16, 16);
    drawline(myoffx, height-1, myoffx+height-16, height-1);
    drawline(myoffx, 16, myoffx, height);
    drawline(myoffx+height-16, 16, myoffx+height-16, height-1);
    
    height -= 16;
    width = height;
  }
  offx = myoffx+1; offy = myoffy+17;
  height = width -= 2;
  mindimhalf = height/2;
#ifdef USE_CONV_TABLE
  for(i = 0; i < (MAX_DRAW_COORD*2); i++)
  {
    int mycoord = i - MAX_DRAW_COORD;
    calc_convx(i, mycoord);
    calc_convy(i, mycoord);
  }
#endif
  unlock_graphics();
  SDL_UpdateRect(screen, 0,0, 0,0);
}

void init_graphics(int *palrgb)
{
  int video_flags;
  int i;
  video_flags = SDL_SWSURFACE;
  if(ARG_FSCRN) 
    video_flags = SDL_FULLSCREEN|SDL_HWSURFACE;
  video_flags |= SDL_ASYNCBLIT;
  video_flags |= SDL_RESIZABLE;
  
  if ( SDL_Init(SDL_INIT_VIDEO|SDL_INIT_AUDIO|SDL_INIT_JOYSTICK) < 0 ) {
    fprintf(stderr,
	    "Couldn't initialize SDL: %s\n", SDL_GetError());
    exit(1);
  }
  atexit(SDL_Quit);
  if(ARG_FSCRN) {
    SDL_ShowCursor(0);
  }
  /* Print information about the joysticks */
  if(SDL_NumJoysticks()) {
    printf("There are %d joysticks attached\n", SDL_NumJoysticks());
    for ( i=0; i<SDL_NumJoysticks(); ++i ) {
      const char *name;
      name = SDL_JoystickName(i);
      printf("Joystick %d = %s",i,name ? name : "Unknown Joystick");
      if(ARG_JLIST == 0 && i == ARG_JOYNUM) {
	joystick = SDL_JoystickOpen(i );
	if(joystick == NULL) {
	  printf(" (failed to open)\n");
	} else{ 
	  printf(" (opened)\n");
	}
      } else {
	printf("\n");
      }
    }
    if(joystick != NULL) {
      joy_button = calloc(num_buttons = SDL_JoystickNumButtons(joystick), sizeof(int));
      if(ARG_JFIRE >= num_buttons ||
	 ARG_JSHIELD >= num_buttons ||
	 ARG_JBOMB >= num_buttons) {
	fprintf(stderr, "Selected joystick button out of range (0-%d)\n",
		num_buttons-1);
	exit(1);
      }
    }
    if(ARG_JLIST) {
      exit(0);
    }
  }

  if(ARG_WIDTH) {
    width  = ARG_WIDTH;
    height = ARG_HEIGHT;
  }
  /* Initialize the display */
  screen = SDL_SetVideoMode(width, height,
			    SDL_GetVideoInfo()->vfmt->BitsPerPixel,
			    video_flags);
  if ( screen == NULL ) {
    fprintf(stderr, "Couldn't set %dx%d video mode: %s\n",width, height, 
	    SDL_GetError());
    exit(1);
  }

  /* Decide which pixel drawing function to use. This is an optimization */
  switch (screen->format->BytesPerPixel) {
   case 1:
    fast_putpixel = fast_putpixel1;
    break;
   case 2:
    fast_putpixel = fast_putpixel2;
    break;
   case 3:
    fast_putpixel = fast_putpixel3;
    break;
   case 4:
    fast_putpixel = fast_putpixel4;
    break;
   default:
    fprintf(stderr, "Unknown video bytes-per-pixel!\n");
    exit(1);
  }
  init_colours(palrgb);
  load_images();
  draw_boundary_box();
  
  
  SDL_WM_SetCaption("SDLRoids " VERSION, "SDLRoids");
  SDL_WM_SetIcon(bitmaps[BMP_ICON], NULL);
}

extern int bPaused;

static void Pause(int stop) {
  POINT Pt;
  Pt.x = 0;
  Pt.y = 0;
  if(stop) {
    //    PrintLetters( "PAUSED", Pt, Pt, RED, 600 );
    bPaused = 1;
  } else {
    bPaused = 0;
    //    PrintLetters( "PAUSED", Pt, Pt, BLACK, 600 );
  }
  SDL_PauseAudio(bPaused);
}

void update_graphics(void)
{
  float value;
  SDL_Event event;
  while ( SDL_PollEvent(&event) ) {
    switch (event.type) {
     case SDL_ACTIVEEVENT:
      if(event.active.state == SDL_APPACTIVE) {
	Pause(!event.active.gain);
      }
      break;
      
     case SDL_QUIT:
      SDL_Quit();
      exit(0);
     case SDL_KEYDOWN:
      if((event.key.keysym.sym == SDLK_RETURN &&
	  event.key.keysym.mod & (KMOD_ALT | KMOD_META)) ||
	 event.key.keysym.sym == SDLK_BACKSPACE) {
	/* toggle fullscreen*/
	if(!(screen->flags & SDL_FULLSCREEN)) {
	  /* currently windowed. */
	  SDL_ShowCursor(0);
	  SDL_WM_GrabInput(SDL_GRAB_ON);
	}
	if(SDL_WM_ToggleFullScreen(screen)) {
	  if(!(screen->flags & SDL_FULLSCREEN)) {
	    SDL_ShowCursor(1);
	    SDL_WM_GrabInput(SDL_GRAB_OFF);
	  }
	}
      } else if(event.key.keysym.sym == SDLK_g &&
		event.key.keysym.mod & KMOD_CTRL) {
	if(!(screen->flags & SDL_FULLSCREEN)) {
	  if(SDL_WM_GrabInput(SDL_GRAB_QUERY) == SDL_GRAB_OFF) {
	    if(SDL_WM_GrabInput(SDL_GRAB_ON) == SDL_GRAB_ON) {
	      SDL_ShowCursor(0);
	    }
	  } else {
	    if(SDL_WM_GrabInput(SDL_GRAB_OFF) == SDL_GRAB_OFF) {
	      SDL_ShowCursor(1);
	    }
	  }
	}
      } else if(event.key.keysym.sym == SDLK_z &&
		event.key.keysym.mod & KMOD_CTRL) {
	Pause(1);
	if(!SDL_WM_IconifyWindow()) {
	  Pause(0); /* iconify failed */
	}
      } else if(event.key.keysym.sym == SDLK_PAUSE) {
	Pause(!bPaused);
      } else if(event.key.keysym.sym == SDLK_DOWN ||
		event.key.keysym.sym == SDLK_UP)
      {
	loopsam(PTHRUST_CHANNEL,PTHRUST_SAMPLE);
      } 

      break;
     case SDL_KEYUP:
      if(event.key.keysym.sym == SDLK_DOWN ||
	 event.key.keysym.sym == SDLK_UP)
      {
	loopsam(PTHRUST_CHANNEL,-1);
      } 
      break;
     case SDL_VIDEORESIZE: 
      screen = SDL_SetVideoMode(event.resize.w, 
				event.resize.h,
				screen->format->BitsPerPixel,
				screen->flags);
      width = event.resize.w;
      height = event.resize.h;
      /* Draw the boundary box, calculate offsets etc */
      draw_boundary_box();
      /* Force redraw of the score display */
      force_score_redraw=1;
      break;    
     case SDL_JOYAXISMOTION:
      if(event.jaxis.value > 5000 || event.jaxis.value < -5000)
	value = event.jaxis.value / 32767.0;
      else
	value = 0;
      switch(event.jaxis.axis)
      {
       case 0: joy_x = value; break;
       case 1: joy_y = value; break;
      }
      
      break;
     case SDL_JOYBUTTONDOWN:
      if(joystick != NULL)
	joy_button[event.jbutton.button] = 1;
      break;
     case SDL_JOYBUTTONUP:
      if(joystick != NULL)
	joy_button[event.jbutton.button] = 0;
      break;
    }
  }
  if(!force_score_redraw && rec_counter) {
    /* Update all changed rects, but if we draw the boundary box
     * there is no need since it's already done.
     */
    SDL_UpdateRects(screen, rec_counter, rects);
  }
  rec_counter = 0;
}

void exit_graphics(void)
{
  int i;
  for(i = 0; i < NUM_BITMAPS; i++)
    SDL_FreeSurface(bitmaps[i]);
  SDL_FreeSurface(screen);
  free(colortable.colors);
  if(joystick != NULL) {
    SDL_JoystickClose(joystick);
    free(joy_button);
  }
}




