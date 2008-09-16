/*
   Landscape rendering
  
   Ok.. i know that voxel is something else... but a lot of people is using
   the name "voxel" to mean this kind of rendering tecnique.
   I wrote this to explain the basic idea behind the rendering of newvox4;
   newvox4 is very badly written (it's named 4 because is the fourth of
   a sequel of experiments) and is coded in pascal + asm.
   Since i got a few request of an explanation i decided to write the kernel
   of the rendering in C hoping that this will be easier to understand.
   This implements only the base landscape (no sky or floating ball) and
   with keyboard only support but i think you can get the idea of how I
   implemented those other things.
  
   I'm releasing this code to the public domain for free... and as it's
   probably really obvious there's no warranty of any kind on it.
   You can do whatever you want with this source; however a credit in any
   program that uses part of this code would be really appreciated :)
  
   Any comment is welcome :)
  
                                    Andrea "6502" Griffini, programmer
                                           agriff@ix.netcom.com
                                        http://vv.val.net/~agriffini
*/  
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "SDL.h"

typedef unsigned char byte;

byte HMap[256*256];      /* Height field */
byte CMap[256*256];      /* Color map */
byte Video[320*200];     /* Off-screen buffer */

/* Reduces a value to 0..255 (used in height field computation) */
int Clamp(int x)
{
  return (x<0 ? 0 : (x>255 ? 255 : x));
}

/* Heightfield and colormap computation */
void ComputeMap(void)
{
  int p,i,j,k,k2,p2;

  /* Start from a plasma clouds fractal */
  HMap[0]=128;
  for ( p=256; p>1; p=p2 )
  {
    p2=p>>1;
    k=p*8+20; k2=k>>1;
    for ( i=0; i<256; i+=p )
    {
      for ( j=0; j<256; j+=p )
      {
	int a,b,c,d;

	a=HMap[(i<<8)+j];
	b=HMap[(((i+p)&255)<<8)+j];
	c=HMap[(i<<8)+((j+p)&255)];
	d=HMap[(((i+p)&255)<<8)+((j+p)&255)];

	HMap[(i<<8)+((j+p2)&255)]=
	  Clamp(((a+c)>>1)+(rand()%k-k2));
	HMap[(((i+p2)&255)<<8)+((j+p2)&255)]=
	  Clamp(((a+b+c+d)>>2)+(rand()%k-k2));
	HMap[(((i+p2)&255)<<8)+j]=
	  Clamp(((a+b)>>1)+(rand()%k-k2));
      }
    }
  }

  /* Smoothing */
  for ( k=0; k<3; k++ )
    for ( i=0; i<256*256; i+=256 )
      for ( j=0; j<256; j++ )
      {
	HMap[i+j]=(HMap[((i+256)&0xFF00)+j]+HMap[i+((j+1)&0xFF)]+
		   HMap[((i-256)&0xFF00)+j]+HMap[i+((j-1)&0xFF)])>>2;
      }

  /* Color computation (derivative of the height field) */
  for ( i=0; i<256*256; i+=256 )
    for ( j=0; j<256; j++ )
    {
      k=128+(HMap[((i+256)&0xFF00)+((j+1)&255)]-HMap[i+j])*4;
      if ( k<0 ) k=0; if (k>255) k=255;
      CMap[i+j]=k;
    }
}

int lasty[320],         /* Last pixel drawn on a given column */
    lastc[320];         /* Color of last pixel on a column */

/*
   Draw a "section" of the landscape; x0,y0 and x1,y1 and the xy coordinates
   on the height field, hy is the viewpoint height, s is the scaling factor
   for the distance. x0,y0,x1,y1 are 16.16 fixed point numbers and the
   scaling factor is a 16.8 fixed point value.
 */
void Line(int x0,int y0,int x1,int y1,int hy,int s)
{
  int i,sx,sy;

  /* Compute xy speed */
  sx=(x1-x0)/320; sy=(y1-y0)/320;
  for ( i=0; i<320; i++ )
  {
    int c,y,h,u0,v0,u1,v1,a,b,h0,h1,h2,h3;

    /* Compute the xy coordinates; a and b will be the position inside the
       single map cell (0..255).
     */
    u0=(x0>>16)&0xFF;    a=(x0>>8)&255;
    v0=((y0>>8)&0xFF00); b=(y0>>8)&255;
    u1=(u0+1)&0xFF;
    v1=(v0+256)&0xFF00;

    /* Fetch the height at the four corners of the square the point is in */
    h0=HMap[u0+v0]; h2=HMap[u0+v1];
    h1=HMap[u1+v0]; h3=HMap[u1+v1];

    /* Compute the height using bilinear interpolation */
    h0=(h0<<8)+a*(h1-h0);
    h2=(h2<<8)+a*(h3-h2);
    h=((h0<<8)+b*(h2-h0))>>16;

    /* Fetch the color at the four corners of the square the point is in */
    h0=CMap[u0+v0]; h2=CMap[u0+v1];
    h1=CMap[u1+v0]; h3=CMap[u1+v1];

    /* Compute the color using bilinear interpolation (in 16.16) */
    h0=(h0<<8)+a*(h1-h0);
    h2=(h2<<8)+a*(h3-h2);
    c=((h0<<8)+b*(h2-h0));

    /* Compute screen height using the scaling factor */
    y=(((h-hy)*s)>>11)+100;

    /* Draw the column */
    if ( y<(a=lasty[i]) )
    {
      unsigned char *b=Video+a*320+i;
      int sc,cc;


      if ( lastc[i]==-1 )
	lastc[i]=c;

      sc=(c-lastc[i])/(a-y);
      cc=lastc[i];

      if ( a>199 ) { b-=(a-199)*320; cc+=(a-199)*sc; a=199; }
      if ( y<0 ) y=0;
      while ( y<a )
      {
	*b=cc>>18; cc+=sc;
	b-=320; a--;
      }
      lasty[i]=y;

    }
    lastc[i]=c;

    /* Advance to next xy position */
    x0+=sx; y0+=sy;
  }
}

float FOV=3.141592654/4;   /* half of the xy field of view */

/*
// Draw the view from the point x0,y0 (16.16) looking at angle a
*/
void View(int x0,int y0,float aa,SDL_Surface *screen)
{
  int d;
  int a,b,h,u0,v0,u1,v1,h0,h1,h2,h3;

  /* Clear offscreen buffer */
  memset(Video,0,320*200);

  /* Initialize last-y and last-color arrays */
  for ( d=0; d<320; d++ )
  {
    lasty[d]=200;
    lastc[d]=-1;
  }

  /* Compute viewpoint height value */

  /* Compute the xy coordinates; a and b will be the position inside the
     single map cell (0..255).
   */
  u0=(x0>>16)&0xFF;    a=(x0>>8)&255;
  v0=((y0>>8)&0xFF00); b=(y0>>8)&255;
  u1=(u0+1)&0xFF;
  v1=(v0+256)&0xFF00;

  /* Fetch the height at the four corners of the square the point is in */
  h0=HMap[u0+v0]; h2=HMap[u0+v1];
  h1=HMap[u1+v0]; h3=HMap[u1+v1];

  /* Compute the height using bilinear interpolation */
  h0=(h0<<8)+a*(h1-h0);
  h2=(h2<<8)+a*(h3-h2);
  h=((h0<<8)+b*(h2-h0))>>16;

  /* Draw the landscape from near to far without overdraw */
  for ( d=0; d<100; d+=1+(d>>6) )
  {
    Line(x0+d*65536*cos(aa-FOV),y0+d*65536*sin(aa-FOV),
         x0+d*65536*cos(aa+FOV),y0+d*65536*sin(aa+FOV),
         h-30,100*256/(d+1));
  }

  /* Blit the final image to the screen */
  if ( SDL_LockSurface(screen) == 0 ) {
    int row;
    Uint8 *src, *dst;

    src = Video;
    dst = (Uint8 *)screen->pixels;
    for ( row=screen->h; row>0; --row )
    {
      memcpy(dst, src, 320);
      src += 320;
      dst += screen->pitch;
    }
    SDL_UnlockSurface(screen);
  }
  SDL_UpdateRect(screen, 0, 0, 0, 0);
}

main(int argc, char *argv[])
{
  SDL_Surface *screen;
  int done;
  int i,k;
  float ss,sa,a,s;
  int x0,y0;
  SDL_Color colors[64];
  SDL_Event event;
  Uint8 *keystate;

  /* Initialize SDL */
  if ( SDL_Init(SDL_INIT_VIDEO) < 0 )
  {
    fprintf(stderr, "Couldn't initialize SDL: %s\n", SDL_GetError());
    exit(1);
  }
  atexit(SDL_Quit);

  /* Enter 320x200x256 mode */
  screen = SDL_SetVideoMode(320, 200, 8,
			(SDL_HWSURFACE|SDL_HWPALETTE|SDL_FULLSCREEN));
  if ( screen == NULL )
  {
    fprintf(stderr, "Couldn't init video mode: %s\n", SDL_GetError());
    exit(1);
  }

  /* Set up the first 64 colors to a grayscale */
  for ( i=0; i<64; i++ )
  {
    colors[i].r = i*4;
    colors[i].g = i*4;
    colors[i].b = i*4;
  }
  SDL_SetColors(screen, colors, 0, 64);

  /* Compute the height map */
  ComputeMap();


  /* Main loop
    
       a     = angle
       x0,y0 = current position
       s     = speed constant
       ss    = current forward/backward speed
       sa    = angular speed
   */
  done=0;
  a=0; k=x0=y0=0;
  s=1024; /*s=4096;*/
  ss=0; sa=0;
  while(!done)
  {
    /* Draw the frame */
    View(x0,y0,a,screen);

    /* Update position/angle */
    x0+=ss*cos(a); y0+=ss*sin(a);
    a+=sa;

    /* Slowly reset the angle to 0 */
    if ( sa != 0 )
    {
      if ( sa < 0 )
        sa += 0.001;
      else
        sa -= 0.001;
    }

    /* User input */
    while ( SDL_PollEvent(&event) )
    {
      if ( event.type == SDL_QUIT )
      {
          done = 1;
      }
    }
    keystate = SDL_GetKeyState(NULL);
    if ( keystate[SDLK_ESCAPE] ) {
      done = 1;
    }
    if ( keystate[SDLK_UP] ) {
      ss+=s;
    }
    if ( keystate[SDLK_DOWN] ) {
      ss-=s;
    }
    if ( keystate[SDLK_RIGHT] ) {
      sa+=0.003;
    }
    if ( keystate[SDLK_LEFT] ) {
      sa-=0.003;
    }
  }

  /* Exit to text mode */
  exit(0);
}
