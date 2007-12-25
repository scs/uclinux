/*
  Written by Bini Michele <mibin@tin.it>, 1998
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "SDL.h"
#include <math.h>
#include <time.h>

#ifndef PI
#define PI	3.14159265358979323846
#endif

#if 0
#define VIDEOX 320
#define VIDEOY 200
#define TABLEX VIDEOX*2
#define TABLEY VIDEOY*2
#else
static int VIDEOX;
static int VIDEOY;
static int TABLEX;
static int TABLEY;
#endif

#define TONES 256

static void do_plasma(SDL_Surface*surface,
	       double x1,
	       double y1,
	       double x2,
	       double y2,
	       double x3,
	       double y3,
	       unsigned char*t)
{
  unsigned int
    X1=x1*(TABLEX/2),
    Y1=y1*(TABLEY/2),
    X2=x2*(TABLEX/2),
    Y2=y2*(TABLEY/2),
    X3=x3*(TABLEX/2),
    Y3=y3*(TABLEY/2);
  unsigned int y;
  unsigned char *t1=t+X1+Y1*TABLEX, *t2=t+X2+Y2*TABLEX, *t3=t+X3+Y3*TABLEX;
  for (y=0; y<VIDEOY; y++) {
    unsigned x;
    unsigned char*tmp= ((Uint8*)surface->pixels) + y * surface->pitch;
    unsigned int t=y*TABLEX, tmax=t+VIDEOX;
    for (x=0; t<tmax; t++, tmp++) {
      tmp[0]=t1[t]+t2[t]+t3[t];
    }
  }
}

int main (int argc, char **argv)
{
  Uint32 video_flags;
  double r[3];
  double R[6];
  SDL_Surface *screen;
  SDL_Color colors[TONES*2];
  unsigned char *t;
  time_t starttime;
  int i, state=0;
  SDL_Rect **modes;
 
  VIDEOX=640;
  VIDEOY=480;
 
  /* randomized stuff */
  srand(time(NULL));
  {
    int c;
    for (c=0; c<3; c++)
      r[c]=((double)(rand()%1000+1))/300000;
    for (c=0; c<6; c++)
      R[c]=((double)(rand()%1000+1))/5000;
  }

  /* Inizialize the SDL library */
  if ( SDL_Init(SDL_INIT_VIDEO) < 0 ) {
    fprintf(stderr, "Couldn't initialize SDL: %s\n", SDL_GetError());
    return 1;
  }

  /* fire and forget... */
  atexit(SDL_Quit);
  
  video_flags = (SDL_SWSURFACE|SDL_HWPALETTE);
  for ( i=1; argv[i]; ++i ) {
    if ( strcmp(argv[i], "-fullscreen") == 0 )
      video_flags |= SDL_FULLSCREEN;
    else
    if ( strcmp(argv[i], "-hw") == 0 )
      video_flags |= SDL_HWSURFACE;
    else
    if ( strcmp(argv[i], "-flip") == 0 )
      video_flags |= SDL_DOUBLEBUF;
#ifndef VIDEOX
    else
    if ( strcmp(argv[i], "-width") == 0 ) {
      if ((i+1)>argc) {
        fprintf(stderr, "too few args\n");
        return 1;
      }
      VIDEOX = atoi(argv[i+1]);
      i++;
    }
#endif
#ifndef VIDEOY
    else
    if ( strcmp(argv[i], "-height") == 0 ) {
      if ((i+1)>argc) {
        fprintf(stderr, "too few args\n");
        return 1;
      }
      VIDEOY = atoi(argv[i+1]);
      i++;
    }
#endif
  }

  printf("trying %i x %i\n", VIDEOX, VIDEOY);

  screen=SDL_SetVideoMode(VIDEOX, VIDEOY, 8, video_flags);
#ifdef VIDEOX
  if ( screen == NULL ) {
    fprintf(stderr, "Couldn't initialize video mode: %s\n", SDL_GetError());
    return 1;
  }
#else
  if ( screen == NULL ) {
    screen = SDL_SetVideoMode(10, 10, 8, video_flags);
    if ( screen == NULL ) {
      fprintf(stderr, "Couldn't set display mode: %s\n",
                                        SDL_GetError());
      SDL_Quit();
      return 1;
    }

    /* Get available fullscreen/hardware modes */
    modes = SDL_ListModes(NULL, SDL_FULLSCREEN|SDL_SWSURFACE);
    SDL_FreeSurface(screen);

    /* Check is there are any modes available */
    if (modes == (SDL_Rect **)0) {
      printf("No modes available! \n");
      SDL_Quit();
      return 1;
    }

    /* Check if or resolution is restricted */
    if (modes == (SDL_Rect **) - 1) {
      printf("All resolutions available. \n");
      SDL_Quit();
      return 1;
    } else {
     /* Print valid modes */
     printf("Available Modes \n");
       for (i = 0; modes[i]; ++i)
         printf("  %d x %d\n", modes[i]->w, modes[i]->h);
       screen = SDL_SetVideoMode(modes[i-1]->w, modes[i-1]->h, 8, video_flags);
       if ( screen == NULL ) {
         fprintf(stderr, "Couldn't set %i x %i: %s\n",
                      modes[i-1]->w, modes[i-1]->h,SDL_GetError());
         return 1;
      }
      VIDEOX=modes[i-1]->w;
      VIDEOY=modes[i-1]->h;
    }
  }
#endif

  TABLEX=VIDEOX*2;
  TABLEY=VIDEOY*2;

  printf("Precalculating table...\n");
  t = (unsigned char *)malloc(TABLEY*TABLEX);
  if ( t == NULL ) {
    fprintf(stderr, "Out of memory\n");
    exit(1);
  }
  {
    int y;
    for (y=0 ; y<TABLEY ; y++) {
      int x;
      for (x=0 ; x<TABLEX ; x++) {
        double tmp=(((double)((x-(TABLEX/2))*(x-(TABLEX/2))+(y-(TABLEX/2))*(y-(TABLEX/2))))
                    *(PI/(TABLEX*TABLEX+TABLEY*TABLEY)));
        t[y*TABLEX+x]=(sin(sqrt(tmp)*12)+1)*TONES/6;
      }
    }
  }


  SDL_EventState(SDL_ACTIVEEVENT, SDL_IGNORE);
  SDL_EventState(SDL_MOUSEMOTION, SDL_IGNORE);
  
  starttime=time(NULL); 

  /* Main loop */
  while (SDL_PollEvent(NULL)==0) {
    state++;
    {
      int c;
      for (c=0 ; c<TONES; c++) {
	colors[c].r=(sin(((double)c)/TONES*6*PI+r[0]*PI*state*PI)+1)*127;
	colors[c].g=(sin(((double)c)/TONES*6*PI+r[1]*state*PI)+1)*127;
	colors[c].b=(sin(((double)c)/TONES*6*PI+r[2]*state*PI)+1)*127;
      }
      SDL_SetColors(screen, colors, 0, TONES);
    }
    if (SDL_LockSurface(screen) <0 ) {
      continue;
    }
    do_plasma(screen,
	(sin(((double)state)*R[0])+1)/2,
	(sin(((double)state)*R[1])+1)/2,
	(sin(((double)state)*R[2])+1)/2,
	(sin(((double)state)*R[3])+1)/2,
	(sin(((double)state)*R[4])+1)/2,
	(sin(((double)state)*R[5])+1)/2, t);
    SDL_UnlockSurface(screen);
    SDL_Flip(screen);
  }
  printf("Frame rate: %g frames/sec\n",((double)state)/difftime(time(NULL),starttime));
  return 0;
}
