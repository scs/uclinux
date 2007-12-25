/*****************************************************************************/
/*                               XFlame v1.0                                 */
/*****************************************************************************/
/* By:                                                                       */
/*     The Rasterman (Carsten Haitzler)                                      */
/*      Copyright (C) 1996                                                   */
/*****************************************************************************/
/* Ported to SDL by:                                                         */
/*     Sam Lantinga                                                          */
/*                                                                           */
/* This is a dirty port, just to get it working on SDL.                      */
/* Improvements left to the reader:                                          */
/* 	Use depth-specific code to optimize HiColor/TrueColor display        */
/* 	Fix the delta code -- it's broken -- shame on Rasterman ;-)          */
/*                                                                           */
/*****************************************************************************/
/* This code is Freeware. You may copy it, modify it or do with it as you    */
/* please, but you may not claim copyright on any code wholly or partly      */
/* based on this code. I accept no responisbility for any consequences of    */
/* using this code, be they proper or otherwise.                             */
/*****************************************************************************/
/* Okay, now all the legal mumbo-jumbo is out of the way, I will just say    */
/* this: enjoy this program, do with it as you please and watch out for more */
/* code releases from The Rasterman running under X... the only way to code. */
/*****************************************************************************/


/* INCLUDES! */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "SDL.h"

/* DEFINES */
#define GEN 500
#define MAX 300
#define WID 80
#define HIH 60
#define HSPREAD 26
#define VSPREAD 78
#define VFALLOFF 14
#define VARIANCE 5
#define VARTREND 2
#define RESIDUAL 68

#define NONE 0x00
#define CMAP 0x02
#define DELT 0x08		/* Delta code is broken -- Rasterman? */
#define BLOK 0x20
#define LACE 0x40
/*This structure contains all of the "Global" variables for my program so */
/*that I just pass a pointer to my functions, not a million parameters */
struct globaldata
{
  Uint32 flags;
  SDL_Surface *screen;
  int nrects;
  SDL_Rect *rects;
};

void printhelp()
{
  printf("XFlame v1.0\n");
  printf("     By: The Rasterman (Carsten Haitzler)\n");
  printf("         e-mail: s2154962@cse.unsw.edu.au\n");
  printf("         web: http://www.cse.unsw.edu.au/~s2154962/\n");
  printf("     Ported to SDL by:  Sam Lantinga\n");
  printf("         e-mail: slouken@devolution.com\n");
  printf("         web: http://www.devolution.com/~slouken/\n");
  printf("     Copyright (C) 1996\n");
  printf("  Please read the DOCS!\n");
  printf("Options:\n");
  printf("  -h : Prints this help\n");
  printf("  -fullscreen : XFlame runs fullscreen if possible\n");
  printf("  -hw : XFlame draws directly to video memory if possible\n");
  printf("  -flip : XFlame uses page-flipping if possible\n");
  printf("  -cmap : XFlame uses its own colormap in its window\n");
  printf("  -nicecmap : XFlame allocates fewer colors\n");
  printf("  -block : XFlame updates the screen in one large block\n");
  printf("  -lace : XFlame updates the screen using extended interlacing\n");
  printf("  -width <w> : XFlame uses a window of width <w> pixels\n");
  printf("  -height <h> : XFlame uses a window of height <h> pixels\n");
}

void fewargs()
{
  /* If someone gives too few arguments, then tell them so! */
  printf("Toow few Arguments!\n");
  return;
}
int powerof(unsigned int n)
{
  /* This returns the power of a number (eg powerof(8)==3, powerof(256)==8, */
  /* powerof(1367)==11, powerof(2568)==12) */
  int p=32;
  if (n<=0x80000000) p=31;
  if (n<=0x40000000) p=30;
  if (n<=0x20000000) p=29;
  if (n<=0x10000000) p=28;
  if (n<=0x08000000) p=27;
  if (n<=0x04000000) p=26;
  if (n<=0x02000000) p=25;
  if (n<=0x01000000) p=24;
  if (n<=0x00800000) p=23;
  if (n<=0x00400000) p=22;
  if (n<=0x00200000) p=21;
  if (n<=0x00100000) p=20;
  if (n<=0x00080000) p=19;
  if (n<=0x00040000) p=18;
  if (n<=0x00020000) p=17;
  if (n<=0x00010000) p=16;
  if (n<=0x00008000) p=15;
  if (n<=0x00004000) p=14;
  if (n<=0x00002000) p=13;
  if (n<=0x00001000) p=12;
  if (n<=0x00000800) p=11;
  if (n<=0x00000400) p=10;
  if (n<=0x00000200) p=9;
  if (n<=0x00000100) p=8;
  if (n<=0x00000080) p=7;
  if (n<=0x00000040) p=6;
  if (n<=0x00000020) p=5;
  if (n<=0x00000010) p=4;
  if (n<=0x00000008) p=3;
  if (n<=0x00000004) p=2;
  if (n<=0x00000002) p=1;
  if (n<=0x00000001) p=0;
  return p;
}

int OpenDisp(void)
{
  if ( SDL_Init(SDL_INIT_VIDEO) < 0 )
	return(0);
  atexit(SDL_Quit);
  return(1);
}

int OpenWindow(struct globaldata *g,int w,int h)
{
  g->screen = SDL_SetVideoMode(w, h, 8, g->flags);
  if (g->screen == NULL)
    {
      return 0;
    }
  return 1;
}

void
SetFlamePalette(struct globaldata *gb, int f,int *ctab)
{
  /*This function sets the flame palette */
  int r,g,b,i;
  SDL_Color cmap[MAX];
  
  /* This step is only needed on palettized screens */
  r = g = b = 0;
  for (i=0; (r != 255) || (g != 255) || (b != 255); i++)
    {
      r=i*3;
      g=(i-80)*3;
      b=(i-160)*3;
      if (r<0) r=0;
      if (r>255) r=255;
      if (g<0) g=0;
      if (g>255) g=255;
      if (b<0) b=0;
      if (b>255) b=255;
      cmap[i].r = r;
      cmap[i].g = g;
      cmap[i].b = b;
    }
  SDL_SetColors(gb->screen, cmap, 0, i);

  /* This step is for all depths */
  for (i=0;i<MAX;i++)
    {
      r=i*3;
      g=(i-80)*3;
      b=(i-160)*3;
      if (r<0) r=0;
      if (r>255) r=255;
      if (g<0) g=0;
      if (g>255) g=255;
      if (b<0) b=0;
      if (b>255) b=255;
      ctab[i]=SDL_MapRGB(gb->screen->format, (Uint8)r, (Uint8)g, (Uint8)b);
    }
}

void
XFSetRandomFlameBase(int *f, int w, int ws, int h)
{
  /*This function sets the base of the flame to random values */
  int x,y,*ptr;
  
  /* initialize a random number seed from the time, so we get random */
  /* numbers each time */
  srand(time(NULL));
  y=h-1;
  for (x=0;x<w;x++)
    {
      ptr=f+(y<<ws)+x;
      *ptr=rand()%MAX;
    }
}

void
XFModifyFlameBase(int *f, int w, int ws, int h)
{
  /*This function modifies the base of the flame with random values */
  int x,y,*ptr,val;
  
  y=h-1;
  for (x=0;x<w;x++)
    {
      ptr=f+(y<<ws)+x;
      *ptr+=((rand()%VARIANCE)-VARTREND);
      val=*ptr;
      if (val>MAX) *ptr=0;
      if (val<0) *ptr=0;
    }
}

void
XFProcessFlame(int *f, int w, int ws, int h, int *ff)
{
  /*This function processes entire flame array */
  int x,y,*ptr,*p,tmp,val;
  
  for (y=(h-1);y>=2;y--)
    {
      for (x=1;x<(w-1);x++)
	{
	  ptr=f+(y<<ws)+x;
	  val=(int)*ptr;
	  if (val>MAX) *ptr=(int)MAX;
	  val=(int)*ptr;
	  if (val>0)
	    {
	      tmp=(val*VSPREAD)>>8;
	      p=ptr-(2<<ws);				
	      *p=*p+(tmp>>1);
	      p=ptr-(1<<ws);				
	      *p=*p+tmp;
	      tmp=(val*HSPREAD)>>8;
	      p=ptr-(1<<ws)-1;
	      *p=*p+tmp;
	      p=ptr-(1<<ws)+1;
	      *p=*p+tmp;
	      p=ptr-1;
	      *p=*p+(tmp>>1);
	      p=ptr+1;
	      *p=*p+(tmp>>1);
	      p=ff+(y<<ws)+x;
	      *p=val;
	      if (y<(h-1)) *ptr=(val*RESIDUAL)>>8;
	    }
	}
    }
}

void
XFDrawFlameBLOK(struct globaldata *g,int *f, int w, int ws, int h, int *ctab)
{
  /*This function copies & displays the flame image in one large block */
  int x,y,*ptr,xx,yy,cl,cl1,cl2,cl3,cl4;
  unsigned char *cptr,*im,*p;
  
  /* get pointer to the image data */
  if ( SDL_LockSurface(g->screen) < 0 )
    return;

  /* copy the calculated flame array to the image buffer */
  im=(unsigned char *)g->screen->pixels;
  for (y=0;y<(h-1);y++)
    {
      for (x=0;x<(w-1);x++)
	{
	  xx=x<<1;
	  yy=y<<1;
	  ptr=f+(y<<ws)+x;
	  cl1=cl=(int)*ptr;
	  ptr=f+(y<<ws)+x+1;
	  cl2=(int)*ptr;
	  ptr=f+((y+1)<<ws)+x+1;
	  cl3=(int)*ptr;
	  ptr=f+((y+1)<<ws)+x;
	  cl4=(int)*ptr;
	  cptr=im+yy*g->screen->pitch+xx;
	  *cptr=(unsigned char)ctab[cl%MAX];
	  p=cptr+1;
	  *p=(unsigned char)ctab[((cl1+cl2)>>1)%MAX];
	  p=cptr+1+g->screen->pitch;
	  *p=(unsigned char)ctab[((cl1+cl3)>>1)%MAX];
	  p=cptr+g->screen->pitch;
	  *p=(unsigned char)ctab[((cl1+cl4)>>1)%MAX];
	}
    }
  SDL_UnlockSurface(g->screen);

  /* copy the image to the screen in one large chunk */
  SDL_Flip(g->screen);
}

static void
XFUpdate(struct globaldata *g)
{
	if ( (g->screen->flags & SDL_DOUBLEBUF) == SDL_DOUBLEBUF ) {
		SDL_Flip(g->screen);
	} else {
  		SDL_UpdateRects(g->screen, g->nrects, g->rects);
	}
}

void
XFDrawFlameLACE(struct globaldata *g,int *f, int w, int ws, int h, int *ctab)
{
  /*This function copies & displays the flame image in interlaced fashion */
  /*that it, it first processes and copies the even lines to the screen, */
  /* then is processes and copies the odd lines of the image to the screen */
  int x,y,*ptr,xx,yy,cl,cl1,cl2,cl3,cl4;
  unsigned char *cptr,*im,*p;
  
  /* get pointer to the image data */
  if ( SDL_LockSurface(g->screen) < 0 )
    return;

  /* copy the calculated flame array to the image buffer */
  im=(unsigned char *)g->screen->pixels;
  for (y=0;y<(h-1);y++)
    {
      for (x=0;x<(w-1);x++)
	{
	  xx=x<<1;
	  yy=y<<1;
	  ptr=f+(y<<ws)+x;
	  cl1=cl=(int)*ptr;
	  ptr=f+(y<<ws)+x+1;
	  cl2=(int)*ptr;
	  ptr=f+((y+1)<<ws)+x+1;
	  cl3=(int)*ptr;
	  ptr=f+((y+1)<<ws)+x;
	  cl4=(int)*ptr;
	  cptr=im+yy*g->screen->pitch+xx;
	  *cptr=(unsigned char)ctab[cl%MAX];
	  p=cptr+1;
	  *p=(unsigned char)ctab[((cl1+cl2)>>1)%MAX];
	  p=cptr+1+g->screen->pitch;
	  *p=(unsigned char)ctab[((cl1+cl3)>>1)%MAX];
	  p=cptr+g->screen->pitch;
	  *p=(unsigned char)ctab[((cl1+cl4)>>1)%MAX];
	}
    }
  SDL_UnlockSurface(g->screen);

  /* copy the even lines to the screen */
  w <<= 1;
  h <<= 1;
  g->nrects = 0;
  for (y=0;y<(h-1);y+=4)
    {
      g->rects[g->nrects].x = 0;
      g->rects[g->nrects].y = y;
      g->rects[g->nrects].w = w;
      g->rects[g->nrects].h = 1;
      ++g->nrects;
    }
  XFUpdate(g);
  /* copy the odd lines to the screen */
  g->nrects = 0;
  for (y=2;y<(h-1);y+=4)
    {
      g->rects[g->nrects].x = 0;
      g->rects[g->nrects].y = y;
      g->rects[g->nrects].w = w;
      g->rects[g->nrects].h = 1;
      ++g->nrects;
    }
  XFUpdate(g);
  /* copy the even lines to the screen */
  g->nrects = 0;
  for (y=1;y<(h-1);y+=4)
    {
      g->rects[g->nrects].x = 0;
      g->rects[g->nrects].y = y;
      g->rects[g->nrects].w = w;
      g->rects[g->nrects].h = 1;
      ++g->nrects;
    }
  XFUpdate(g);
  /* copy the odd lines to the screen */
  g->nrects = 0;
  for (y=3;y<(h-1);y+=4)
    {
      g->rects[g->nrects].x = 0;
      g->rects[g->nrects].y = y;
      g->rects[g->nrects].w = w;
      g->rects[g->nrects].h = 1;
      ++g->nrects;
    }
  XFUpdate(g);
}

void
XFDrawFlame(struct globaldata *g,int *f, int w, int ws, int h, int *ctab)
{
  /*This function copies & displays the flame image in interlaced fashion */
  /*that it, it first processes and copies the even lines to the screen, */
  /* then is processes and copies the odd lines of the image to the screen */
  int x,y,*ptr,xx,yy,cl,cl1,cl2,cl3,cl4;
  unsigned char *cptr,*im,*p;
  
  /* get pointer to the image data */
  if ( SDL_LockSurface(g->screen) < 0 )
    return;

  /* copy the calculated flame array to the image buffer */
  im=(unsigned char *)g->screen->pixels;
  for (y=0;y<(h-1);y++)
    {
      for (x=0;x<(w-1);x++)
	{
	  xx=x<<1;
	  yy=y<<1;
	  ptr=f+(y<<ws)+x;
	  cl1=cl=(int)*ptr;
	  ptr=f+(y<<ws)+x+1;
	  cl2=(int)*ptr;
	  ptr=f+((y+1)<<ws)+x+1;
	  cl3=(int)*ptr;
	  ptr=f+((y+1)<<ws)+x;
	  cl4=(int)*ptr;
	  cptr=im+yy*g->screen->pitch+xx;
	  *cptr=(unsigned char)ctab[cl%MAX];
	  p=cptr+1;
	  *p=(unsigned char)ctab[((cl1+cl2)>>1)%MAX];
	  p=cptr+1+g->screen->pitch;
	  *p=(unsigned char)ctab[((cl1+cl3)>>1)%MAX];
	  p=cptr+g->screen->pitch;
	  *p=(unsigned char)ctab[((cl1+cl4)>>1)%MAX];
	}
    }
  SDL_UnlockSurface(g->screen);

  /* copy the even lines to the screen */
  w <<= 1;
  h <<= 1;
  g->nrects = 0;
  for (y=0;y<(h-1);y+=2)
    {
      g->rects[g->nrects].x = 0;
      g->rects[g->nrects].y = y;
      g->rects[g->nrects].w = w;
      g->rects[g->nrects].h = 1;
      ++g->nrects;
    }
  XFUpdate(g);
  /* copy the odd lines to the screen */
  g->nrects = 0;
  for (y=1;y<(h-1);y+=2)
    {
      g->rects[g->nrects].x = 0;
      g->rects[g->nrects].y = y;
      g->rects[g->nrects].w = w;
      g->rects[g->nrects].h = 1;
      ++g->nrects;
    }
  XFUpdate(g);
}

int Xflame(struct globaldata *g,int w, int h, int f, int *ctab)
{
  int done;
  SDL_Event event;

  /*This function is the hub of XFlame.. it initialises the flame array, */
  /*processes the array, genereates the flames and displays them */
  int *flame,flamesize,ws,flamewidth,flameheight,*flame2;
  
  /* workout the size needed for the flame array */
  flamewidth=w>>1;
  flameheight=h>>1;
  ws=powerof(flamewidth);
  flamesize=(1<<ws)*flameheight*sizeof(int);
  /* allocate the memory for the flame array */
  flame=(int *)malloc(flamesize);
  /* if we didn't get the memory, return 0 */
  if (!flame) return 0;
  memset(flame, 0, flamesize);
  /* allocate the memory for the second flame array */
  flame2=(int *)malloc(flamesize);
  /* if we didn't get the memory, return 0 */
  if (!flame2) return 0;
  memset(flame2, 0, flamesize);
  if (f&BLOK)
    {
      g->rects = NULL;
    }
  else if (f&LACE)
    {
      /* allocate the memory for update rectangles */
      g->rects=(SDL_Rect *)malloc((h>>2)*sizeof(SDL_Rect));
      /* if we couldn't get the memory, return 0 */
      if (!g->rects) return 0;
    }
  else
    {
      /* allocate the memory for update rectangles */
      g->rects=(SDL_Rect *)malloc((h>>1)*sizeof(SDL_Rect));
      /* if we couldn't get the memory, return 0 */
      if (!g->rects) return 0;
    }
  /* set the base of the flame to something random */
  XFSetRandomFlameBase(flame,w>>1,ws,h>>1);
  /* now loop, generating and displaying flames */
  for (done=0; !done; )
    {
      /* modify the bas of the flame */
      XFModifyFlameBase(flame,w>>1,ws,h>>1);
      /* process the flame array, propagating the flames up the array */
      XFProcessFlame(flame,w>>1,ws,h>>1,flame2);
      /* if the user selected BLOCK display method, then display the flame */
      /* all in one go, no fancy upating techniques involved */
      if (f&BLOK)
	{
	  XFDrawFlameBLOK(g,flame2,w>>1,ws,h>>1,ctab);
	}
      else if (f&LACE)
	{
	  XFDrawFlameLACE(g,flame2,w>>1,ws,h>>1,ctab);
	}
      else
	/* the default of displaying the flames INTERLACED */
	{
	  XFDrawFlame(g,flame2,w>>1,ws,h>>1,ctab);
	}
      /* Look for a key or quit event */
      while ( SDL_PollEvent(&event) )
        {
          if ( (event.type == SDL_KEYDOWN) || (event.type == SDL_QUIT) )
            done = 1;
        }
    }
    return(done);
}

/* Here's the MAIN part of the program */
main(int argc, char **argv)
{
  struct globaldata glob;
  char disp[256];	
  int flags;
  int width,height,i,colortab[MAX];
  
  /* Set all the variable to default values */
  strcpy(disp,":0.0");
  flags=NONE;
  width=128;
  height=128;
  
  /* Check command line for arguments */
  glob.flags = SDL_SWSURFACE;
  if (argc>1)
    {
      for (i=1;i<=argc;i++)
	{
	  /* if the user requests help */
	  if (!strcmp("-h",argv[i-1]))
	    {
	      printhelp();
	      exit(0); 
	    }
	  /* if the user requests to run on full display*/
	  if (!strcmp("-fullscreen",argv[i-1]))
	    {
              glob.flags |= SDL_FULLSCREEN;
	    }
	  /* if the user requests drawing on video memory */
	  if (!strcmp("-hw",argv[i-1]))
	    {
              glob.flags |= SDL_HWSURFACE;
	    }
	  /* if the user requests double-buffering */
	  if (!strcmp("-flip",argv[i-1]))
	    {
              glob.flags |= SDL_DOUBLEBUF;
	    }
	  /* if the user requests to run with own colormap*/
	  if (!strcmp("-cmap",argv[i-1]))
	    {
              glob.flags |= SDL_HWPALETTE;
	      flags|=CMAP;
	    }
	  /* if the user requests to use Lace updating of the image */
	  if (!strcmp("-lace",argv[i-1]))
	    {
	      flags|=LACE;
	    }
	  /* if the user requests to use Block updating of the image */
	  if (!strcmp("-block",argv[i-1]))
	    {
	      flags|=BLOK;
	    }
	  /* if the user requests a particular width */
	  if (!strcmp("-width",argv[i-1]))
	    {
	      if ((i+1)>argc)
		{
		  fewargs();
		  exit(1);
		}
	      width=atoi(argv[i]);
	      if (width<16)
		{
		  width=16;
		}
	      i++;
	    }
	  /* if the user requests a particular height */
	  if (!strcmp("-height",argv[i-1]))
	    {
	      if ((i+1)>argc)
		{
		  fewargs();
		  exit(1);
		}
	      height=atoi(argv[i]);
	      if (height<16)
		{
		  height=16;
		}
	      i++;
	    }
	}
    }
  if (!OpenDisp())
    {
      printf("Could not initialize SDL: %s\n",SDL_GetError());
      exit(1);
    }
  if (!OpenWindow(&glob,width,height))
    {
      exit(1);
    }
  /* if the user requested a CLEAN display method, set the window up */
  /* accordingly with backign store, saveunders etc.) */

 /* Set up the palette for the flame according to user flags */
  SetFlamePalette(&glob,flags,colortab);

  /* Start displaying the flame!*/
  if (!Xflame(&glob,glob.screen->w,glob.screen->h,flags,colortab))
    {
      /* if Xflame returned 0, it encountered an error in allocating memory */
      printf("Not enough memory to allocate to the flame arrays\n");
      exit(1);
    }
  exit(0);
}

