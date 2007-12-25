/*
  Thanks go to Federico 'pix' Feroldi for the original
  water algorithm idea...

  Some optimizations added by Jason Hood.

  I hope no one minds looking at my messy code...  It's really messy.
  (in my opinion, anyway)  It hasn't been properly commented/documented
  yet, either...  When it's properly documented, it'll be on my web site:
    http://www.xyzz.org/

  Use the makefile...
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SDL.h"
#include "datatype.h"
#include "fixsin.h"
#include "fps.h"


#define WATERWID 320
#define WATERHGT 200


/* The Height field...  Two pages, so that the filter will work correctly */
int Height[2][WATERWID * WATERHGT];

/* Yes, I've got three copies of the background, all next to each other.
   Press 's' a bunch of times to see why...
 */
static byte BkGdImagePre[WATERWID * WATERHGT];
static byte BkGdImage[WATERWID * WATERHGT];
static byte BkGdImagePost[WATERWID * WATERHGT];

byte *bufptr;

char HelpMessage[] =
{
  "Controls are:      (you may use any background: \"water file.bmp\")\n"
  "\t?\tHelp...\n"
  "\t`\tPause\n"
  "Automatic effects:\n"
  "\t1\tToggle Surfer mode\n"
  "\t2\tToggle Rain mode\n"
  "\t3\tToggle Blob mode...\n"
  "\t4\tToggle \"swirly\" mode...\n"
  "\tb/B\tTurn on \"bump\" mode...\n"
  "\t<space>\tTurn off effects 1-4 and b\n"
  "Manual effects:\n"
  "\tMouse\tMake blobs (button 1 and button 2 are different)\n"
  "\t6\tMake a large waterdrop\n"
  "\t7\tMake a large waterdrop in the center\n"
  "\tz\tDistort / exaggerate the water\n"
  "Physics:\n"
  "\td/D\tDecrease / Increase water density\n"
  "\th/H\tDecrease / Increase splash height\n"
  "\tr/R\tDecrease / Increase waterdrop radius\n"
  "\tm\tToggle the water \"movement\"\n"
  "\tl/L\tChange the light level (Off, 100%%, 50%%, 25%%, ...)\n"
  "\tw/j/s/S\tSet physics for water/jelly/sludge/SuperSludge material...\n"
};


void water(SDL_Surface *image, SDL_Surface *screen);

void help(void);

void DrawWaterNoLight(int page);
void DrawWaterWithLight(int page, int LightModifier);
void CalcWater(int npage, int density);
void SmoothWater(int npage);

void HeightBlob(int x, int y, int radius, int height, int page);
void HeightBox (int x, int y, int radius, int height, int page);

void WarpBlob(int x, int y, int radius, int height, int page);
void SineBlob(int x, int y, int radius, int height, int page);


main(int argc, char **argv)
{
  SDL_Surface *screen;
  char *imagefile;
  SDL_Surface *image;
  SDL_Palette *palette;

  if (SDL_Init(SDL_INIT_VIDEO)<0)
  {
    printf("Couldn't init SDL: %s\n", SDL_GetError());
    exit(1);
  }
  atexit(SDL_Quit);

  /* start the random number generator */
  randomize();

  /* load a user-specified picture, or load the default picture */
  if(argv[1])
    imagefile = argv[1];
  else
    imagefile = "water320.bmp";
  image = SDL_LoadBMP(imagefile);
  if (image == NULL)
  {
    printf("Couldn't load %s: %s\n", imagefile, SDL_GetError());
    exit(1);
  }
  palette = image->format->palette;
  if ((image->format->BitsPerPixel != 8) || (palette == NULL))
  {
    printf("Image must be 8-bit and have a palette\n");
    exit(1);
  }
  if ((image->w != WATERWID) || (image->h != WATERHGT))
  {
    printf("Image must be %dx%d in size\n", WATERWID, WATERHGT);
    exit(1);
  }

  printf(HelpMessage);

  /* Set up my 16.16 x 2048 degree sine tables... */
  FCreateSines();

  /* Set the video mode and palette */
  screen = SDL_SetVideoMode(WATERWID,WATERHGT,8,
			(SDL_HWSURFACE|SDL_HWPALETTE|SDL_FULLSCREEN));
  if (screen == NULL)
  {
    printf("Couldn't set video mode: %s\n", SDL_GetError());
    exit(1);
  }
  /* Fill the extra palette entries with white and set the display palette */
  {
    int nwhite;
      
    nwhite = 256-palette->ncolors;
    memset(&palette->colors[palette->ncolors], 255, nwhite*sizeof(SDL_Color));
    SDL_SetColors(screen, palette->colors, 0, 256);
  }

  water(image, screen);
  SDL_FreeSurface(image);

  ShowFps();
}


void water(SDL_Surface *image, SDL_Surface *screen)
{
  int Hpage = 0;
  int xang, yang;
  int swirlangle;
  int x, y, ox = 80, oy = 60;
  int done = 0;
  int mode=0x4000;
  int density = 4, pheight = 400, radius = 30;
  SDL_Event event;
  int mouse_x, mouse_y;

  int movement=1;
  int light=1;

  int offset;


  xang = rand()%2048;
  yang = rand()%2048;
  swirlangle = rand()%2048;

  memset(Height[0], 0, sizeof(int)*WATERWID*WATERHGT);
  memset(Height[1], 0, sizeof(int)*WATERWID*WATERHGT);


  bufptr = (unsigned char*)image->pixels;
  memcpy(BkGdImagePre,  bufptr, WATERWID*WATERHGT);
  memcpy(BkGdImage,     bufptr, WATERWID*WATERHGT);
  memcpy(BkGdImagePost, bufptr, WATERWID*WATERHGT);

  FpsStart();

  done = 0;
  SDL_EnableUNICODE(1);		/* Enable keycode translations */
  while(!done)
  {
    while (SDL_PollEvent(&event))
    {
      switch(event.type)
      {
        case SDL_QUIT: {
          done = 1;
        }
        break;
        /* The main "interface" */
        case SDL_KEYDOWN: {
          switch(event.key.keysym.unicode)
          {
            case 'd': density--; break;
            case 'D': density++; break;

            case 'h': pheight-=40; break;
            case 'H': pheight+=40; break;

            case 'r': radius++; break;
            case 'R': radius--; break;

            case 'l': light++; break;
            case 'L': if(light>0) light--; break;

            case 'c': memset(Height[0], 0, sizeof(int)*WATERWID*WATERHGT);
                      memset(Height[1], 0, sizeof(int)*WATERWID*WATERHGT);
                      break;
            case 'z': if(movement)
                        memset(Height[Hpage], 0, sizeof(int)*WATERWID*WATERHGT);
                      else
                        SmoothWater(Hpage);
                      break;

            case 'w':
            case 'W': mode=mode | 0x4000;
                      density=4; light=1; pheight=600;
                      break;
            case 'j':
            case 'J': mode=mode & 0xbfff;
                      density=3; pheight=400;
                      break;
            case 's': density=6; pheight=400;
                      mode=mode & 0xbfff;
                      break;
            case 'S': density=8; pheight=400;
                      mode=mode & 0xbfff;
                      break;
            case 'b': mode = mode & (0xbfff - 4);  mode ^= 4;
                      density=4; pheight=1400; radius=80;
                      break;
            case 'B': mode = mode & (0xbfff - 4);  mode ^= 4;
                      density=4; pheight = -1400; radius=80;
                      break;


            case 'm':
            case 'M': movement ^= 1;
              if(movement)
              {
                pheight=400;
              }
              else
              {
                pheight=256;
              }
              break;

/* Each bit of the mode variable is used to represent the state of a
   different option that can be turned on or off...  */
            case '1': mode ^= 1; break;
            case '2': mode ^= 2; break;
            case '3': mode ^= 4; break;
            case '4': mode ^= 8; if(mode&8) {xang=0; yang=0;} break;

            case ' ': mode &= 0x4000; break;

            case '6':
              HeightBlob(-1, -1, rand()%(radius/2)+2, pheight, Hpage);
              break;

            case '7':
              HeightBlob(WATERWID/2, WATERHGT/2, radius/2, pheight, Hpage);
              break;

            case '8':
              HeightBox(WATERWID/2, WATERHGT/2, radius/2, pheight, Hpage);
              break;

            case '`': /* pause */ break;
            case '?': help(); break;
            case 27: done = 1; break;
          }
        }
        break;
      }
    }

    switch(SDL_GetMouseState(&mouse_x, &mouse_y))
    {
      case SDL_BUTTON(1):
       if(mode & 0x4000)
         HeightBlob(mouse_x-((320-WATERWID)/2), mouse_y-((200-WATERHGT)/2), 2, pheight, Hpage);
       else if(movement)
         SineBlob(mouse_x-((320-WATERWID)/2), mouse_y-((200-WATERHGT)/2), radius, -pheight, Hpage);
       else
         SineBlob(mouse_x-((320-WATERWID)/2), mouse_y-((200-WATERHGT)/2), radius, -pheight, Hpage);
       break;
      case SDL_BUTTON(3):
       if(mode & 0x4000)
         HeightBlob(mouse_x-((320-WATERWID)/2), mouse_y-((200-WATERHGT)/2), radius/2, pheight, Hpage);
       else if(movement)
         SineBlob(mouse_x-((320-WATERWID)/2), mouse_y-((200-WATERHGT)/2), radius, pheight, Hpage);
       else
         SineBlob(mouse_x-((320-WATERWID)/2), mouse_y-((200-WATERHGT)/2), radius, pheight, Hpage);
       break;
    }

  /*  The surfer... */
    if(mode&1)
    {
        x = (WATERWID/2)
          + ((
             (
              (FSin( (xang* 65) >>8) >>8) *
              (FSin( (xang*349) >>8) >>8)
             ) * ((WATERWID-8)/2)
            ) >> 16);
        y = (WATERHGT/2)
          + ((
             (
              (FSin( (yang*377) >>8) >>8) *
              (FSin( (yang* 84) >>8) >>8)
             ) * ((WATERHGT-8)/2)
            ) >> 16);
        xang += 13;
        yang += 12;

       if(mode & 0x4000)
       {
        offset = (oy+y)/2*WATERWID + (ox+x)/2;
        Height[Hpage][offset] = pheight;
        Height[Hpage][offset + 1] =
        Height[Hpage][offset - 1] =
        Height[Hpage][offset + WATERWID] =
        Height[Hpage][offset - WATERWID] = pheight >> 1;

        offset = y*WATERWID + x;
        Height[Hpage][offset] = pheight<<1;
        Height[Hpage][offset + 1] =
        Height[Hpage][offset - 1] =
        Height[Hpage][offset + WATERWID] =
        Height[Hpage][offset - WATERWID] = pheight;
       }
       else
       {
        SineBlob((ox+x)/2, (oy+y)/2, 3, -1200, Hpage);
        SineBlob(x, y, 4, -2000, Hpage);
       }

        ox = x;
        oy = y;
    }
  /* The raindrops... */
    if(mode&2)
    {
        x = rand()%(WATERWID-2) + 1;
        y = rand()%(WATERHGT-2) + 1;
        Height[Hpage][y*WATERWID + x] = rand()%(pheight<<2);
    }
  /* The big splashes... */
    if(mode&4)
    {
      if(rand()%20 == 0)
      {
        if(mode & 0x4000)
          HeightBlob(-1, -1, radius/2, pheight, Hpage);
        else
          SineBlob(-1, -1, radius, -pheight*6, Hpage);
      }
    }
  /*  The surfer (2) ... Swirling effect */
    if(mode&8)
    {
        x = (WATERWID/2)
          + ((
             (FCos(swirlangle)) * (25)
            ) >> 16);
        y = (WATERHGT/2)
          + ((
             (FSin(swirlangle)) * (25)
            ) >> 16);
        swirlangle += 50;
        if(mode & 0x4000)
          HeightBlob(x,y, radius/3, pheight, Hpage);
        else
          WarpBlob(x, y, radius, pheight, Hpage);
    }

    if(light)
      DrawWaterWithLight(Hpage, light-1);
    else
      DrawWaterNoLight(Hpage);

    if(movement)
      CalcWater(Hpage^1, density);
    else
      memcpy(&Height[Hpage^1][0], &Height[Hpage][0], sizeof(int)*WATERWID*WATERHGT);


    Hpage ^= 1;

    /* Draw the image like a sprite... */
    frames++;
    SDL_BlitSurface(image, NULL, screen, NULL);
    SDL_UpdateRect(screen, 0, 0, 0, 0);
  }

  FpsEnd();
}

void DrawWaterNoLight(int page)
{

  int dx, dy;
  int x, y;
  int c;

  int offset=WATERWID + 1;

  int *ptr = &Height[page][0];

  for (y = (WATERHGT-1)*WATERWID; offset < y; offset += 2)
  {
    for (x = offset+WATERWID-2; offset < x; offset++)
    {
      dx = ptr[offset] - ptr[offset+1];
      dy = ptr[offset] - ptr[offset+WATERWID];
      c = BkGdImage[offset + WATERWID*(dy>>3) + (dx>>3)];

     /* If anyone knows a better/faster way to do this, please tell me... */
      bufptr[offset] = (c < 0) ? 0 : (c > 255) ? 255 : c;

      offset++;
      dx = ptr[offset] - ptr[offset+1];
      dy = ptr[offset] - ptr[offset+WATERWID];
      c = BkGdImage[offset + WATERWID*(dy>>3) + (dx>>3)];
      bufptr[offset] = (c < 0) ? 0 : (c > 255) ? 255 : c;
 
    }
  }
}

void DrawWaterWithLight(int page, int LightModifier)
{

  int dx, dy;
  int x, y;
  int c;

  int offset=WATERWID + 1;

  int *ptr = &Height[page][0];


  for (y = (WATERHGT-1)*WATERWID; offset < y; offset += 2)
  {
    for (x = offset+WATERWID-2; offset < x; offset++)
    {
      dx = ptr[offset] - ptr[offset+1];
      dy = ptr[offset] - ptr[offset+WATERWID];

      c = BkGdImage[offset + WATERWID*(dy>>3) + (dx>>3)] - (dx>>LightModifier);

     /* If anyone knows a better/faster way to do this, please tell me... */
      bufptr[offset] = (c < 0) ? 0 : (c > 255) ? 255 : c;

      offset++;
      dx = ptr[offset] - ptr[offset+1];
      dy = ptr[offset] - ptr[offset+WATERWID];
      c = BkGdImage[offset + WATERWID*(dy>>3) + (dx>>3)] - (dx>>LightModifier);
      bufptr[offset] = (c < 0) ? 0 : (c > 255) ? 255 : c;
 
    }
  }
}

void CalcWater(int npage, int density)
{
  int newh;
  int count = WATERWID + 1;

  int *newptr = &Height[npage][0];
  int *oldptr = &Height[npage^1][0];

  int x, y;

  /* Sorry, this function might not be as readable as I'd like, because
     I optimized it somewhat.  (enough to make me feel satisfied with it)
   */
  for (y = (WATERHGT-1)*WATERWID; count < y; count += 2)
  {
    for (x = count+WATERWID-2; count < x; count++)
    {
/* This does the eight-pixel method.  It looks much better. */

      newh          = ((oldptr[count + WATERWID]
                      + oldptr[count - WATERWID]
                      + oldptr[count + 1]
                      + oldptr[count - 1]
                      + oldptr[count - WATERWID - 1]
                      + oldptr[count - WATERWID + 1]
                      + oldptr[count + WATERWID - 1]
                      + oldptr[count + WATERWID + 1]
                       ) >> 2 )
                      - newptr[count];


      newptr[count] =  newh - (newh >> density);
    }
  }
}
void SmoothWater(int npage)
{
  int newh;
  int count = WATERWID + 1;

  int *newptr = &Height[npage][0];
  int *oldptr = &Height[npage^1][0];

  int x, y;

  /* Sorry, this function might not be as readable as I'd like, because
     I optimized it somewhat.  (enough to make me feel satisfied with it)
   */

  for(y=1; y<WATERHGT-1; y++)
  {
    for(x=1; x<WATERWID-1; x++)
    {
/* This does the eight-pixel method.  It looks much better. */

      newh          = ((oldptr[count + WATERWID]
                      + oldptr[count - WATERWID]
                      + oldptr[count + 1]
                      + oldptr[count - 1]
                      + oldptr[count - WATERWID - 1]
                      + oldptr[count - WATERWID + 1]
                      + oldptr[count + WATERWID - 1]
                      + oldptr[count + WATERWID + 1]
                       ) >> 3 )
                      + newptr[count];


      newptr[count] =  newh>>1;
      count++;
    }
    count += 2;
  }
}

void CalcWaterBigFilter(int npage, int density)
{
  int newh;
  int count = (2*WATERWID) + 2;

  int *newptr = &Height[npage][0];
  int *oldptr = &Height[npage^1][0];

  int x, y;

  /* Sorry, this function might not be as readable as I'd like, because
     I optimized it somewhat.  (enough to make me feel satisfied with it)
   */

  for(y=2; y<WATERHGT-2; y++)
  {
    for(x=2; x<WATERWID-2; x++)
    {
/* This does the 25-pixel method.  It looks much okay. */

      newh        = (
                     (
                      (
                       (oldptr[count + WATERWID]
                      + oldptr[count - WATERWID]
                      + oldptr[count + 1]
                      + oldptr[count - 1]
                       )<<1)
                      + ((oldptr[count - WATERWID - 1]
                      + oldptr[count - WATERWID + 1]
                      + oldptr[count + WATERWID - 1]
                      + oldptr[count + WATERWID + 1]))
                      + ( (
                          oldptr[count - (WATERWID*2)]
                        + oldptr[count + (WATERWID*2)]
                        + oldptr[count - 2]
                        + oldptr[count + 2]
                        ) >> 1 )
                      + ( (
                          oldptr[count - (WATERWID*2) - 1]
                        + oldptr[count - (WATERWID*2) + 1]
                        + oldptr[count + (WATERWID*2) - 1]
                        + oldptr[count + (WATERWID*2) + 1]
                        + oldptr[count - 2 - WATERWID]
                        + oldptr[count - 2 + WATERWID]
                        + oldptr[count + 2 - WATERWID]
                        + oldptr[count + 2 + WATERWID]
                        ) >> 2 )
                     )
                    >> 3)
                    - (newptr[count]);


      newptr[count] =  newh - (newh >> density);
      count++;
    }
    count += 4;
  }
}



void HeightBlob(int x, int y, int radius, int height, int page)
{
  int rquad;
  int cx, cy, cyq;
  int left, top, right, bottom;


  rquad = radius * radius;

  /* Make a randomly-placed blob... */
  if(x<0) x = 1+radius+ rand()%(WATERWID-2*radius-1);
  if(y<0) y = 1+radius+ rand()%(WATERHGT-2*radius-1);

  left=-radius; right = radius;
  top=-radius; bottom = radius;

  /* Perform edge clipping... */
  if(x - radius < 1) left -= (x-radius-1);
  if(y - radius < 1) top  -= (y-radius-1);
  if(x + radius > WATERWID-1) right -= (x+radius-WATERWID+1);
  if(y + radius > WATERHGT-1) bottom-= (y+radius-WATERHGT+1);


  for(cy = top; cy < bottom; cy++)
  {
    cyq = cy*cy;
    for(cx = left; cx < right; cx++)
    {
      if(cx*cx + cyq < rquad)
        Height[page][WATERWID*(cy+y) + (cx+x)] += height;
    }
  }

}


void HeightBox (int x, int y, int radius, int height, int page)
{
  int cx, cy;
  int left, top, right, bottom;


  if(x<0) x = 1+radius+ rand()%(WATERWID-2*radius-1);
  if(y<0) y = 1+radius+ rand()%(WATERHGT-2*radius-1);

  left=-radius; right = radius;
  top=-radius; bottom = radius;

  /* Perform edge clipping... */
  if(x - radius < 1) left -= (x-radius-1);
  if(y - radius < 1) top  -= (y-radius-1);
  if(x + radius > WATERWID-1) right -= (x+radius-WATERWID+1);
  if(y + radius > WATERHGT-1) bottom-= (y+radius-WATERHGT+1);

  for(cy = top; cy < bottom; cy++)
  {
    for(cx = left; cx < right; cx++)
    {
        Height[page][WATERWID*(cy+y) + (cx+x)] = height;
    }
  }

}


void WarpBlob(int x, int y, int radius, int height, int page)
{
  int cx, cy;
  int left,top,right,bottom;
  int square;
  int radsquare = radius * radius;

  radsquare = (radius*radius);

  height /= 64;

  left=-radius; right = radius;
  top=-radius; bottom = radius;

  /* Perform edge clipping... */
  if(x - radius < 1) left -= (x-radius-1);
  if(y - radius < 1) top  -= (y-radius-1);
  if(x + radius > WATERWID-1) right -= (x+radius-WATERWID+1);
  if(y + radius > WATERHGT-1) bottom-= (y+radius-WATERHGT+1);

  for(cy = top; cy < bottom; cy++)
  {
    for(cx = left; cx < right; cx++)
    {
      square = cy*cy + cx*cx;
      if(square < radsquare)
      {
        Height[page][WATERWID*(cy+y) + cx+x]
          += (radius-sqrt(square))*(float)(height);
      }
    }
  }
}

void SineBlob(int x, int y, int radius, int height, int page)
{
  int cx, cy;
  int left,top,right,bottom;
  int square, dist;
  int radsquare = radius * radius;
  float length = (1024.0/(float)radius)*(1024.0/(float)radius);

  if(x<0) x = 1+radius+ rand()%(WATERWID-2*radius-1);
  if(y<0) y = 1+radius+ rand()%(WATERHGT-2*radius-1);


  radsquare = (radius*radius);


  left=-radius; right = radius;
  top=-radius; bottom = radius;


  /* Perform edge clipping... */
  if(x - radius < 1) left -= (x-radius-1);
  if(y - radius < 1) top  -= (y-radius-1);
  if(x + radius > WATERWID-1) right -= (x+radius-WATERWID+1);
  if(y + radius > WATERHGT-1) bottom-= (y+radius-WATERHGT+1);

  for(cy = top; cy < bottom; cy++)
  {
    for(cx = left; cx < right; cx++)
    {
      square = cy*cy + cx*cx;
      if(square < radsquare)
      {
        dist = sqrt(square*length);
        Height[page][WATERWID*(cy+y) + cx+x]
          += (int)((FCos(dist)+0xffff)*(height)) >> 19;
      }
    }
  }
}


void help()
{
  printf(HelpMessage);
  fflush(stdout);
}

