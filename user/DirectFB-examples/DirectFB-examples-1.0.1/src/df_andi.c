/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
   All rights reserved.

   Written by Denis Oliver Kropp <dok@directfb.org>,
              Andreas Hundt <andi@fischlustig.de> and
              Sven Neumann <neo@directfb.org>.

   This file is subject to the terms and conditions of the MIT License:

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation
   files (the "Software"), to deal in the Software without restriction,
   including without limitation the rights to use, copy, modify, merge,
   publish, distribute, sublicense, and/or sell copies of the Software,
   and to permit persons to whom the Software is furnished to do so,
   subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <directfb.h>

#include <direct/util.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include "util.h"

/* height and width of the penguin surface (more that one penguin on it) */
#define XTUXSIZE 400
#define YTUXSIZE 240

/* height and width of one sprite */
#define XSPRITESIZE 40
#define YSPRITESIZE 60

/* new animation frame is set every ANIMATION_DELAY steps */
#define ANIMATION_DELAY 5

/* resolution of the destination mask */
static int DESTINATION_MASK_WIDTH;
static int DESTINATION_MASK_HEIGHT;

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...)                                                    \
     {                                                                    \
          err = x;                                                        \
          if (err != DFB_OK) {                                            \
               fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ );     \
               DirectFBErrorFatal( #x, err );                             \
          }                                                               \
     }

/* DirectFB interfaces needed by df_andi */
static IDirectFB               *dfb;
static IDirectFBSurface        *primary;
static IDirectFBEventBuffer    *keybuffer;
static IDirectFBImageProvider  *provider;
static IDirectFBFont           *font;

/* DirectFB surfaces used by df_andi */
static IDirectFBSurface *tuximage;
static IDirectFBSurface *background;
static IDirectFBSurface *destination_mask;

/* values on which placement of penguins and text depends */
static int xres;
static int yres;
static int fontheight;

static bool triple;

static unsigned int rand_pool = 0x12345678;
static unsigned int rand_add  = 0x87654321;

static inline unsigned int myrand()
{
     rand_pool ^= ((rand_pool << 7) | (rand_pool >> 25));
     rand_pool += rand_add;
	 rand_add  += rand_pool;

     return rand_pool;
}

/* anmation frame */
typedef struct _PenguinFrame {
     DFBRectangle rect;
     struct _PenguinFrame *next;
} PenguinFrame;

/* linked lists of animation frames */
static PenguinFrame* left_frames = NULL;
static PenguinFrame* right_frames = NULL;
static PenguinFrame* up_frames = NULL;
static PenguinFrame* down_frames = NULL;

typedef enum {
     DIR_LEFT,
     DIR_RIGHT,
     DIR_UP,
     DIR_DOWN
} Direction;

/* penguin struct, needed for each penguin on the screen */
typedef struct _Penguin {
     int x, y;
     int x_togo;
     int y_togo;
     int moving;
     int sprite_nr;
     int delay;
     PenguinFrame *left_frame;
     PenguinFrame *right_frame;
     PenguinFrame *up_frame;
     PenguinFrame *down_frame;
     PenguinFrame **frameset;
     struct _Penguin *next;
} Penguin;

/* needed for the penguin linked list */
static Penguin *penguins     = NULL;
static Penguin *last_penguin = NULL;

/* number of penguins currently on screen */
static int population = 0;

/* number of destination coordinates in coords array */
static int nr_coords = 0;

/* coors array has hardcoded maximum possible length */
static int *coords;

/*
 * adds one penguin to the list, and sets initial state
 */
static void spawn_penguin()
{
     Penguin *new_penguin = (Penguin*)malloc( sizeof(Penguin) );

     new_penguin->x = xres/2;
     new_penguin->y = yres/2;
     new_penguin->x_togo = 0;
     new_penguin->y_togo = 0;
     new_penguin->moving = 1;

     new_penguin->delay = 5;

     new_penguin->left_frame = left_frames;
     new_penguin->right_frame = right_frames;
     new_penguin->up_frame = up_frames;
     new_penguin->down_frame = down_frames;

     new_penguin->next = NULL;

     if (!penguins) {
          penguins = new_penguin;
          last_penguin = new_penguin;
     }
     else {
          last_penguin->next = new_penguin;
          last_penguin = new_penguin;
     }
     population++;
}

/*
 * removes one penguin (the first) from the list
 */
static void destroy_penguin()
{
     Penguin *first_penguin = penguins;

     if (penguins) {
          penguins = penguins->next;
          free (first_penguin);
          population--;
     }
}

/*
 * removes a given number of penguins
 */
static void destroy_penguins(int number)
{
     while (number--)
          destroy_penguin();
}


/*
 * adds a given number of penguins
 */
static void spawn_penguins(int number)
{
     while (number--)
          spawn_penguin();
}

/*
 * blits all penguins to the screen
 */
static void draw_penguins()
{
     int           j = population;
     Penguin      *p = penguins;
     DFBRectangle  rects[population < 256 ? population : 256];
     DFBPoint      points[population < 256 ? population : 256];

     primary->SetBlittingFlags( primary, DSBLIT_SRC_COLORKEY );

     while (j > 0) {
          int n = 0;

          while (n < j && n < 256) {
               rects[n] = (*(p->frameset))->rect;

               points[n].x = p->x;
               points[n].y = p->y;

               n++;
               p = p->next;
          }

          primary->BatchBlit( primary, tuximage, rects, points, n );

          j -= n;
     }
}

/*
 *  moves and clipps all penguins, penguins that are in formation shiver,
 *  penguins not in formation "walk"
 */
static void move_penguins( int step )
{
     Penguin *p = penguins;

     while (p) {
          if (ABS(p->x_togo) < step)
               p->x_togo = 0;

          if (ABS(p->y_togo) < step)
               p->y_togo = 0;


          if (!p->x_togo && !p->y_togo) {
               if (p->moving) {
                    /* walking penguins get new destination if they have reached
                       their destination */
                    p->x_togo = (myrand()%100) - 50;
                    p->y_togo = (myrand()%100) - 50;
               }
               else {
                    p->frameset = &p->down_frame;

                    /* penguins that have reached their
                       formation point jitter */
                    p->x += myrand()%3 - 1;
                    p->y += myrand()%3 - 1;
               }
          }
          /* increase/decrease coordinates and to go variables */
          if (p->x_togo > 0) {
               p->x -= step;
               p->x_togo -= step;

               p->frameset = &p->left_frame;
          }
          if (p->x_togo < 0) {
               p->x += step;
               p->x_togo += step;

               p->frameset = &p->right_frame;
          }
          if (p->y_togo > 0) {
               p->y -= step;
               p->y_togo -= step;

               p->frameset = &p->up_frame;
          }
          if (p->y_togo < 0) {
               p->y += step;
               p->y_togo += step;

               p->frameset = &p->down_frame;
          }

          /* clip penguin */
          if (p->x < 0)
               p->x = 0;

          if (p->y < 0)
               p->y = 0;

          if (p->x > xres - XSPRITESIZE)
               p->x = xres - XSPRITESIZE;

          if (p->y > yres - YSPRITESIZE)
               p->y = yres - YSPRITESIZE;

          if (p->delay == 0) {
               *(p->frameset) = (*(p->frameset))->next;
               p->delay = 5;
          }
          else {
               p->delay--;
          }

          p = p->next;
     }
}

/*
 * searches a destination point in the coords array for each penguin
 */
static void penguins_search_destination() {
     Penguin *p = penguins;
     if (nr_coords) {
          while (p) {
               int entry = (myrand()%nr_coords) * 2;

               p->x_togo= p->x - coords[entry]   * xres/1000.0f;
               p->y_togo= p->y - coords[entry+1] * yres/1000.0f;
               p->moving = 0;

               p = p->next;
          }
     }
}

/*
 * removes all penguins
 */
static void destroy_all_penguins()
{
     Penguin *p = penguins;

     while (p) {
          penguins = p->next;
          free(p);
          p = penguins;
     }
}

/*
 * revives all penguins, penguins that are in formation move again
 */
static void revive_penguins()
{
     Penguin *p = penguins;

     while (p) {
          p->moving = 1;
          p = p->next;
     }
}

/*
 * interprets the destination mask from the destination_mask surface, all back
 * pixels become formation points, and are stored in the coords array
 */
static void read_destination_mask()
{
     DFBResult  ret;
     int        x, y;
     void      *ptr;
     int        pitch;

     coords = calloc( DESTINATION_MASK_WIDTH * DESTINATION_MASK_HEIGHT, sizeof(int) );


     ret = destination_mask->Lock( destination_mask, DSLF_READ, &ptr, &pitch );
     if (ret) {
          DirectFBError( "Could not lock destination mask surface", ret );
          return;
     }

     for (y=0;y<DESTINATION_MASK_HEIGHT;y++) {
          u32 *src = ptr + y * pitch;

          for (x=0;x<DESTINATION_MASK_WIDTH;x++) {
               if ((src[x] & 0x00FFFFFF) == 0) {
                    coords[nr_coords*2  ] = (x *(1000/DESTINATION_MASK_WIDTH));
                    coords[nr_coords*2+1] = (y *(1000/DESTINATION_MASK_HEIGHT));
                    nr_coords++;
               }
          }
     }

     destination_mask->Unlock( destination_mask );
}

/*
 * initializes the animation frames for a specified direction at yoffset
 */
static void initialize_direction_frames(PenguinFrame **direction_frames, int yoffset)
{
     PenguinFrame* new_frame = NULL;
     PenguinFrame* last_frame = NULL;

     if (!*direction_frames) {
          int i;

          for (i = 0; i < (XTUXSIZE/XSPRITESIZE - 1) ;i++) {
               new_frame = (PenguinFrame*) malloc( sizeof(PenguinFrame) ); //FIXME: leak

               new_frame->rect.x = i*XSPRITESIZE;
               new_frame->rect.y = YSPRITESIZE*yoffset;
               new_frame->rect.w = XSPRITESIZE;
               new_frame->rect.h = YSPRITESIZE;

               if (!*direction_frames) {
                    *direction_frames = new_frame;
               }
               else {
                    last_frame->next = new_frame;
               }
               last_frame = new_frame;
          }
          last_frame->next = *direction_frames;
     }
}

/*
 * initialize all animation frames
 */
static void initialize_animation()
{
     initialize_direction_frames( &down_frames,  0 );
     initialize_direction_frames( &left_frames,  1 );
     initialize_direction_frames( &up_frames,    2 );
     initialize_direction_frames( &right_frames, 3 );
}

/*
 * set up DirectFB and load resources
 */
static void init_resources( int argc, char *argv[] )
{
     DFBResult err;
     DFBSurfaceDescription dsc;

     srand((long)time(0));

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* create an input buffer for key events */
     DFBCHECK(dfb->CreateInputEventBuffer( dfb, DICAPS_KEYS,
                                           DFB_FALSE, &keybuffer ));

     /* set our cooperative level to DFSCL_FULLSCREEN for exclusive access to
        the primary layer */
     err = dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );
     if (err)
       DirectFBError( "Failed to get exclusive access", err );

     /* get the primary surface, i.e. the surface of the primary layer we have
        exclusive access to */
     dsc.flags = DSDESC_CAPS;
     dsc.caps = DSCAPS_PRIMARY | DSCAPS_TRIPLE;

     err = dfb->CreateSurface( dfb, &dsc, &primary );
     if (err) {
          dsc.caps = DSCAPS_PRIMARY | DSCAPS_DOUBLE;

          DFBCHECK(dfb->CreateSurface( dfb, &dsc, &primary ));
     }
     else
          triple = true;

     DFBCHECK(primary->GetSize( primary, &xres, &yres ));

     /* load font */
     {
          DFBFontDescription desc;

          desc.flags = DFDESC_HEIGHT;
          desc.height = 24;

          DFBCHECK(dfb->CreateFont( dfb, FONT, &desc, &font ));
          DFBCHECK(font->GetHeight( font, &fontheight ));
          DFBCHECK(primary->SetFont( primary, font ));
     }

     /* load penguin animation */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/tux.png",
                                        &provider ));

     DFBCHECK (provider->GetSurfaceDescription (provider, &dsc));
     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &tuximage ));

     DFBCHECK(provider->RenderTo( provider, tuximage, NULL ));
     provider->Release( provider );

     /* set the colorkey to green */
     tuximage->SetSrcColorKey( tuximage, 0x00, 0xFF, 0x00 );

     /* load the background image */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/wood_andi.jpg",
                                        &provider ));

     DFBCHECK (provider->GetSurfaceDescription (provider, &dsc));
     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT;
     dsc.width = xres;
     dsc.height = yres;
     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &background ));

     DFBCHECK(provider->RenderTo( provider, background, NULL ));
     provider->Release( provider );

     /* load the penguin destination mask */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR
                                        "/destination_mask.png",
                                        &provider ));

     DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

     dsc.pixelformat = DSPF_RGB32;

     DESTINATION_MASK_WIDTH  = dsc.width;
     DESTINATION_MASK_HEIGHT = dsc.height;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &destination_mask ));

     DFBCHECK(provider->RenderTo( provider, destination_mask, NULL ));
     provider->Release( provider );
}

/*
 * deinitializes resources and DirectFB
 */
static void deinit_resources()
{
     free( coords );

     destroy_all_penguins();

     tuximage->Release( tuximage );
     background->Release( background );
     destination_mask->Release( destination_mask );
     primary->Release( primary );
     keybuffer->Release( keybuffer );
     font->Release( font );
     dfb->Release( dfb );
}

int main( int argc, char *argv[] )
{
     FPSData fps;
     int     quit = 0;
     int     clipping = 0;

     init_resources( argc, argv );

     read_destination_mask();

     initialize_animation();

     spawn_penguins( 200 );

     primary->SetDrawingFlags( primary, DSDRAW_BLEND );

     fps_init( &fps );

     /* main loop */
     while (!quit) {
          DFBInputEvent evt;
          char buf[32];

          /* draw the background image */
          primary->SetBlittingFlags( primary, DSBLIT_NOFX );

          primary->Blit( primary, background, NULL, 0, 0 );

          /* move the penguins 3 times, thats faster ;-) */
          move_penguins( 3 );

          /* draw all penguins */
          draw_penguins();

          /* draw the population string in upper left corner */
          primary->SetColor( primary, 0, 0, 60, 0xa0 );
          primary->FillRectangle( primary, 0, 0, 440, fontheight+5 );

          snprintf( buf, sizeof(buf), "Penguin Population: %d", population );

          primary->SetColor( primary, 180, 200, 255, 0xFF );
          primary->DrawString( primary, buf, -1, 10, 0, DSTF_LEFT | DSTF_TOP );

          snprintf( buf, sizeof(buf), "FPS: %s", fps.fps_string );

          primary->SetColor( primary, 190, 210, 255, 0xFF );
          primary->DrawString( primary, buf, -1, 300, 0, DSTF_LEFT | DSTF_TOP );

          /* flip display */
          primary->Flip( primary, NULL, triple ? DSFLIP_ONSYNC : DSFLIP_WAITFORSYNC );

          fps_count( &fps, 1000 );

          /* process keybuffer */
          while (keybuffer->GetEvent( keybuffer, DFB_EVENT(&evt)) == DFB_OK) {
               if (evt.type == DIET_KEYPRESS) {
                    switch (DFB_LOWER_CASE(evt.key_symbol)) {
                         case DIKS_ESCAPE:
                         case DIKS_SMALL_Q:
                         case DIKS_BACK:
                         case DIKS_STOP:
                              /* quit main loop */
                              quit = 1;
                              break;
                         case DIKS_SMALL_S:
                         case DIKS_CURSOR_UP:
                              /* add another penguin */
                              spawn_penguins(10);
                              break;
                         case DIKS_SMALL_R:
                              /* penguins in formation will walk around again */
                              revive_penguins();
                              break;
                         case DIKS_SMALL_D:
                         case DIKS_CURSOR_DOWN:
                              /* removes one penguin */
                              destroy_penguins(10);
                              break;
                         case DIKS_SMALL_C:
                              /*toggle clipping*/
                              clipping=!clipping;
                              if (clipping) {
                                   DFBRegion clipregion =
                                       { 100,100, xres-100, yres-100 };
                                   primary->SetClip( primary, &clipregion );
                              }
                              else
                                   primary->SetClip( primary, NULL );
                              break;
                         case DIKS_SPACE:
                         case DIKS_ENTER:
                         case DIKS_OK:
                              /* penguins go in formation */
                              penguins_search_destination();
                              break;
                         default:
                              break;
                    }
               }
          }
     }

     deinit_resources();
     return 42;
}
