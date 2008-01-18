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

#include <pthread.h>

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

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
IDirectFB               *dfb;
IDirectFBSurface        *primary;
IDirectFBInputDevice    *keyboard;
IDirectFBEventBuffer    *keybuffer;
IDirectFBImageProvider  *provider;
IDirectFBFont           *font;

/* DirectFB surfaces used by df_andi */
IDirectFBSurface *smokey_light;

int xres;
int yres;

static int intro()
{
     DFBResult err;

     int   l       = 0;
     int   jitter1 = yres/100 + 1;
     int   jitter2 = (jitter1 - 1) / 2;
     char *lines[] = {
          "3",
          "2",
          "1",
          NULL
     };

     primary->SetDrawingFlags( primary, DSDRAW_NOFX );
     primary->SetBlittingFlags( primary, DSBLIT_NOFX );

     while (lines[l]) {
          int frames = 200;

          while (frames--) {
               primary->SetColor( primary, 0, 0, 0, 0 );
               primary->FillRectangle( primary, 0, 0, xres, yres );

               primary->SetColor( primary,
                                  0x40 + rand()%0xC0, 0x80 + rand()%0x80, 0x80 + rand()%0x80, 0xff );
               primary->DrawString( primary, lines[l], -1,
                                    xres/2 + rand()%jitter1-jitter2,
                                    yres/2 + rand()%jitter1-jitter2, DSTF_CENTER );

               /* flip display */
               DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

               pthread_testcancel();
          }

          ++l;
     }

     return 0;
}

static int demo1()
{
     int i;
     int frames = 400;
     DFBResult err;
     double b = 0;

     primary->SetDrawingFlags( primary, DSDRAW_NOFX );
     primary->SetBlittingFlags( primary, DSBLIT_NOFX );

     primary->SetColor( primary, 0xff, 0xff, 0xff, 0xff );
     primary->FillRectangle( primary, 0, 0, xres, yres );

     /* flip display */
     DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

     pthread_testcancel();


     primary->SetColor( primary, 0, 0, 0, 0 );
     primary->FillRectangle( primary, 0, 0, xres, yres );

     for (i=0; i<30; i++) {
          usleep( 40000 );

          /* flip display */
          DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

          pthread_testcancel();
     }

     while (frames--) {
          double f;
          DFBRectangle rect;

          primary->FillRectangle( primary, 0, 0, xres, yres );

          f = cos(b) * 30  +  sin(b+0.5) * 40;

          rect.w = (int)((sin(f*cos(f/10.0))/2 + 1.2)*800);
          rect.h = (int)((sin(f*sin(f/10.0)) + 1.2)*300);

          rect.x = (xres - rect.w) / 2;
          rect.y = (yres - rect.h) / 2;

          primary->StretchBlit( primary, smokey_light, NULL, &rect );

          b += .001;

          /* flip display */
          DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

          pthread_testcancel();
     }

     return 0;
}

static int demo2()
{
     DFBResult err;
     int frames = 400;
     int xres2 = xres/2;
     int yres2 = yres/2;
     double b = 0;

     primary->SetDrawingFlags( primary, DSDRAW_BLEND );
     primary->SetBlittingFlags( primary, DSBLIT_NOFX );

     while (frames--) {
          double w;

          primary->SetColor( primary, 0, 0, 0, 0x10 );
          primary->FillRectangle( primary, 0, 0, xres, yres );

          for (w=b; w<=b+6.29; w+=.05) {
               primary->SetColor( primary,
                                  sin(1*w+b) *127+127,
                                  sin(2*w-b) *127+127,
                                  sin(3*w+b) *127+127,
                                  sin(4*w-b) *127+127 );
               primary->DrawLine( primary, xres2, yres2,
                                  xres2 + cos(w)*xres2, yres2 + sin(w)*yres2 );
          }

          b += .02;

          /* flip display */
          DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

          pthread_testcancel();
     }

     primary->SetColor( primary, 0, 0, 0, 0x10 );

     for (frames=0; frames<75; frames++) {
          primary->FillRectangle( primary, 0, 0, xres, yres );

          /* flip display */
          DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC | DSFLIP_BLIT ));

          pthread_testcancel();
     }

     return 0;
}

static int (*demos[])() = { intro, demo1, demo2, NULL};

static void* demo_loop (void *arg)
{
     DFBResult err;
     int d = 0;

     while (demos[d]) {
          if (demos[d]())
               break;

          ++d;
     }

     primary->SetColor( primary, 0, 0, 0, 0 );
     primary->FillRectangle( primary, 0, 0, xres, yres );

     primary->SetColor( primary, 0xff, 0xff, 0xff, 0xff );
     primary->DrawString( primary, "The End", -1, xres/2, yres/2, DSTF_CENTER );

     /* flip display */
     DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

     return NULL;
}

int main( int argc, char *argv[] )
{
     pthread_t demo_loop_thread = (pthread_t) -1;
     DFBResult err;
     int quit = 0;

     DFBSurfaceDescription dsc;

     srand((long)time(0));

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));


     /* get an interface to the primary keyboard and create an
        input buffer for it */
     DFBCHECK(dfb->GetInputDevice( dfb, DIDID_KEYBOARD, &keyboard ));
     DFBCHECK(keyboard->CreateEventBuffer( keyboard, &keybuffer ));

     /* set our cooperative level to DFSCL_FULLSCREEN for exclusive access to
        the primary layer */
     err = dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );
     if (err)
          DirectFBError( "Failed to get exclusive access", err );

     /* get the primary surface, i.e. the surface of the primary layer we have
        exclusive access to */
     dsc.flags = DSDESC_CAPS;
     dsc.caps = DSCAPS_PRIMARY | DSCAPS_DOUBLE | DSCAPS_VIDEOONLY;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &primary ));

     /* set our desired video mode */
     DFBCHECK(primary->GetSize( primary, &xres, &yres ));

     /* load font */
     {
          DFBFontDescription desc;

          desc.flags = DFDESC_HEIGHT;
          desc.height = yres/10;

          DFBCHECK(dfb->CreateFont( dfb, FONT, &desc, &font ));
          DFBCHECK(primary->SetFont( primary, font ));
     }

     /* load smokey_light */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/smokey_light.jpg",
                                        &provider ));

     DFBCHECK(provider->GetSurfaceDescription (provider, &dsc));
     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &smokey_light ));

     DFBCHECK(provider->RenderTo( provider, smokey_light, NULL ));
     provider->Release( provider );


     /* main loop */
     while (!quit) {
          DFBInputEvent evt;

          if ((int)demo_loop_thread == -1)
               pthread_create( &demo_loop_thread, NULL, demo_loop, NULL );

          keybuffer->WaitForEvent( keybuffer );

          /* process keybuffer */
          while (keybuffer->GetEvent( keybuffer, DFB_EVENT(&evt)) == DFB_OK) {
               if (evt.type == DIET_KEYPRESS) {
                    switch (evt.key_id) {
                         case DIKI_ESCAPE:
                              /* quit main loop */
                              quit = 1;
                              pthread_cancel( demo_loop_thread );
                              pthread_join( demo_loop_thread, NULL );
                              break;

                         default:
                              break;
                    }
               }
          }
     }

     smokey_light->Release( smokey_light );
     keybuffer->Release( keybuffer );
     keyboard->Release( keyboard );
     primary->Release( primary );
     dfb->Release( dfb );

     return 0;
}
