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

#include <time.h>     /* for `clock()'   */
#include <stdio.h>    /* for `fprintf()' */
#include <stdlib.h>   /* for `rand()'    */
#include <unistd.h>   /* for `sleep()'   */
#include <math.h>     /* for `sqrt()'    */

/* the super interface */
static IDirectFB *dfb;

/* the primary surface (surface of primary layer) */
static IDirectFBSurface *primary;

static IDirectFBImageProvider *provider;

/* Input interfaces: device and its buffer */
static IDirectFBInputDevice *keyboard;
static IDirectFBEventBuffer *key_events;

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...)                                                     \
               err = x;                                                    \
               if (err != DFB_OK) {                                        \
                    fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
                    DirectFBErrorFatal( #x, err );                         \
               }

static int screen_width, screen_height;


static void shutdown()
{
     /* release our interfaces to shutdown DirectFB */
     primary->Release( primary );
     key_events->Release( key_events );
     keyboard->Release( keyboard );
     dfb->Release( dfb );
}


#define SURFACEMANAGER_TEST_SURFACES 200

static void surfacemanager_test()
{
     int i;
     int width, height;
     unsigned long t;
     IDirectFBSurface      *surfaces[SURFACEMANAGER_TEST_SURFACES];
     IDirectFBSurface      *surface;
     DFBResult             ret;
     DFBSurfaceDescription dsc;

     provider->GetSurfaceDescription (provider, &dsc);

     dsc.flags = DSDESC_WIDTH | DSDESC_HEIGHT;

     for (i=0; i<SURFACEMANAGER_TEST_SURFACES; i++) {
          dsc.width = rand()%500 + 100;
          dsc.height = rand()%500 + 100;

          ret = dfb->CreateSurface( dfb, &dsc, &surfaces[i] );
          if (ret) {
               int j;

               DirectFBError( "surfacemanager_test: "
                              "unable to create surface", ret );

               for (j=0; j<i; j++)
                    surfaces[j]->Release( surfaces[j] );

               return;
          }

          provider->RenderTo( provider, surfaces[i], NULL );
     }


     t = clock();
     for (i=0; i<SURFACEMANAGER_TEST_SURFACES*100; i++) {
          surface = surfaces[rand()%SURFACEMANAGER_TEST_SURFACES];
          surface->GetSize (surface, &width, &height);
          primary->Blit( primary,
                         surface, NULL,
                         (screen_width - width) / 2,
                         (screen_height - height) / 2 );
     }
     t = clock() - t;

     printf( "surfacemanager_test: clock diff %d\n", (int)t );

     for (i=0; i<SURFACEMANAGER_TEST_SURFACES; i++)
          surfaces[i]->Release( surfaces[i] );
}

int main( int argc, char *argv[] )
{
     DFBResult err;

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* get an interface to the primary keyboard
        and create an input buffer for it */
     DFBCHECK(dfb->GetInputDevice( dfb, DIDID_KEYBOARD, &keyboard ));
     DFBCHECK(keyboard->CreateEventBuffer( keyboard, &key_events ));

     /* set our cooperative level to DFSCL_FULLSCREEN
        for exclusive access to the primary layer */
     err = dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );
     if (err)
       DirectFBError( "Failed to get exclusive access", err );
     
     /* get the primary surface, i.e. the surface of the primary
        layer we have exclusive access to */
     {
          DFBSurfaceDescription dsc;

          dsc.flags = DSDESC_CAPS;
          dsc.caps = DSCAPS_PRIMARY;

          DFBCHECK(dfb->CreateSurface( dfb, &dsc, &primary ));
          primary->GetSize( primary, &screen_width, &screen_height );
     }

     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/melted.png",
                                        &provider ));

     surfacemanager_test();
//     surfacemanager_test();

     shutdown();

     return 0;
}

