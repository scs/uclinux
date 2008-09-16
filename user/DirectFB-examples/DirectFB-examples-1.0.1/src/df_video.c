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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include <directfb.h>

static IDirectFB              *dfb;
static IDirectFBDisplayLayer  *layer;

static IDirectFBImageProvider *provider;
static IDirectFBVideoProvider *videoprovider;

static IDirectFBWindow        *videowindow;
static IDirectFBSurface       *videosurface;

static IDirectFBWindow        *dfbwindow;
static IDirectFBSurface       *dfbsurface;

static IDirectFBInputDevice   *mouse;
static IDirectFBInputDevice   *keyboard;
static IDirectFBEventBuffer   *mouse_events;

int err;

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...) \
     {                                                                \
          err = x;                                                    \
          if (err != DFB_OK) {                                        \
               fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
               DirectFBErrorFatal( #x, err );                         \
          }                                                           \
     }


int main( int argc, char *argv[] )
{
     DFBDisplayLayerConfig  layer_config;
     DFBInputDeviceKeyState quit = DIKS_UP;

     DFBCHECK(DirectFBInit( &argc, &argv ));

     if (argc < 2) {
          fprintf(stderr, "%s: you must specify a video source\n", argv[0]);
          return 1;
     }

     DFBCHECK(DirectFBCreate( &dfb ));

     DFBCHECK(dfb->GetInputDevice( dfb, DIDID_MOUSE, &mouse ));
     DFBCHECK(dfb->GetInputDevice( dfb, DIDID_KEYBOARD, &keyboard ));

     DFBCHECK(mouse->CreateEventBuffer( mouse, &mouse_events ));

     DFBCHECK(dfb->GetDisplayLayer( dfb, DLID_PRIMARY, &layer ));

     {
          DFBSurfaceDescription sdsc;
          DFBWindowDescription desc;

          DFBCHECK(dfb->CreateVideoProvider( dfb, argv[1],
                                             &videoprovider ));
          videoprovider->GetSurfaceDescription( videoprovider, &sdsc );


          desc.flags = DWDESC_POSX | DWDESC_POSY | DWDESC_WIDTH | DWDESC_HEIGHT;
          desc.posx = 0;
          desc.posy = 0;
          desc.width = sdsc.width;
          desc.height = sdsc.height;

          DFBCHECK(layer->CreateWindow( layer, &desc, &videowindow ) );
          DFBCHECK(videowindow->GetSurface( videowindow, &videosurface ) );

          videowindow->SetOpacity( videowindow, 0xFF );

          DFBCHECK(videoprovider->PlayTo( videoprovider, videosurface,
                                          NULL, NULL, NULL ));
     }
     {
          DFBWindowDescription desc;

          desc.flags = DWDESC_POSX | DWDESC_POSY | DWDESC_WIDTH |
                       DWDESC_HEIGHT | DWDESC_CAPS;
          desc.posx = 0;
          desc.posy = 20;
          desc.width = 275;//512;
          desc.height = 116;//145;
          desc.caps = DWCAPS_ALPHACHANNEL;

          DFBCHECK(layer->CreateWindow( layer, &desc, &dfbwindow ) );
          DFBCHECK(dfbwindow->GetSurface( dfbwindow, &dfbsurface ) );

          DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/shot.png",
                                             &provider ));
          DFBCHECK(provider->RenderTo( provider, dfbsurface, NULL ));
          provider->Release( provider );

          dfbwindow->SetOpacity( dfbwindow, 0xFF );
     }

     layer->GetConfiguration( layer, &layer_config );


     while (quit == DIKS_UP) {
          DFBInputEvent ev;
          int movx = 0;
          int movy = 0;

          keyboard->GetKeyState( keyboard, DIKI_ESCAPE, &quit );

          while (mouse_events->GetEvent( mouse_events, DFB_EVENT(&ev) ) == DFB_OK) {
               if (ev.type == DIET_AXISMOTION) {
                    switch (ev.axis) {
                         case DIAI_X:
                              movx += ev.axisrel;
                              break;
                         case DIAI_Y:
                              movy += ev.axisrel;
                              break;
                         default:
                              break;
                    }
               } else
               if (ev.type == DIET_BUTTONRELEASE) {
                    quit = DIKS_DOWN;
               }
          }

          {
               static int mode = 0;

               if (mode || 1) {
                    static int wx = 0;
                    static int wy = 0;
                    static int dirx = 4;
                    static int diry = 2;

                    wx += dirx;
                    wy += diry;

                    if (wx >= layer_config.width - 768/2  ||  wx <= 0)
                         dirx *= -1;
                    if (wy >= layer_config.height - 576/2  ||  wy <= 0)
                         diry *= -1;

                    videowindow->Move( videowindow, dirx, diry );
               }
               else {
                    static float w = 0;
                    unsigned char r = sin(w)*128+127;
                    unsigned char g = sin(w*0.3f)*128+127;
                    unsigned char b = sin(w*0.5f)*128+127;

                    layer->SetBackgroundColor( layer, r, g, b, 0 );

                    w += 0.1f;
               }

               mode = !mode;
          }

          if (movx || movy)
               dfbwindow->Move( dfbwindow, movx, movy );
     }

     videoprovider->Release( videoprovider );
     dfbwindow->Release( dfbwindow );
     layer->Release( layer );
     dfb->Release( dfb );

     return 42;
}
