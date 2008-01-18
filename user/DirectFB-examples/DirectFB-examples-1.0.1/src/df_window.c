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
#include <time.h>

#include <directfb.h>


/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...) \
     {                                                                \
          err = x;                                                    \
          if (err != DFB_OK) {                                        \
               fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ ); \
               DirectFBErrorFatal( #x, err );                         \
          }                                                           \
     }

static inline long myclock()
{
  struct timeval tv;

  gettimeofday (&tv, NULL);
  return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

int main( int argc, char *argv[] )
{
     IDirectFB              *dfb;
     IDirectFBDisplayLayer  *layer;

     IDirectFBImageProvider *provider;
     IDirectFBVideoProvider *video_provider;

     IDirectFBSurface       *bgsurface;

     IDirectFBWindow        *window1;
     IDirectFBWindow        *window2;
     IDirectFBSurface       *window_surface1;
     IDirectFBSurface       *window_surface2;

     IDirectFBEventBuffer   *buffer;

     IDirectFBFont          *font;

     DFBDisplayLayerConfig         layer_config;
     DFBGraphicsDeviceDescription  gdesc;
     IDirectFBWindow*              upper;
     DFBWindowID                   id1;

     int fontheight;
     int err;
     int quit = 0;


     DFBCHECK(DirectFBInit( &argc, &argv ));
     DFBCHECK(DirectFBCreate( &dfb ));

     dfb->GetDeviceDescription( dfb, &gdesc );

     DFBCHECK(dfb->GetDisplayLayer( dfb, DLID_PRIMARY, &layer ));

     layer->SetCooperativeLevel( layer, DLSCL_ADMINISTRATIVE );

     if (!((gdesc.blitting_flags & DSBLIT_BLEND_ALPHACHANNEL) &&
           (gdesc.blitting_flags & DSBLIT_BLEND_COLORALPHA  )))
     {
          layer_config.flags = DLCONF_BUFFERMODE;
          layer_config.buffermode = DLBM_BACKSYSTEM;

          layer->SetConfiguration( layer, &layer_config );
     }

     layer->GetConfiguration( layer, &layer_config );
     layer->EnableCursor ( layer, 1 );

     {
          DFBFontDescription desc;

          desc.flags = DFDESC_HEIGHT;
          desc.height = layer_config.width/50;

          DFBCHECK(dfb->CreateFont( dfb, FONT, &desc, &font ));
          font->GetHeight( font, &fontheight );
     }

     if (argc < 2 ||
         dfb->CreateVideoProvider( dfb, argv[1], &video_provider ) != DFB_OK)
     {
          video_provider = NULL;
     }

     {
          DFBSurfaceDescription desc;

          DFBCHECK(dfb->CreateImageProvider( dfb,
                                             DATADIR"/desktop.png",
                                             &provider ));

          desc.flags  = DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_CAPS;
          desc.width  = layer_config.width;
          desc.height = layer_config.height;
          desc.caps   = DSCAPS_SHARED;

          DFBCHECK(dfb->CreateSurface( dfb, &desc, &bgsurface ) );

          provider->RenderTo( provider, bgsurface, NULL );
          provider->Release( provider );

          DFBCHECK(bgsurface->SetFont( bgsurface, font ));

          bgsurface->SetColor( bgsurface, 0xCF, 0xCF, 0xFF, 0xFF );
          bgsurface->DrawString( bgsurface,
                                 "Move the mouse over a window to activate it.",
                                 -1, 0, 0, DSTF_LEFT | DSTF_TOP );

          bgsurface->SetColor( bgsurface, 0xCF, 0xDF, 0xCF, 0xFF );
          bgsurface->DrawString( bgsurface,
                                 "Press left mouse button and drag to move the window.",
                                 -1, 0, fontheight, DSTF_LEFT | DSTF_TOP );

          bgsurface->SetColor( bgsurface, 0xCF, 0xEF, 0x9F, 0xFF );
          bgsurface->DrawString( bgsurface,
                                 "Press middle mouse button to raise/lower the window.",
                                 -1, 0, fontheight * 2, DSTF_LEFT | DSTF_TOP );

          bgsurface->SetColor( bgsurface, 0xCF, 0xFF, 0x6F, 0xFF );
          bgsurface->DrawString( bgsurface,
                                 "Press right mouse button when you are done.", -1,
                                 0, fontheight * 3,
                                 DSTF_LEFT | DSTF_TOP );

          layer->SetBackgroundImage( layer, bgsurface );
          layer->SetBackgroundMode( layer, DLBM_IMAGE );
     }

     {
          DFBSurfaceDescription sdsc;
          DFBWindowDescription  desc;

          desc.flags = ( DWDESC_POSX | DWDESC_POSY |
                         DWDESC_WIDTH | DWDESC_HEIGHT );

          if (!video_provider) {
               desc.caps = DWCAPS_ALPHACHANNEL;
               desc.flags |= DWDESC_CAPS;

               sdsc.width  = 300;
               sdsc.height = 200;
          }
          else {
               video_provider->GetSurfaceDescription( video_provider, &sdsc );

               if (sdsc.flags & DSDESC_CAPS) {
                    desc.flags       |= DWDESC_SURFACE_CAPS;
                    desc.surface_caps = sdsc.caps;
               }
          }

          desc.posx   = 20;
          desc.posy   = 120;
          desc.width  = sdsc.width;
          desc.height = sdsc.height;

          DFBCHECK( layer->CreateWindow( layer, &desc, &window2 ) );
          window2->GetSurface( window2, &window_surface2 );

          window2->SetOpacity( window2, 0xFF );

          window2->CreateEventBuffer( window2, &buffer );

          if (video_provider) {
               video_provider->PlayTo( video_provider, window_surface2,
                                       NULL, NULL, NULL );
          }
          else
          {
               window_surface2->SetColor( window_surface2,
                                          0x00, 0x30, 0x10, 0xc0 );
               window_surface2->DrawRectangle( window_surface2,
                                               0, 0, desc.width, desc.height );
               window_surface2->SetColor( window_surface2,
                                          0x80, 0xa0, 0x00, 0x90 );
               window_surface2->FillRectangle( window_surface2,
                                               1, 1,
                                               desc.width-2, desc.height-2 );
          }

          window_surface2->Flip( window_surface2, NULL, 0 );
     }

     {
          DFBWindowDescription desc;

          desc.flags  = ( DWDESC_POSX | DWDESC_POSY |
                          DWDESC_WIDTH | DWDESC_HEIGHT | DWDESC_CAPS );
          desc.posx   = 200;
          desc.posy   = 200;
          desc.width  = 512;
          desc.height = 145;
          desc.caps   = DWCAPS_ALPHACHANNEL;

          DFBCHECK(layer->CreateWindow( layer, &desc, &window1 ) );
          window1->GetSurface( window1, &window_surface1 );

          DFBCHECK(dfb->CreateImageProvider( dfb,
                                             DATADIR"/dfblogo.png",
                                             &provider ));
          provider->RenderTo( provider, window_surface1, NULL );

          window_surface1->SetColor( window_surface1, 0xFF, 0x20, 0x20, 0x90 );
          window_surface1->DrawRectangle( window_surface1,
                                          0, 0, desc.width, desc.height );

          window_surface1->Flip( window_surface1, NULL, 0 );

          provider->Release( provider );

          window1->AttachEventBuffer( window1, buffer );

          window1->SetOpacity( window1, 0xFF );

          window1->GetID( window1, &id1 );
     }

     window1->RequestFocus( window1 );
     window1->RaiseToTop( window1 );
     upper = window1;

     while (!quit) {
          static IDirectFBWindow* active = NULL;
          static int grabbed = 0;
          static int startx = 0;
          static int starty = 0;
          static int endx = 0;
          static int endy = 0;
          DFBWindowEvent evt;

          buffer->WaitForEventWithTimeout( buffer, 0, 10 );

          while (buffer->GetEvent( buffer, DFB_EVENT(&evt) ) == DFB_OK) {
               IDirectFBWindow* window;

               if (evt.window_id == id1)
                    window = window1;
               else
                    window = window2;

               if (evt.type == DWET_GOTFOCUS) {
                    active = window;
               }
               else if (active) {
                    switch (evt.type) {

                    case DWET_BUTTONDOWN:
                         if (!grabbed && evt.button == DIBI_LEFT) {
                              grabbed = 1;
                              startx  = evt.cx;
                              starty  = evt.cy;
                              window->GrabPointer( window );
                         }
                         break;

                    case DWET_BUTTONUP:
                         switch (evt.button) {
                              case DIBI_LEFT:
                                   if (grabbed) {
                                        window->UngrabPointer( window );
                                        grabbed = 0;
                                   }
                                   break;
                              case DIBI_MIDDLE:
                                   upper->LowerToBottom( upper );
                                   upper =
                                     (upper == window1) ? window2 : window1;
                                   break;
                              case DIBI_RIGHT:
                                   quit = DIKS_DOWN;
                                   break;
                              default:
                                   break;
                         }
                         break;

                    case DWET_KEYDOWN:
                         if (grabbed)
                              break;
                         switch (evt.key_id) {
                              case DIKI_RIGHT:
                                   active->Move (active, 1, 0);
                                   break;
                              case DIKI_LEFT:
                                   active->Move (active, -1, 0);
                                   break;
                              case DIKI_UP:
                                   active->Move (active, 0, -1);
                                   break;
                              case DIKI_DOWN:
                                   active->Move (active, 0, 1);
                                   break;
                              default:
                                   break;
                         }
                         break;

                    case DWET_LOSTFOCUS:
                         if (!grabbed && active == window)
                              active = NULL;
                         break;

                    default:
                         break;

                    }
               }

               switch (evt.type) {

               case DWET_MOTION:
                    endx = evt.cx;
                    endy = evt.cy;
                    break;

               case DWET_KEYDOWN:
                    switch (evt.key_symbol) {
                    case DIKS_ESCAPE:
                    case DIKS_SMALL_Q:
                    case DIKS_CAPITAL_Q:
                    case DIKS_BACK:
                    case DIKS_STOP:
                         quit = 1;
                         break;
                    default:
                         break;
                    }
                    break;

               default:
                    break;
               }
          }

          if (video_provider)
               window_surface2->Flip( window_surface2, NULL, 0 );

          if (active) {
               if (grabbed) {
                    active->Move( active, endx - startx, endy - starty);
                    startx = endx;
                    starty = endy;
               }
               active->SetOpacity( active,
                                   (sin( myclock()/300.0 ) * 85) + 170 );
          }
     }

     if (video_provider)
          video_provider->Release( video_provider );

     buffer->Release( buffer );
     font->Release( font );
     window_surface2->Release( window_surface2 );
     window_surface1->Release( window_surface1 );
     window2->Release( window2 );
     window1->Release( window1 );
     layer->Release( layer );
     bgsurface->Release( bgsurface );
     dfb->Release( dfb );

     return 42;
}
