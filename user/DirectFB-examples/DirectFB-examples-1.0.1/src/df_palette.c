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
#include <string.h>

#include <directfb.h>

/* the super interface */
static IDirectFB            *dfb;

/* the primary surface (surface of primary layer) */
static IDirectFBSurface     *primary;
static IDirectFBPalette     *palette;

/* Input interfaces: device and its buffer */
static IDirectFBEventBuffer *events;

static int screen_width, screen_height;

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...) \
        {                                                                      \
           err = x;                                                            \
           if (err != DFB_OK) {                                                \
              fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ );           \
              DirectFBErrorFatal( #x, err );                                   \
           }                                                                   \
        }
        
static void
generate_palette()
{
     int       i;
     DFBResult err;
     DFBColor  colors[256];

     for (i=0; i<256; i++) {
          colors[i].a = 0xff;
          colors[i].r = i + 85;
          colors[i].g = i;
          colors[i].b = i + 171;
     }

     DFBCHECK(palette->SetEntries( palette, colors, 256, 0 ));
}

static void
rotate_palette()
{
     DFBResult err;
     DFBColor  colors[256];

     DFBCHECK(palette->GetEntries( palette, colors, 256, 0 ));

     DFBCHECK(palette->SetEntries( palette, colors + 1, 255, 0 ));

     colors[0].r += 17;
     colors[0].g += 31;
     colors[0].b += 29;
     DFBCHECK(palette->SetEntries( palette, colors, 1, 255 ));
}

static void
fill_surface( IDirectFBSurface *surface )
{
     DFBResult  err;
     int        x;
     int        y;
     void      *ptr;
     int        pitch;
     u8        *dst;

     DFBCHECK(surface->Lock( surface, DSLF_WRITE, &ptr, &pitch ));

     for (y=0; y<screen_height; y++) {
          dst = ptr + y * pitch;

          for (x=0; x<screen_width; x++)
               dst[x] = (x*x + y) / (y+1);
     }

     DFBCHECK(surface->Unlock( surface ));
}

int
main( int argc, char *argv[] )
{
     int                    quit = 0;
     DFBResult              err;
     DFBSurfaceDescription  sdsc;

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* create an event buffer for all devices */
     DFBCHECK(dfb->CreateInputEventBuffer( dfb, DICAPS_ALL,
                                           DFB_FALSE, &events ));

     /* set our cooperative level to DFSCL_FULLSCREEN
        for exclusive access to the primary layer */
     dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );

     /* get the primary surface, i.e. the surface of the
        primary layer we have exclusive access to */
     sdsc.flags       = DSDESC_CAPS | DSDESC_PIXELFORMAT;
     sdsc.caps        = DSCAPS_PRIMARY;
     sdsc.pixelformat = DSPF_LUT8;

     DFBCHECK(dfb->CreateSurface( dfb, &sdsc, &primary ));

     primary->Clear( primary, 0, 0, 0, 0 );

     primary->GetSize( primary, &screen_width, &screen_height );

     /* get access to the palette */
     DFBCHECK(primary->GetPalette( primary, &palette ));

     generate_palette();

     fill_surface( primary );
     
     while (!quit) {
          DFBInputEvent evt;

          while (events->GetEvent( events, DFB_EVENT(&evt) ) == DFB_OK) {
               switch (evt.type) {
                    case DIET_KEYPRESS:
                         switch (evt.key_symbol) {
                              case DIKS_ESCAPE:
                                   quit = 1;
                                   break;
                              default:
                                   ;
                         }
                    default:
                         ;
               }
          }

          rotate_palette();
     }

     /* release our interfaces to shutdown DirectFB */
     palette->Release( palette );
     primary->Release( primary );
     events->Release( events );
     dfb->Release( dfb );

     return 0;
}

