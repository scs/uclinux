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

#include <directfb.h>


/* the super interface */
static IDirectFB *dfb;

/* the primary surface (surface of primary layer) */
static IDirectFBSurface *primary;

/* the temporary surface */
static IDirectFBSurface *tempsurf;

/* provider for our images/font */
static IDirectFBFont *font;

/* Input buffer */
static IDirectFBEventBuffer *events;

/* macro for a safe call to DirectFB functions */
#define DFBCHECK(x...) \
        {                                                                      \
           err = x;                                                            \
           if (err != DFB_OK) {                                                \
              fprintf( stderr, "%s <%d>:\n\t", __FILE__, __LINE__ );           \
              DirectFBErrorFatal( #x, err );                                   \
           }                                                                   \
        }

static char *rules[] = { "CLEAR", "SRC", "SRC OVER", "DST OVER",
                         "SRC IN", "DST IN", "SRC OUT", "DST OUT",
                         "SRC ATOP", "DST ATOP", "ADD", "XOR" };
static int num_rules = sizeof( rules ) / sizeof( rules[0] );

static int screen_width, screen_height;

int main( int argc, char *argv[] )
{
     int                     i;
     int                     step;
     DFBResult               err;
     DFBSurfaceDescription   sdsc;
     DFBFontDescription      fdsc;
     IDirectFBImageProvider *provider;

     DFBCHECK(DirectFBInit( &argc, &argv ));

     /* create the super interface */
     DFBCHECK(DirectFBCreate( &dfb ));

     /* create an event buffer with all devices attached that have keys */
     DFBCHECK(dfb->CreateInputEventBuffer( dfb, DICAPS_KEYS, DFB_FALSE, &events ));

     /* set our cooperative level to DFSCL_FULLSCREEN
        for exclusive access to the primary layer */
     dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );


     /* get the primary surface, i.e. the surface of the
        primary layer we have exclusive access to */
     sdsc.flags = DSDESC_CAPS;
     sdsc.caps  = DSCAPS_PRIMARY | DSCAPS_FLIPPING | DSCAPS_PREMULTIPLIED;

     DFBCHECK(dfb->CreateSurface( dfb, &sdsc, &primary ));

     primary->Clear( primary, 0, 0, 0, 0 );
     primary->Flip( primary, NULL, DSFLIP_NONE );

     primary->GetSize( primary, &screen_width, &screen_height );

     step = screen_width / 5;


     /* create the temporary surface */
     sdsc.flags       = DSDESC_CAPS | DSDESC_PIXELFORMAT | DSDESC_WIDTH | DSDESC_HEIGHT;
     sdsc.caps        = DSCAPS_PREMULTIPLIED;
     sdsc.pixelformat = DSPF_ARGB;
     sdsc.width       = screen_width;
     sdsc.height      = screen_height;

     DFBCHECK(dfb->CreateSurface( dfb, &sdsc, &tempsurf ));



     /* Load background image. */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/wood_andi.jpg", &provider ));

     /* Render to temporary surface. */
     provider->RenderTo( provider, tempsurf, NULL );
     provider->Release( provider );

     /* Blit background onto primary surface (dimmed). */
     primary->SetBlittingFlags( primary, DSBLIT_COLORIZE );
     primary->SetColor( primary, 190, 200, 180, 0 );
     primary->Blit( primary, tempsurf, NULL, 0, 0 );


     tempsurf->Clear( tempsurf, 0, 0, 0, 0 );


     tempsurf->SetDrawingFlags( tempsurf, DSDRAW_SRC_PREMULTIPLY | DSDRAW_BLEND );
     tempsurf->SetPorterDuff( tempsurf, DSPD_SRC );

     fdsc.flags = DFDESC_HEIGHT;
     fdsc.height = screen_width/24;

     DFBCHECK(dfb->CreateFont( dfb, FONT, &fdsc, &font ));
     DFBCHECK(tempsurf->SetFont( tempsurf, font ));

     tempsurf->SetColor( tempsurf, 0xFF, 0xFF, 0xFF, 0xFF );
     tempsurf->DrawString( tempsurf, "Porter/Duff Demo", -1, screen_width/2, 20, DSTF_TOPCENTER );

     font->Release( font );


     fdsc.height = screen_width/32;

     DFBCHECK(dfb->CreateFont( dfb, FONT, &fdsc, &font ));
     DFBCHECK(tempsurf->SetFont( tempsurf, font ));


     for (i=0; i<num_rules; i++) {
          int x = (1 + i % 4) * step;
          int y = (0 + i / 4) * 180;

          tempsurf->SetPorterDuff( tempsurf, DSPD_SRC );
          tempsurf->SetColor( tempsurf, 255, 0, 0, 140 );
          tempsurf->FillRectangle( tempsurf, x - 50, y + 100, 80, 70 );

          tempsurf->SetPorterDuff( tempsurf, i+1 );
          tempsurf->SetColor( tempsurf, 0, 0, 255, 200 );
          tempsurf->FillRectangle( tempsurf, x - 30, y + 130, 80, 70 );

          tempsurf->SetPorterDuff( tempsurf, DSPD_SRC_OVER );
          tempsurf->SetColor( tempsurf, 6*0x1F, 6*0x10+0x7f, 0xFF, 0xFF );
          tempsurf->DrawString( tempsurf, rules[i], -1, x, y + 210, DSTF_CENTER | DSTF_TOP );
     }

     font->Release( font );


     primary->SetBlittingFlags( primary, DSBLIT_BLEND_ALPHACHANNEL );
     primary->SetPorterDuff( primary, DSPD_SRC_OVER );
     primary->Blit( primary, tempsurf, NULL, 0, 0 );

     primary->Flip( primary, NULL, DSFLIP_NONE );


     while (1) {
          DFBInputEvent ev;

          events->WaitForEvent( events );

          events->GetEvent( events, DFB_EVENT(&ev) );

          if (ev.type == DIET_KEYRELEASE && ev.key_symbol == DIKS_ESCAPE)
               break;
     }

     /* release our interfaces to shutdown DirectFB */
     tempsurf->Release( tempsurf );
     primary->Release( primary );
     events->Release( events );
     dfb->Release( dfb );

     return 0;
}

