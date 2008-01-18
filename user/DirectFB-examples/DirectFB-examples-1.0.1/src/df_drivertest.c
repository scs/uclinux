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

/* DirectFB interfaces */
IDirectFB               *dfb;
IDirectFBSurface        *primary;
IDirectFBDisplayLayer   *layer;
IDirectFBEventBuffer    *keybuffer;
IDirectFBImageProvider  *provider;
IDirectFBFont           *font;

/* DirectFB surfaces */
IDirectFBSurface *maskimage;
IDirectFBSurface *testimage;
IDirectFBSurface *testimage2;

/* values on which placement of penguins and text depends */
int xres;
int yres;
int fontheight;

void init_resources( int argc, char *argv[] )
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

     DFBCHECK(dfb->GetDisplayLayer( dfb, DLID_PRIMARY, &layer ));

     /* get the primary surface, i.e. the surface of the primary layer we have
        exclusive access to */
     dsc.flags = DSDESC_CAPS;
     dsc.caps = DSCAPS_PRIMARY | DSCAPS_DOUBLE | DSCAPS_VIDEOONLY;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &primary ));
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

     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR"/testmask.png",
                                        &provider ));

     DFBCHECK (provider->GetSurfaceDescription (provider, &dsc));
     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &maskimage ));

     DFBCHECK(provider->RenderTo( provider, maskimage, NULL ));
     provider->Release( provider );

     /* load the penguin destination mask */
     DFBCHECK(dfb->CreateImageProvider( dfb, DATADIR
                                        "/pngtest.png",
                                        &provider ));

     DFBCHECK(provider->GetSurfaceDescription( provider, &dsc ));

     dsc.width  = 128;
     dsc.height = 128;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &testimage ));

     DFBCHECK(provider->RenderTo( provider, testimage, NULL ));
     
     dsc.width  = 111;
     dsc.height = 77;

     DFBCHECK(dfb->CreateSurface( dfb, &dsc, &testimage2 ));

     DFBCHECK(provider->RenderTo( provider, testimage2, NULL ));
     
     
     provider->Release( provider );
}

/*
 * deinitializes resources and DirectFB
 */
void deinit_resources()
{
     maskimage->Release( maskimage );
     testimage->Release( testimage );
     testimage2->Release( testimage2 );
     primary->Release( primary );
     keybuffer->Release( keybuffer );
     layer->Release( layer );
     dfb->Release( dfb );

}

int main( int argc, char *argv[] )
{
     DFBResult err;
     int quit = 0;

     init_resources( argc, argv );

     primary->Clear( primary, 0x00, 0x00, 0x00, 0xFF );
     primary->Blit( primary, maskimage, NULL, 0, 0 );
     /* flip display */
     DFBCHECK(primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC ));

     /* main loop */
     while (!quit) {
          DFBInputEvent evt;

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
                         /* test blitting */
                         case DIKS_SMALL_B:
                              primary->Blit( primary, maskimage, NULL, 0, 0 );
                              primary->Blit( primary, testimage, NULL, 20, 20 );
                              primary->Blit( primary, testimage2, NULL, 319, 70 );
                              primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
                              break;
                         /* test stretched blitting */
                         case DIKS_SMALL_S:
                              {
                                   DFBRectangle rect1 = {319,70,111,77};
                                   DFBRectangle rect2 = {20,20,128,128};
                                   primary->Blit( primary, maskimage, NULL, 0, 0 );
                                   primary->StretchBlit( primary, testimage, NULL, &rect1 );
                                   primary->StretchBlit( primary, testimage2, NULL, &rect2 );
                                   primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
                              }
                              break;
                         case DIKS_SMALL_F:
                              primary->SetDrawingFlags( primary, DSDRAW_NOFX );
                              primary->Blit( primary, maskimage, NULL, 0, 0 );
                              primary->SetColor( primary, 0xFF, 0x00, 0xFF, 0xFF );
                              primary->FillRectangle( primary, 319, 70, 111, 77 );
                              primary->FillRectangle( primary, 20, 20, 128, 128 );
                              primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
                              break;
                         case DIKS_SMALL_D:
                              primary->SetDrawingFlags( primary, DSDRAW_NOFX );
                              primary->Blit( primary, maskimage, NULL, 0, 0 );
                              primary->SetColor( primary, 0xFF, 0x00, 0xFF, 0xFF );
                              primary->DrawRectangle( primary, 319, 70, 111, 77 );
                              primary->DrawRectangle( primary, 20, 20, 128, 128 );
                              primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
                              break;
                         case DIKS_SMALL_R:
                              primary->Blit( primary, maskimage, NULL, 0, 0 );
                              primary->SetDrawingFlags( primary, DSDRAW_BLEND );
                              primary->SetColor( primary, 0xFF, 0x00, 0xFF, 0x80 );
                              primary->FillRectangle( primary, 319, 70, 111, 77 );
                              primary->FillRectangle( primary, 20, 20, 128, 128 );
                              primary->SetDrawingFlags( primary, DSDRAW_NOFX );
                              primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
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
