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
#include <string.h>

typedef struct {
     int  width;
     int  height;
     int  skip;
     u8  *data;

     IDirectFBSurface *surface;
} Fire;

/******************************************************************************/

static IDirectFB            *dfb     = NULL;
static IDirectFBSurface     *primary = NULL;
static IDirectFBEventBuffer *events  = NULL;

static Fire *fire = NULL;

/******************************************************************************/

static void init_application( int *argc, char **argv[] );
static void exit_application( int status );

static void generate_palette( IDirectFBSurface *surface );
static void fade_out_palette( IDirectFBSurface *surface );

static Fire *create_fire ( IDirectFBSurface *surface );
static void  render_fire ( Fire *fire );
static void  destroy_fire( Fire *fire );

/******************************************************************************/

static unsigned int rand_pool = 0x12345678;
static unsigned int rand_add  = 0x87654321;

static inline unsigned int myrand()
{
     rand_pool ^= ((rand_pool << 7) | (rand_pool >> 25));
     rand_pool += rand_add;
     rand_add  += rand_pool;

     return rand_pool;
}

/******************************************************************************/

int
main( int argc, char *argv[] )
{
     /* Initialize application. */
     init_application( &argc, &argv );
     
     /* Main loop. */
     while (1) {
          DFBInputEvent event;

          /* Render and display the next frame. */
          render_fire( fire );

          /* Check for new events. */
          while (events->GetEvent( events, DFB_EVENT(&event) ) == DFB_OK) {

               /* Handle key press events. */
               if (event.type == DIET_KEYPRESS) {
                    switch (event.key_symbol) {
                         case DIKS_ESCAPE:
                         case DIKS_POWER:
                         case DIKS_BACK:
                         case DIKS_SMALL_Q:
                         case DIKS_CAPITAL_Q:
                              exit_application( 0 );
                              break;

                         default:
                              break;
                    }
               }
          }
     }

     /* Shouldn't reach this. */
     return 0;
}

/******************************************************************************/

static void
generate_palette( IDirectFBSurface *surface )
{
     u32               i;
     DFBResult         ret;
     DFBColor          colors[256];
     IDirectFBPalette *palette;

     /* Get access to the surface's palette data. */
     ret = surface->GetPalette( surface, &palette );
     if (ret) {
          DirectFBError( "IDirectFBSurface::GetPalette() failed", ret );
          exit_application( 8 );
     }

     /* Calculate RGB values. */
     for (i = 0; i < 48; i++) {
          colors[47-i].r = ((48*48*48-1) - (i * i * i)) / (48*48/4);
          colors[i].g = 0;
          colors[i].b = 0;
     }

     for (i = 0; i < 104; i++) {
          colors[i+48].r = 192;
          colors[i+48].g = i * 24 / 13;
          colors[i+48].b = 0;
     }

     for (i = 0; i < 104; i++) {
          colors[i+152].r = 192;
          colors[i+152].g = 192;
          colors[i+152].b = i * 24 / 13;
     }

     /* Calculate alpha values. */
     for (i = 0; i < 256; i++)
          colors[255-i].a = ~(i * i * i * i) >> 24;

     /* Set new palette data. */
     ret = palette->SetEntries( palette, colors, 256, 0 );
     if (ret) {
          DirectFBError( "IDirectFBPalette::SetEntries() failed", ret );
          exit_application( 9 );
     }

     /* Release the palette interface. */
     palette->Release( palette );
}

static void
fade_out_palette( IDirectFBSurface *surface )
{
     int               i;
     int               fade;
     DFBResult         ret;
     DFBColor          colors[256];
     IDirectFBPalette *palette;

     /* Get access to the surface's palette data. */
     ret = surface->GetPalette( surface, &palette );
     if (ret) {
          DirectFBError( "IDirectFBSurface::GetPalette() failed", ret );
          return;
     }

     /* Get palette data. */
     ret = palette->GetEntries( palette, colors, 256, 0 );
     if (ret) {
          DirectFBError( "IDirectFBPalette::SetEntries() failed", ret );
          return;
     }

     /* Fade out... */
     do {
          fade = 0;

          /* Calculate new palette entries. */
          for (i = 0; i < 256; i++) {
               if (colors[i].r || colors[i].g || colors[i].b)
                    fade = 1;

               if (colors[i].r)
                    colors[i].r -= (colors[i].r >> 4) + 1;

               if (colors[i].g)
                    colors[i].g -= (colors[i].g >> 4) + 1;
          
               if (colors[i].b)
                    colors[i].b -= (colors[i].b >> 4) + 1;
          }

          /* Wait for vertical retrace. */
          dfb->WaitForSync( dfb );
          
          /* Set new palette data. */
          ret = palette->SetEntries( palette, colors, 256, 0 );
          if (ret) {
               DirectFBError( "IDirectFBPalette::SetEntries() failed", ret );
               return;
          }
     } while (fade);

     /* Release the palette interface. */
     palette->Release( palette );
}

static Fire *
create_fire( IDirectFBSurface *surface )
{
     Fire *fire;

     /* Allocate structure. */
     fire = calloc( 1, sizeof(Fire) );
     if (!fire) {
          fprintf( stderr, "Out of system memory!\n" );
          return NULL;
     }

     /* Retrieve the width and height. */
     surface->GetSize( surface, &fire->width, &fire->height );
     
     /* Calculate how much of the height to skip. */
     fire->skip   = fire->height - 256;
     if (fire->skip < 0)
          fire->skip = 0;
     
     if (fire->height > 256)
          fire->height = 256;

     /* Allocate fire data including an additional line. */
     fire->data = calloc( fire->height + 1, fire->width );
     if (!fire->data) {
          fprintf( stderr, "Out of system memory!\n" );
          free( fire );
          return NULL;
     }
     
     /* Generate the fire palette. */
     generate_palette( surface );

     /* Remember the surface. */
     fire->surface = surface;

     return fire;
}

static void
render_fire( Fire *fire )
{
     int        i;
     DFBResult  ret;

     void      *surface_data;
     int        surface_pitch;

     u8        *fire_data   = fire->data;
     int        fire_height = fire->height;

     IDirectFBSurface *surface = fire->surface;

     /* Loop through all lines. */
     while (fire_height--) {
          u8 *d = fire_data + 1;
          u8 *s = fire_data + fire->width;

          /* Loop through all columns but the first and the last one. */
          for (i = 0; i < fire->width - 2; i++) {
               int val;
                
               /* Calculate the average of the current pixel and three below. */
               val = (d[i] + s[i] + s[i+1] + s[i+2]) >> 2;

               /* Add some randomness. */
               if (val)
                    val += (myrand() % 3) - 1;

               /* Write back with overflow checking. */
               d[i] = (val > 0xff) ? 0xff : val;
          }

          /* Increase fire data pointer to the next line. */
          fire_data += fire->width;
     }

     /* Put some flammable stuff into the additional line. */
     memset( fire_data, 0x20, fire->width );
     for (i = 0; i < fire->width/2; i++)
          fire_data[myrand()%fire->width] = 0xff;

     /* Lock the surface's data for direct write access. */
     ret = surface->Lock( surface, DSLF_WRITE, &surface_data, &surface_pitch );
     if (ret) {
          DirectFBError( "IDirectFBSurface::Lock() failed", ret );
          exit_application( 6 );
     }

     /* Add skip offset. */
     surface_data += surface_pitch * fire->skip;

     /* Write fire data to the surface. */
     for (i = 0; i < fire->height; i++) {
          /* Copy one line to the surface. */
          memcpy( surface_data, fire->data + i * fire->width, fire->width );

          /* Increase surface data pointer to the next line. */
          surface_data += surface_pitch;
     }

     /* Unlock the surface's data. */
     ret = surface->Unlock( surface );
     if (ret) {
          DirectFBError( "IDirectFBSurface::Unlock() failed", ret );
          exit_application( 7 );
     }

     /* Flip the surface to display the new frame. */
     surface->Flip( surface, NULL, 0 );
}

static void
destroy_fire( Fire *fire )
{
     /* Deallocate fire data. */
     free( fire->data );

     /* Deallocate structure. */
     free( fire );
}

/******************************************************************************/

static void
init_application( int *argc, char **argv[] )
{
     DFBResult             ret;
     DFBSurfaceDescription desc;

     /* Initialize DirectFB including command line parsing. */
     ret = DirectFBInit( argc, argv );
     if (ret) {
          DirectFBError( "DirectFBInit() failed", ret );
          exit_application( 1 );
     }

     DirectFBSetOption ("bg-none", NULL);

     /* Create the super interface. */
     ret = DirectFBCreate( &dfb );
     if (ret) {
          DirectFBError( "DirectFBCreate() failed", ret );
          exit_application( 2 );
     }

     /* Request fullscreen mode. */
     dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );

     /* Fill the surface description. */
     desc.flags       = DSDESC_CAPS | DSDESC_PIXELFORMAT;
     desc.caps        = DSCAPS_PRIMARY | DSCAPS_DOUBLE;
     desc.pixelformat = DSPF_LUT8;
     
     /* Create an 8 bit palette surface. */
     ret = dfb->CreateSurface( dfb, &desc, &primary );
     if (ret) {
          DirectFBError( "IDirectFB::CreateSurface() failed", ret );
          exit_application( 3 );
     }
     
     /* Create an event buffer with key capable devices attached. */
     ret = dfb->CreateInputEventBuffer( dfb, DICAPS_KEYS, DFB_FALSE, &events );
     if (ret) {
          DirectFBError( "IDirectFB::CreateEventBuffer() failed", ret );
          exit_application( 4 );
     }
     
     /* Create the fire. */
     fire = create_fire( primary );
     if (!fire)
          exit_application( 5 );

     /* Clear both buffers with black. */
     primary->Clear( primary, 0x00, 0x00, 0x00, 0xff );
     primary->Flip( primary, NULL, 0 );
     primary->Clear( primary, 0x00, 0x00, 0x00, 0xff );
}

static void
exit_application( int status )
{
     /* Fade screen to black. */
     if (primary)
          fade_out_palette( primary );

     /* Destroy the fire. */
     if (fire)
          destroy_fire( fire );

     /* Release the event buffer. */
     if (events)
          events->Release( events );

     /* Release the primary surface. */
     if (primary)
          primary->Release( primary );

     /* Release the super interface. */
     if (dfb)
          dfb->Release( dfb );

     /* Terminate application. */
     exit( status );
}

