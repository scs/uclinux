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

/******************************************************************************/

static IDirectFB             *dfb     = NULL;
static IDirectFBDisplayLayer *layer   = NULL;
static IDirectFBWindow       *window  = NULL;
static IDirectFBSurface      *surface = NULL;
static IDirectFBEventBuffer  *events  = NULL;

/******************************************************************************/

static void init_application( int *argc, char **argv[] );
static void exit_application( int status );

static void update();

/******************************************************************************/

int
main( int argc, char *argv[] )
{
     /* Initialize application. */
     init_application( &argc, &argv );

     surface->Clear( surface, 0x1e, 0x1e, 0x1e, 0xa6 );

     window->SetOpacity( window, 0xff );

     /* Main loop. */
     while (1) {
          DFBWindowEvent event;

          update();

          events->WaitForEventWithTimeout( events, 0, 100 );

          /* Check for new events. */
          while (events->GetEvent( events, DFB_EVENT(&event) ) == DFB_OK) {
               switch (event.type) {
                    default:
                         break;
               }
          }
     }

     /* Shouldn't reach this. */
     return 0;
}

/******************************************************************************/

static void
init_application( int *argc, char **argv[] )
{
     DFBResult             ret;
     DFBWindowDescription  desc;
     DFBDisplayLayerConfig config;

     /* Initialize DirectFB including command line parsing. */
     ret = DirectFBInit( argc, argv );
     if (ret) {
          DirectFBError( "DirectFBInit() failed", ret );
          exit_application( 1 );
     }

     /* Create the super interface. */
     ret = DirectFBCreate( &dfb );
     if (ret) {
          DirectFBError( "DirectFBCreate() failed", ret );
          exit_application( 2 );
     }

     /* Get the primary display layer. */
     ret = dfb->GetDisplayLayer( dfb, DLID_PRIMARY, &layer );
     if (ret) {
          DirectFBError( "IDirectFB::GetDisplayLayer() failed", ret );
          exit_application( 3 );
     }

     /* Get the screen size etc. */
     layer->GetConfiguration( layer, &config );

     /* Fill the window description. */
     desc.flags  = DWDESC_POSX | DWDESC_POSY |
                   DWDESC_WIDTH | DWDESC_HEIGHT | DWDESC_CAPS;
     desc.posx   = config.width - 192 - 64 - 4;
     desc.posy   = 128;
     desc.width  = 64;
     desc.height = 64;
     desc.caps   = DWCAPS_ALPHACHANNEL | DWCAPS_NODECORATION;

     /* Create the window. */
     ret = layer->CreateWindow( layer, &desc, &window );
     if (ret) {
          DirectFBError( "IDirectFBDisplayLayer::CreateWindow() failed", ret );
          exit_application( 4 );
     }

     /* Get the window's surface. */
     ret = window->GetSurface( window, &surface );
     if (ret) {
          DirectFBError( "IDirectFBWindow::GetSurface() failed", ret );
          exit_application( 5 );
     }

     /* Create an event buffer for all keyboard events. */
     ret = window->CreateEventBuffer( window, &events );
     if (ret) {
          DirectFBError( "IDirectFBWindow::CreateEventBuffer() failed", ret );
          exit_application( 6 );
     }

     /* Add ghost option (behave like an overlay). */
     window->SetOptions( window, DWOP_ALPHACHANNEL | DWOP_GHOST );

     /* Move window to upper stacking class. */
     window->SetStackingClass( window, DWSC_UPPER );

     /* Make it the top most window. */
     window->RaiseToTop( window );
}

static void
exit_application( int status )
{
     /* Release the event buffer. */
     if (events)
          events->Release( events );

     /* Release the window's surface. */
     if (surface)
          surface->Release( surface );

     /* Release the window. */
     if (window)
          window->Release( window );

     /* Release the layer. */
     if (layer)
          layer->Release( layer );

     /* Release the super interface. */
     if (dfb)
          dfb->Release( dfb );

     /* Terminate application. */
     exit( status );
}

/******************************************************************************/

#define JT unsigned long
static double
get_load()
{
     static double old_load = 0;

     double blt_load, ret;
     
     
     static JT old_b, old_t;
     JT        new_b, new_t;
     JT        ticks_past; /* avoid div-by-0 by not calling too often :-( */
     char      dummy[16];
     FILE     *stat;

     stat = fopen ("/proc/bltstat", "r");
     if (!stat)
          return 0;

     if (fscanf (stat, "%s %lu %lu", dummy, &new_b, &new_t) < 3) {
          fclose (stat);
          return 0;
     }

     fclose (stat);

     ticks_past = new_t - old_t;
     if (ticks_past)
          blt_load = ( (double)new_b - (double)old_b ) / (double)ticks_past;
     else
          blt_load = 0;

     old_b = new_b;
     old_t = new_t;
     
     
     ret = (blt_load + old_load + old_load + old_load) / 4.0;

     old_load = blt_load;

     return ret;
}
#undef JT

static void
update()
{
     int load = get_load() * 64;

     surface->SetColor( surface, 0x1e, 0x1e, 0x1e, 0xa6 );
     surface->FillRectangle( surface, 63, 0, 1, 64 - load );

     surface->SetColor( surface, 0xff, 0x60, 0x00, 0xcc );
     surface->FillRectangle( surface, 63, 64 - load, 1, load );

     surface->Blit( surface, surface, NULL, -1, 0 );

     surface->SetColor( surface, 0x60, 0x60, 0x60, 0xff );
     surface->FillRectangle( surface,  0,  0, 64,  1 );
     surface->FillRectangle( surface,  0, 63, 64,  1 );
     surface->FillRectangle( surface,  0,  1,  1, 62 );
     surface->FillRectangle( surface, 63,  1,  1, 62 );


     surface->Flip( surface, NULL, 0 );
}

