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

     surface->Clear( surface, 0xff, 0xff, 0xff, 0x30 );

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
     desc.posx   = config.width - 224;
     desc.posy   = 8;
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

#define SET_IF_DESIRED(x,y) do{  if(x) *(x) = (y); }while(0)
#define JT unsigned long
static void four_cpu_numbers(int *uret, int *nret, int *sret, int *iret)
{
     int       tmp_u, tmp_n, tmp_s, tmp_i;
     static JT old_u, old_n, old_s, old_i, old_wa, old_hi, old_si;
     JT        new_u, new_n, new_s, new_i, new_wa = 0, new_hi = 0, new_si = 0;
     JT        ticks_past; /* avoid div-by-0 by not calling too often :-( */
     char      dummy[16];
     FILE     *stat;

     stat = fopen ("/proc/stat", "r");
     if (!stat)
          return;

     if (fscanf (stat, "%s %lu %lu %lu %lu %lu %lu %lu", dummy,
                 &new_u, &new_n, &new_s, &new_i, &new_wa, &new_hi, &new_si) < 5)
     {
          fclose (stat);
          return;
     }

     fclose (stat);

     ticks_past = ((new_u + new_n + new_s + new_i + new_wa + new_hi + new_si) -
                   (old_u + old_n + old_s + old_i + old_wa + old_hi + old_si));
     if (ticks_past) {
          tmp_u = ((new_u - old_u) << 16) / ticks_past;
          tmp_n = ((new_n - old_n) << 16) / ticks_past;
          tmp_s = ((new_s - old_s) << 16) / ticks_past;
          tmp_i = ((new_i - old_i) << 16) / ticks_past;
     }
     else {
          tmp_u = 0;
          tmp_n = 0;
          tmp_s = 0;
          tmp_i = 0;
     }

     SET_IF_DESIRED(uret, tmp_u);
     SET_IF_DESIRED(nret, tmp_n);
     SET_IF_DESIRED(sret, tmp_s);
     SET_IF_DESIRED(iret, tmp_i);

     old_u  = new_u;
     old_n  = new_n;
     old_s  = new_s;
     old_i  = new_i;
     old_wa = new_wa;
     old_hi = new_hi;
     old_si = new_si;
}
#undef JT

static int
get_load()
{
     static int old_load = 0;

     int u = 0, n = 0, s = 0, i, load;

     four_cpu_numbers( &u, &n, &s, &i );

     load = u + n + s;

     old_load = (load + load + load + old_load) >> 2;

     return old_load >> 10;
}

static void
update()
{
     int load = get_load();

     surface->SetColor( surface, 0xff, 0xff, 0xff, 0x30 );
     surface->FillRectangle( surface, 63, 0, 1, 64 - load );

     surface->SetColor( surface, 0x00, 0x50, 0xd0, 0xcc );
     surface->FillRectangle( surface, 63, 64 - load, 1, load );

     surface->Blit( surface, surface, NULL, -1, 0 );

     surface->SetColor( surface, 0x00, 0x00, 0x00, 0x60 );
     surface->DrawRectangle( surface, 0, 0, 64, 64 );


     surface->Flip( surface, NULL, 0 );
}

