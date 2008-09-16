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

char *wanted_iface = "eth0";

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
     /* Parse command line. */
     if (argc > 1 && *argv[1] != '\0')
          wanted_iface = argv[1];
     
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
     desc.posx   = config.width - 160;
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
static void input_output(double *in, double *out)
{
     static JT      old_in = 0, old_out = 0;
     static double  top_in = 10, top_out = 10;
     double         tmp_in = 0, tmp_out = 0;
     JT             new_in, new_out;
     JT             dummy;
     int            found = 0;
     char           iface[64];
     char           buf[256];
     FILE          *stat;

     stat = fopen ("/proc/net/dev", "r");
     if (!stat)
          return;

     while (fgets (buf, 256, stat)) {
          int i = 0;

          while (buf[i] != 0) {
               if (buf[i] == ':')
                    buf[i] = ' ';

               i++;
          }

          if (sscanf (buf, "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu "
                      "%lu %lu %lu %lu\n", iface, &new_in, &dummy, &dummy,
                      &dummy, &dummy, &dummy, &dummy, &dummy, &new_out, &dummy,
                      &dummy, &dummy, &dummy, &dummy, &dummy, &dummy) < 17)
               continue;
          
          if (!strcmp (iface, wanted_iface)) {
               found = 1;
               break;
          }
     }

     fclose (stat);

     if (found) {
          if (old_in) {
               tmp_in = new_in - old_in;

               if (top_in < tmp_in)
                    top_in = tmp_in;

               tmp_in /= top_in;
          }

          if (old_out) {
               tmp_out = new_out - old_out;

               if (top_out < tmp_out)
                    top_out = tmp_out;

               tmp_out /= top_out;
          }

          old_in  = new_in;
          old_out = new_out;
     }

     SET_IF_DESIRED(in, tmp_in);
     SET_IF_DESIRED(out, tmp_out);
}
#undef JT

static void
get_load(int mult, int *ret_r_total, int *ret_t_total)
{
     static double old_r_total = 0;
     static double old_t_total = 0;

     double r_total = 0, t_total = 0;

     input_output( &r_total, &t_total );

     *ret_r_total = ((r_total + old_r_total + old_r_total + old_r_total) / 3.0)*mult;
     *ret_t_total = ((t_total + old_t_total + old_t_total + old_t_total) / 3.0)*mult;

     old_r_total = r_total;
     old_t_total = t_total;
}

static void
update()
{
     int rx_load, tx_load;
     get_load(64,&rx_load,&tx_load);
     surface->SetColor( surface, 0xff, 0xff, 0xff, 0x30 );

     if (rx_load > tx_load) {
       surface->FillRectangle( surface, 63, 0, 1, 64 - rx_load );
       surface->SetColor( surface, 0x00, 0xA0, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - rx_load, 1, rx_load );
       surface->SetColor( surface, 0x00, 0xF0, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - tx_load, 1, tx_load );
     } else {
       surface->FillRectangle( surface, 63, 0, 1, 64 - tx_load );
       surface->SetColor( surface, 0x00, 0xF0, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - tx_load, 1, tx_load );
       surface->SetColor( surface, 0x00, 0xA0, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - rx_load, 1, rx_load );
     }

     surface->Blit( surface, surface, NULL, -1, 0 );

     surface->SetColor( surface, 0x00, 0x00, 0x00, 0x60 );
     surface->DrawRectangle( surface, 0, 0, 64, 64 );


     surface->Flip( surface, NULL, 0 );
}

