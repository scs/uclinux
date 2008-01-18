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
     desc.posx   = config.width - 288;
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

static void total_dio(double *r_total, double *w_total)
{
     unsigned long  new_r_total = 0;
     unsigned long  new_w_total = 0;
     double         tmp_r_total = 0;
     double         tmp_w_total = 0;
     static unsigned long old_r_total, top_r_total;
     static unsigned long old_w_total, top_w_total;
     char           buf[64*1024];
     char          *tmp;
     unsigned long  dummy;
     unsigned long  readsec = 0;
     unsigned long  writesec = 0;
     FILE          *stat;

     stat = fopen ("/proc/stat", "r");
     if (!stat)
          return;

     while (fgets (buf, 64*1024, stat)) {
       if (strncmp("disk_io:",buf,sizeof("disk_io:")-1))
         continue;

       tmp = buf;
       while ((tmp = strchr(tmp,' '))) {
         tmp++;
         if (sscanf (tmp, "(%lu,%lu):(%lu,%lu,%lu,%lu,%lu)", &dummy, &dummy, &dummy, &dummy, &readsec, &dummy, &writesec) < 7)
           continue;
         new_r_total += readsec;
         new_w_total += writesec;
       }
     }

     fclose (stat);

     if (old_r_total) {
       tmp_r_total = new_r_total - old_r_total;
       if (top_r_total < tmp_r_total)
         top_r_total = tmp_r_total;
       tmp_r_total /= top_r_total;
       old_r_total = new_r_total;
     } else {
       old_r_total = new_r_total;
     }

     *r_total = tmp_r_total;

     if (old_w_total) {
       tmp_w_total = new_w_total - old_w_total;
       if (top_w_total < tmp_w_total)
         top_w_total = tmp_w_total;
       tmp_w_total /= top_w_total;
       old_w_total = new_w_total;
     } else {
       old_w_total = new_w_total;
     }

     *w_total = tmp_w_total;
}

static void
get_load(int mult, int *ret_r_total, int *ret_w_total)
{
     static double old_r_total = 0;
     static double old_w_total = 0;

     double r_total = 0, w_total = 0;

     total_dio( &r_total, &w_total );

     *ret_r_total = ((r_total + old_r_total + old_r_total + old_r_total) / 3.0)*mult;
     *ret_w_total = ((w_total + old_w_total + old_w_total + old_w_total) / 3.0)*mult;

     old_r_total = r_total;
     old_w_total = w_total;
}

static void
update()
{
     int read_load, write_load;
     get_load(64,&read_load,&write_load);
     surface->SetColor( surface, 0xff, 0xff, 0xff, 0x30 );

     if (read_load > write_load) {
       surface->FillRectangle( surface, 63, 0, 1, 64 - read_load );
       surface->SetColor( surface, 0xA0, 0x00, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - read_load, 1, read_load );
       surface->SetColor( surface, 0xF0, 0x00, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - write_load, 1, write_load );
     } else {
       surface->FillRectangle( surface, 63, 0, 1, 64 - write_load );
       surface->SetColor( surface, 0xF0, 0x00, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - write_load, 1, write_load );
       surface->SetColor( surface, 0xA0, 0x00, 0x00, 0xcc );
       surface->FillRectangle( surface, 63, 64 - read_load, 1, read_load );
     }

     surface->Blit( surface, surface, NULL, -1, 0 );

     surface->SetColor( surface, 0x00, 0x00, 0x00, 0x60 );
     surface->DrawRectangle( surface, 0, 0, 64, 64 );


     surface->Flip( surface, NULL, 0 );
}

