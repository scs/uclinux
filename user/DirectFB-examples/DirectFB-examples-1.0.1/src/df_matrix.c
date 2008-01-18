/* cairo - a vector graphics library with display and print output
 *
 * Copyright © 2002 University of Southern California
 *
 * This library is free software; you can redistribute it and/or
 * modify it either under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation
 * (the "LGPL") or, at your option, under the terms of the Mozilla
 * Public License Version 1.1 (the "MPL"). If you do not alter this
 * notice, a recipient may use your version of this file under either
 * the MPL or the LGPL.
 *
 * You should have received a copy of the LGPL along with this library
 * in the file COPYING-LGPL-2.1; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 * You should have received a copy of the MPL along with this library
 * in the file COPYING-MPL-1.1
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY
 * OF ANY KIND, either express or implied. See the LGPL or the MPL for
 * the specific language governing rights and limitations.
 *
 * The Original Code is the cairo graphics library.
 *
 * The Initial Developer of the Original Code is University of Southern
 * California.
 *
 * Contributor(s):
 *	Carl D. Worth <cworth@cworth.org>
 */

/*
   (c) Copyright 2001-2007  The DirectFB Organization (directfb.org)
   (c) Copyright 2000-2004  Convergence (integrated media) GmbH

   All rights reserved.

   Written by Denis Oliver Kropp <dok@directfb.org>,
              Andreas Hundt <andi@fischlustig.de>,
              Sven Neumann <neo@directfb.org>,
              Ville Syrjälä <syrjala@sci.fi> and
              Claudio Ciccani <klan@users.sf.net>.
              
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

#include <math.h>

/******************************************************************************/

static IDirectFB            *dfb     = NULL;
static IDirectFBSurface     *primary = NULL;
static IDirectFBEventBuffer *events  = NULL;

/******************************************************************************/

static void init_application( int *argc, char **argv[] );
static void exit_application( int status );

/******************************************************************************/

typedef struct _cairo_matrix {
    double xx; double yx;
    double xy; double yy;
    double x0; double y0;
} cairo_matrix_t;

static inline void
cairo_matrix_multiply (cairo_matrix_t *result, const cairo_matrix_t *a, const cairo_matrix_t *b)
{
    cairo_matrix_t r;

    r.xx = a->xx * b->xx + a->yx * b->xy;
    r.yx = a->xx * b->yx + a->yx * b->yy;

    r.xy = a->xy * b->xx + a->yy * b->xy;
    r.yy = a->xy * b->yx + a->yy * b->yy;

    r.x0 = a->x0 * b->xx + a->y0 * b->xy + b->x0;
    r.y0 = a->x0 * b->yx + a->y0 * b->yy + b->y0;

    *result = r;
}

static inline void
cairo_matrix_init (cairo_matrix_t *matrix,
		   double xx, double yx,

		   double xy, double yy,
		   double x0, double y0)
{
    matrix->xx = xx; matrix->yx = yx;
    matrix->xy = xy; matrix->yy = yy;
    matrix->x0 = x0; matrix->y0 = y0;
}

static inline void
cairo_matrix_init_identity (cairo_matrix_t *matrix)
{
    cairo_matrix_init (matrix,
		       1, 0,
		       0, 1,
		       0, 0);
}

static inline void
cairo_matrix_init_translate (cairo_matrix_t *matrix,
			     double tx, double ty)
{
    cairo_matrix_init (matrix,
		       1, 0,
		       0, 1,
		       tx, ty);
}

static inline void
cairo_matrix_translate (cairo_matrix_t *matrix, double tx, double ty)
{
    cairo_matrix_t tmp;

    cairo_matrix_init_translate (&tmp, tx, ty);

    cairo_matrix_multiply (matrix, &tmp, matrix);
}

static inline void
cairo_matrix_init_scale (cairo_matrix_t *matrix,
			 double sx, double sy)
{
    cairo_matrix_init (matrix,
		       sx,  0,
		       0, sy,
		       0, 0);
}

static inline void
cairo_matrix_scale (cairo_matrix_t *matrix, double sx, double sy)
{
    cairo_matrix_t tmp;

    cairo_matrix_init_scale (&tmp, sx, sy);

    cairo_matrix_multiply (matrix, &tmp, matrix);
}

static inline void
cairo_matrix_init_rotate (cairo_matrix_t *matrix,
                          double radians)
{
    double  s;
    double  c;

    s = sin (radians);
    c = cos (radians);

    cairo_matrix_init (matrix,
		       c, s,
		       -s, c,
		       0, 0);
}

static inline void
cairo_matrix_rotate (cairo_matrix_t *matrix, double radians)
{
    cairo_matrix_t tmp;

    cairo_matrix_init_rotate (&tmp, radians);

    cairo_matrix_multiply (matrix, &tmp, matrix);
}

/******************************************************************************/

static inline void
set_cairo_matrix( const cairo_matrix_t *cairo )
{
     s32 matrix[6];

     matrix[0] = (s32)(cairo->xx * 0x10000);
     matrix[1] = (s32)(cairo->xy * 0x10000);
     matrix[2] = (s32)(cairo->x0 * 0x10000);
     matrix[3] = (s32)(cairo->yx * 0x10000);
     matrix[4] = (s32)(cairo->yy * 0x10000);
     matrix[5] = (s32)(cairo->y0 * 0x10000);

     primary->SetMatrix( primary, matrix );
}

/******************************************************************************/

int
main( int argc, char *argv[] )
{
     int            i = 0;
     int            width, height;
     cairo_matrix_t matrix;

     /* Initialize application. */
     init_application( &argc, &argv );

     /* Query size of output surface. */
     primary->GetSize( primary, &width, &height );

     /* Transform coordinates to have 0,0 in the center. */
     cairo_matrix_init_translate( &matrix, width/2, height/2 );

     /* Enable coordinate transformation and anti-aliasing for all drawing/blitting, but not Clear(). */
     primary->SetRenderOptions( primary, DSRO_MATRIX | DSRO_ANTIALIAS );

     /* Main loop. */
     while (1) {
          DFBInputEvent event;

          /* Convert doubles to DirectFB's fixed point 16.16 and call IDirectFBSurface::SetMatrix(). */
          set_cairo_matrix( &matrix );

          /* Clear the frame. */
          primary->Clear( primary, 0x00, 0x00, 0x00, 0xff );


          /* Fill a small white rectangle in the middle. */
          primary->SetColor( primary, 0xff, 0xff, 0xff, 0xff );
          primary->FillRectangle( primary, -20, -20, 40, 40 );

          /* Fill a small green rectangle on the left. */
          primary->SetColor( primary, 0x00, 0xff, 0x00, 0xff );
          primary->FillRectangle( primary, -120, -20, 40, 40 );

          /* Fill a small blue rectangle at the top. */
          primary->SetColor( primary, 0x00, 0x00, 0xff, 0xff );
          primary->FillRectangle( primary, -20, -120, 40, 40 );

          /* Fill a red rectangle down-right without AA. */
          primary->SetColor( primary, 0xff, 0, 0, 0xff );
          primary->SetRenderOptions( primary, DSRO_MATRIX );
          primary->FillRectangle( primary, 100, 100, 100, 100 );
          primary->SetRenderOptions( primary, DSRO_MATRIX | DSRO_ANTIALIAS );

          /* Draw a white outline around the red rectangle. */
          primary->SetColor( primary, 0xcc, 0xcc, 0xcc, 0xff );
          primary->DrawRectangle( primary, 100, 100, 100, 100 );

          /* Draw a line across the objects. */
          primary->SetColor( primary, 0x12, 0x34, 0x56, 0xff );
          primary->DrawLine( primary, 0, 0, 300, 300 );

          primary->SetColor( primary, 0xff, 0xff, 0xff, 0xff );
          primary->DrawLine( primary, -20, -20, -300, -300 );

          /* Fill a triangle. */
          primary->SetColor( primary, 0x80, 0x90, 0x70, 0xff );
          primary->FillTriangle( primary, 0, 0, 200, -210, -200, 190 );


          /* Flip the output surface. */
          primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );

//          primary->Dump( primary, "/", "df_matrix" );

          /* Rotate scene slightly. */
          cairo_matrix_rotate( &matrix, 0.1 );

          cairo_matrix_scale( &matrix, 0.99, 0.99 );
          //cairo_matrix_scale( &matrix, 1.001, 1.001 );

          if (++i == 500) {
               i = 0;

               cairo_matrix_init_translate( &matrix, width/2, height/2 );
          }

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

     /* Create the super interface. */
     ret = DirectFBCreate( &dfb );
     if (ret) {
          DirectFBError( "DirectFBCreate() failed", ret );
          exit_application( 2 );
     }

     /* Request fullscreen mode. */
     dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );

     /* Fill the surface description. */
     desc.flags = DSDESC_CAPS;
     desc.caps  = DSCAPS_PRIMARY | DSCAPS_DOUBLE;
     
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
     
     /* Clear with black. */
     primary->Clear( primary, 0x00, 0x00, 0x00, 0xff );
     primary->Flip( primary, NULL, 0 );
}

static void
exit_application( int status )
{
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

