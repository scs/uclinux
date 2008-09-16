/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
   (c) Copyright 2002-2004  convergence GmbH.

   All rights reserved.

   Written by Denis Oliver Kropp <dok@directfb.org>,
              Andreas Hundt <andi@fischlustig.de>,
              Sven Neumann <neo@directfb.org> and
              Ville Syrjälä <syrjala@sci.fi>.

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

#include "ve.h"

int
main( int argc, char *argv[] )
{
     int i;

     VeVector vx;
     VeVector v[] =
          {
               { { 0.0f, 0.0f, -4.0f, 1.0f } },
               { { 0.0f, 0.0f, -3.0f, 1.0f } },
               { { 0.0f, 0.0f, -2.0f, 1.0f } },
               { { 0.0f, 0.0f, -1.0f, 1.0f } },
               { { 0.0f, 0.0f,  0.0f, 1.0f } },
               { { 0.0f, 0.0f,  1.0f, 1.0f } },
               { { 0.0f, 0.0f,  2.0f, 1.0f } },
          };

     veViewport( 0, 0, 640, 480 );

     vePerspective( 80, 640.0 / 480.0, 1.0, 3.0 );

     for (i=0; i<sizeof(v)/sizeof(v[0]); i++) {
          veTransform( &vx, &v[i] );
     }

     return 0;
}
