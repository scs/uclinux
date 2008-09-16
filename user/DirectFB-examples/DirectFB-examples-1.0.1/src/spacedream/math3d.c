/*
   (c) Copyright 2000-2002  convergence integrated media GmbH.
   (c) Copyright 2002       convergence GmbH.
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

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "math3d.h"

static const Matrix identity = { { 1, 0, 0, 0,
                                   0, 1, 0, 0,
                                   0, 0, 1, 0,
                                   0, 0, 0, 1 } };

float vector_length( Vector *vector )
{
     return sqrt( vector->v[X] * vector->v[X] +
                  vector->v[Y] * vector->v[Y] +
                  vector->v[Z] * vector->v[Z] );
}

void vector_scale( Vector *vector, float factor )
{
     vector->v[X] *= factor;
     vector->v[Y] *= factor;
     vector->v[Z] *= factor;
}

void matrix_transform( Matrix *matrix, Vector *source, Vector *destination )
{
/*     printf( "source: %f, %f, %f, %f\n",
             source->v[X], source->v[Y], source->v[Z], source->v[W] );*/

     destination->v[X] = matrix->v[X1] * source->v[X] +
                         matrix->v[Y1] * source->v[Y] +
                         matrix->v[Z1] * source->v[Z] +
                         matrix->v[W1] * source->v[W];

     destination->v[Y] = matrix->v[X2] * source->v[X] +
                         matrix->v[Y2] * source->v[Y] +
                         matrix->v[Z2] * source->v[Z] +
                         matrix->v[W2] * source->v[W];

     destination->v[Z] = matrix->v[X3] * source->v[X] +
                         matrix->v[Y3] * source->v[Y] +
                         matrix->v[Z3] * source->v[Z] +
                         matrix->v[W3] * source->v[W];

     destination->v[W] = matrix->v[X4] * source->v[X] +
                         matrix->v[Y4] * source->v[Y] +
                         matrix->v[Z4] * source->v[Z] +
                         matrix->v[W4] * source->v[W];

/*     printf( "destination: %f, %f, %f, %f\n",
             destination->v[X], destination->v[Y], destination->v[Z], destination->v[W] );*/
}

Matrix *matrix_new_identity()
{
     Matrix *m = malloc( sizeof(Matrix) );

     *m = identity;

     return m;
}

Matrix *matrix_new_perspective( float d )
{
     Matrix *m = matrix_new_identity();

     m->v[Z4] = 1.0f / d;

     return m;
}

void matrix_multiply( Matrix *destination, Matrix *source )
{
     float tmp[4];

     tmp[0] = source->v[X1] * destination->v[X1] +
              source->v[Y1] * destination->v[X2] +
              source->v[Z1] * destination->v[X3] +
              source->v[W1] * destination->v[X4];
     tmp[1] = source->v[X2] * destination->v[X1] +
              source->v[Y2] * destination->v[X2] +
              source->v[Z2] * destination->v[X3] +
              source->v[W2] * destination->v[X4];
     tmp[2] = source->v[X3] * destination->v[X1] +
              source->v[Y3] * destination->v[X2] +
              source->v[Z3] * destination->v[X3] +
              source->v[W3] * destination->v[X4];
     tmp[3] = source->v[X4] * destination->v[X1] +
              source->v[Y4] * destination->v[X2] +
              source->v[Z4] * destination->v[X3] +
              source->v[W4] * destination->v[X4];

     destination->v[X1] = tmp[0];
     destination->v[X2] = tmp[1];
     destination->v[X3] = tmp[2];
     destination->v[X4] = tmp[3];


     tmp[0] = source->v[X1] * destination->v[Y1] +
              source->v[Y1] * destination->v[Y2] +
              source->v[Z1] * destination->v[Y3] +
              source->v[W1] * destination->v[Y4];
     tmp[1] = source->v[X2] * destination->v[Y1] +
              source->v[Y2] * destination->v[Y2] +
              source->v[Z2] * destination->v[Y3] +
              source->v[W2] * destination->v[Y4];
     tmp[2] = source->v[X3] * destination->v[Y1] +
              source->v[Y3] * destination->v[Y2] +
              source->v[Z3] * destination->v[Y3] +
              source->v[W3] * destination->v[Y4];
     tmp[3] = source->v[X4] * destination->v[Y1] +
              source->v[Y4] * destination->v[Y2] +
              source->v[Z4] * destination->v[Y3] +
              source->v[W4] * destination->v[Y4];

     destination->v[Y1] = tmp[0];
     destination->v[Y2] = tmp[1];
     destination->v[Y3] = tmp[2];
     destination->v[Y4] = tmp[3];


     tmp[0] = source->v[X1] * destination->v[Z1] +
              source->v[Y1] * destination->v[Z2] +
              source->v[Z1] * destination->v[Z3] +
              source->v[W1] * destination->v[Z4];
     tmp[1] = source->v[X2] * destination->v[Z1] +
              source->v[Y2] * destination->v[Z2] +
              source->v[Z2] * destination->v[Z3] +
              source->v[W2] * destination->v[Z4];
     tmp[2] = source->v[X3] * destination->v[Z1] +
              source->v[Y3] * destination->v[Z2] +
              source->v[Z3] * destination->v[Z3] +
              source->v[W3] * destination->v[Z4];
     tmp[3] = source->v[X4] * destination->v[Z1] +
              source->v[Y4] * destination->v[Z2] +
              source->v[Z4] * destination->v[Z3] +
              source->v[W4] * destination->v[Z4];

     destination->v[Z1] = tmp[0];
     destination->v[Z2] = tmp[1];
     destination->v[Z3] = tmp[2];
     destination->v[Z4] = tmp[3];


     tmp[0] = source->v[X1] * destination->v[W1] +
              source->v[Y1] * destination->v[W2] +
              source->v[Z1] * destination->v[W3] +
              source->v[W1] * destination->v[W4];
     tmp[1] = source->v[X2] * destination->v[W1] +
              source->v[Y2] * destination->v[W2] +
              source->v[Z2] * destination->v[W3] +
              source->v[W2] * destination->v[W4];
     tmp[2] = source->v[X3] * destination->v[W1] +
              source->v[Y3] * destination->v[W2] +
              source->v[Z3] * destination->v[W3] +
              source->v[W3] * destination->v[W4];
     tmp[3] = source->v[X4] * destination->v[W1] +
              source->v[Y4] * destination->v[W2] +
              source->v[Z4] * destination->v[W3] +
              source->v[W4] * destination->v[W4];

     destination->v[W1] = tmp[0];
     destination->v[W2] = tmp[1];
     destination->v[W3] = tmp[2];
     destination->v[W4] = tmp[3];
}

void matrix_translate( Matrix *matrix, float x, float y, float z )
{
     Matrix tmp = identity;

     tmp.v[W1] = x;
     tmp.v[W2] = y;
     tmp.v[W3] = z;

     matrix_multiply( matrix, &tmp );
}

void matrix_scale( Matrix *matrix, float x, float y, float z )
{
     Matrix tmp = identity;

     tmp.v[X1] = x;
     tmp.v[Y2] = y;
     tmp.v[Z3] = z;

     matrix_multiply( matrix, &tmp );
}

void matrix_rotate( Matrix *matrix, Vector_Elements axis, float angle )
{
     float  _cos = (float) cos( angle );
     float  _sin = (float) sin( angle );
     Matrix  tmp = identity;

     switch (axis) {
          case X:
               tmp.v[Y2] =   _cos;
               tmp.v[Z2] = - _sin;
               tmp.v[Y3] =   _sin;
               tmp.v[Z3] =   _cos;
               break;
          case Y:
               tmp.v[X1] =   _cos;
               tmp.v[Z1] =   _sin;
               tmp.v[X3] = - _sin;
               tmp.v[Z3] =   _cos;
               break;
          case Z:
               tmp.v[X1] =   _cos;
               tmp.v[Y1] = - _sin;
               tmp.v[X2] =   _sin;
               tmp.v[Y2] =   _cos;
               break;
          default:
               break;
     }

     matrix_multiply( matrix, &tmp );
}


