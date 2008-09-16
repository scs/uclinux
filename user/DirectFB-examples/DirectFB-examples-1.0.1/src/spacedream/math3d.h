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


#ifndef __DFB_MATH_H__
#define __DFB_MATH_H__

typedef struct {
     float v[4];
} Vector;

typedef struct {
     float v[16];
} Matrix;


typedef enum {
     X = 0,
     Y = 1,
     Z = 2,
     W = 3
} Vector_Elements;

typedef enum {
     X1 = 0,
     Y1 = 1,
     Z1 = 2,
     W1 = 3,
     X2 = 4,
     Y2 = 5,
     Z2 = 6,
     W2 = 7,
     X3 = 8,
     Y3 = 9,
     Z3 = 10,
     W3 = 11,
     X4 = 12,
     Y4 = 13,
     Z4 = 14,
     W4 = 15
} Matrix_Elements;


float vector_length( Vector *vector );
void  vector_scale( Vector *vector, float factor );


void matrix_transform( Matrix *matrix, Vector *source, Vector *destination );

Matrix *matrix_new_identity();
Matrix *matrix_new_perspective( float d );
void    matrix_multiply( Matrix *destination, Matrix *source );
void    matrix_translate( Matrix *matrix, float x, float y, float z );
void    matrix_scale( Matrix *matrix, float x, float y, float z );
void    matrix_rotate( Matrix *matrix, Vector_Elements axis, float angle );


#endif

