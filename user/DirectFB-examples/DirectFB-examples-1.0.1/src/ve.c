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

/*
 * Mesa 3-D graphics library
 * Version:  3.1
 *
 * Copyright (C) 1999  Brian Paul   All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * BRIAN PAUL BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */





/*
 * Matrix operations
 *
 *
 * NOTES:
 * 1. 4x4 transformation matrices are stored in memory in column major order.
 * 2. Points/vertices are to be thought of as column vectors.
 * 3. Transformation of a point p by a matrix M is: p' = M * p
 *
 */


#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <direct/debug.h>
#include <direct/list.h>
#include <direct/mem.h>
#include <direct/memcpy.h>
#include <direct/messages.h>

#include "ve.h"

/* Pi */
#ifndef M_PI
#define M_PI (3.14159265358979323846)
#endif

/* Give symbolic names to some of the entries in the matrix to help
 * out with the rework of the viewport_map as a matrix transform.
 */
#define MAT_SX 0
#define MAT_SY 5
#define MAT_SZ 10
#define MAT_TX 12
#define MAT_TY 13
#define MAT_TZ 14

typedef struct {
     DirectLink   link;

     float        m[16];
} VeMatrix;

static const float Identity[16] = {
     1.0, 0.0, 0.0, 0.0,
     0.0, 1.0, 0.0, 0.0,
     0.0, 0.0, 1.0, 0.0,
     0.0, 0.0, 0.0, 1.0
};

/**************************************************************************************************/

static VeMatrix modelview = {
     { 0, NULL, NULL },
     {
          1.0, 0.0, 0.0, 0.0,
          0.0, 1.0, 0.0, 0.0,
          0.0, 0.0, 1.0, 0.0,
          0.0, 0.0, 0.0, 1.0
     }
};

static VeMatrix projection = {
     { 0, NULL, NULL },
     {
          1.0, 0.0, 0.0, 0.0,
          0.0, 1.0, 0.0, 0.0,
          0.0, 0.0, 1.0, 0.0,
          0.0, 0.0, 0.0, 1.0
     }
};

static VeMatrix windowmap = {
     { 0, NULL, NULL },
     {
          1.0, 0.0, 0.0, 0.0,
          0.0, 1.0, 0.0, 0.0,
          0.0, 0.0, 1.0, 0.0,
          0.0, 0.0, 0.0, 1.0
     }
};

static VeMatrix composite = {
     { 0, NULL, NULL },
     {
          1.0, 0.0, 0.0, 0.0,
          0.0, 1.0, 0.0, 0.0,
          0.0, 0.0, 1.0, 0.0,
          0.0, 0.0, 0.0, 1.0
     }
};

static unsigned int  age = 1;
static bool          update;
static DFBRectangle  viewport;
static DirectLink   *stack;

static float         near;
static float         far;

/**************************************************************************************************/

#define TRANSFORM_POINT( Q, M, P )					\
   Q[0] = M[0] * P[0] + M[4] * P[1] + M[8] *  P[2] + M[12] * P[3];	\
   Q[1] = M[1] * P[0] + M[5] * P[1] + M[9] *  P[2] + M[13] * P[3];	\
   Q[2] = M[2] * P[0] + M[6] * P[1] + M[10] * P[2] + M[14] * P[3];	\
   Q[3] = M[3] * P[0] + M[7] * P[1] + M[11] * P[2] + M[15] * P[3];

/*
 * This matmul was contributed by Thomas Malik
 *
 * Perform a 4x4 matrix multiplication  (product = a x b).
 * Input:  a, b - matrices to multiply
 * Output:  product - product of a and b
 * WARNING: (product != b) assumed
 * NOTE:    (product == a) allowed
 *
 * KW: 4*16 = 64 muls
 */
#define A(row,col)  a[(col<<2)+row]
#define B(row,col)  b[(col<<2)+row]
#define P(row,col)  product[(col<<2)+row]

static inline void
matmul4( float *product, const float *a, const float *b )
{
     int i;
     for (i = 0; i < 4; i++) {
          float ai0=A(i,0),  ai1=A(i,1),  ai2=A(i,2),  ai3=A(i,3);
          P(i,0) = ai0 * B(0,0) + ai1 * B(1,0) + ai2 * B(2,0) + ai3 * B(3,0);
          P(i,1) = ai0 * B(0,1) + ai1 * B(1,1) + ai2 * B(2,1) + ai3 * B(3,1);
          P(i,2) = ai0 * B(0,2) + ai1 * B(1,2) + ai2 * B(2,2) + ai3 * B(3,2);
          P(i,3) = ai0 * B(0,3) + ai1 * B(1,3) + ai2 * B(2,3) + ai3 * B(3,3);
     }
}

#undef A
#undef B
#undef P

/**************************************************************************************************/

static inline void
update_composite()
{
     if (update) {
          matmul4( composite.m, projection.m, modelview.m );

          update = false;

          if (!++age)
               age++;

          D_DEBUG( "VE/Transform: Updated composite matrix!\n"
                   "                              %8.3f  %8.3f  %8.3f  %8.3f\n"
                   "                              %8.3f  %8.3f  %8.3f  %8.3f\n"
                   "                              %8.3f  %8.3f  %8.3f  %8.3f\n"
                   "                              %8.3f  %8.3f  %8.3f  %8.3f\n",
                   composite.m[0], composite.m[4], composite.m[ 8], composite.m[12],
                   composite.m[1], composite.m[5], composite.m[ 9], composite.m[13],
                   composite.m[2], composite.m[6], composite.m[10], composite.m[14],
                   composite.m[3], composite.m[7], composite.m[11], composite.m[15] );
     }
}

/**************************************************************************************************/

/*
 * Generate a 4x4 transformation matrix from veRotate parameters.
 */
static void
rotation_matrix( float angle, float x, float y, float z, float m[] )
{
     /* This function contributed by Erich Boleyn (erich@uruk.org) */
     float mag, s, c;
     float xx, yy, zz, xy, yz, zx, xs, ys, zs, one_c;

     s = sin( angle );
     c = cos( angle );

     mag = sqrt( x*x + y*y + z*z );

     if (mag == 0.0) {
          /* generate an identity matrix and return */
          direct_memcpy(m, Identity, sizeof(float)*16);
          return;
     }

     x /= mag;
     y /= mag;
     z /= mag;

#define M(row,col)  m[col*4+row]

     /*
      *     Arbitrary axis rotation matrix.
      *
      *  This is composed of 5 matrices, Rz, Ry, T, Ry', Rz', multiplied
      *  like so:  Rz * Ry * T * Ry' * Rz'.  T is the final rotation
      *  (which is about the X-axis), and the two composite transforms
      *  Ry' * Rz' and Rz * Ry are (respectively) the rotations necessary
      *  from the arbitrary axis to the X-axis then back.  They are
      *  all elementary rotations.
      *
      *  Rz' is a rotation about the Z-axis, to bring the axis vector
      *  into the x-z plane.  Then Ry' is applied, rotating about the
      *  Y-axis to bring the axis vector parallel with the X-axis.  The
      *  rotation about the X-axis is then performed.  Ry and Rz are
      *  simply the respective inverse transforms to bring the arbitrary
      *  axis back to it's original orientation.  The first transforms
      *  Rz' and Ry' are considered inverses, since the data from the
      *  arbitrary axis gives you info on how to get to it, not how
      *  to get away from it, and an inverse must be applied.
      *
      *  The basic calculation used is to recognize that the arbitrary
      *  axis vector (x, y, z), since it is of unit length, actually
      *  represents the sines and cosines of the angles to rotate the
      *  X-axis to the same orientation, with theta being the angle about
      *  Z and phi the angle about Y (in the order described above)
      *  as follows:
      *
      *  cos ( theta ) = x / sqrt ( 1 - z^2 )
      *  sin ( theta ) = y / sqrt ( 1 - z^2 )
      *
      *  cos ( phi ) = sqrt ( 1 - z^2 )
      *  sin ( phi ) = z
      *
      *  Note that cos ( phi ) can further be inserted to the above
      *  formulas:
      *
      *  cos ( theta ) = x / cos ( phi )
      *  sin ( theta ) = y / sin ( phi )
      *
      *  ...etc.  Because of those relations and the standard trigonometric
      *  relations, it is pssible to reduce the transforms down to what
      *  is used below.  It may be that any primary axis chosen will give the
      *  same results (modulo a sign convention) using thie method.
      *
      *  Particularly nice is to notice that all divisions that might
      *  have caused trouble when parallel to certain planes or
      *  axis go away with care paid to reducing the expressions.
      *  After checking, it does perform correctly under all cases, since
      *  in all the cases of division where the denominator would have
      *  been zero, the numerator would have been zero as well, giving
      *  the expected result.
      */

     xx = x * x;
     yy = y * y;
     zz = z * z;
     xy = x * y;
     yz = y * z;
     zx = z * x;
     xs = x * s;
     ys = y * s;
     zs = z * s;
     one_c = 1.0F - c;

     M(0,0) = (one_c * xx) + c;
     M(0,1) = (one_c * xy) - zs;
     M(0,2) = (one_c * zx) + ys;
     M(0,3) = 0.0F;

     M(1,0) = (one_c * xy) + zs;
     M(1,1) = (one_c * yy) + c;
     M(1,2) = (one_c * yz) - xs;
     M(1,3) = 0.0F;

     M(2,0) = (one_c * zx) - ys;
     M(2,1) = (one_c * yz) + xs;
     M(2,2) = (one_c * zz) + c;
     M(2,3) = 0.0F;

     M(3,0) = 0.0F;
     M(3,1) = 0.0F;
     M(3,2) = 0.0F;
     M(3,3) = 1.0F;

#undef M
}

/**************************************************************************************************/

void
veFrustum( double left,    double right,
           double bottom,  double top,
           double nearval, double farval )
{
     float x, y, a, b, c, d;

     D_DEBUG( "VE/Frustum: left %.1f, right %.1f, bottom %.1f, top %.1f, near %.1f, far %.1f\n",
              left, right, bottom, top, nearval, farval );

     if ((nearval<=0.0 || farval<=0.0) || (nearval == farval) || (left == right) || (top == bottom)) {
          D_ERROR( "VE/Frustum: Invalid values!\n" );
          return;
     }

     x = (2.0*nearval) / (right-left);
     y = (2.0*nearval) / (top-bottom);
     a = (right+left) / (right-left);
     b = (top+bottom) / (top-bottom);
     c = -(farval+nearval) / ( farval-nearval);
     d = -(2.0*farval*nearval) / (farval-nearval);  /* error? */

#define M(row,col)  projection.m[col*4+row]
     M(0,0) = x;     M(0,1) = 0.0F;  M(0,2) = a;      M(0,3) = 0.0F;
     M(1,0) = 0.0F;  M(1,1) = y;     M(1,2) = b;      M(1,3) = 0.0F;
     M(2,0) = 0.0F;  M(2,1) = 0.0F;  M(2,2) = c;      M(2,3) = d;
     M(3,0) = 0.0F;  M(3,1) = 0.0F;  M(3,2) = -1.0F;  M(3,3) = 0.0F;
#undef M

     near = nearval;
     far  = farval;

/*     if (ctx->Driver.NearFar) {
          (*ctx->Driver.NearFar)( ctx, nearval, farval );
     }*/

     update = true;
}

void
veOrtho( double left,    double right,
         double bottom,  double top,
         double nearval, double farval )
{
     float x, y, z;
     float tx, ty, tz;

     D_DEBUG( "VE/Ortho: left %.1f, right %.1f, bottom %.1f, top %.1f, near %.1f, far %.1f\n",
              left, right, bottom, top, nearval, farval );

     if ((left == right) || (bottom == top) || (nearval == farval)) {
          D_ERROR( "VE/Ortho: Invalid values!\n" );
          return;
     }

     x = 2.0 / (right-left);
     y = 2.0 / (top-bottom);
     z = -2.0 / (farval-nearval);
     tx = -(right+left) / (right-left);
     ty = -(top+bottom) / (top-bottom);
     tz = -(farval+nearval) / (farval-nearval);

#define M(row,col)  projection.m[col*4+row]
     M(0,0) = x;     M(0,1) = 0.0F;  M(0,2) = 0.0F;  M(0,3) = tx;
     M(1,0) = 0.0F;  M(1,1) = y;     M(1,2) = 0.0F;  M(1,3) = ty;
     M(2,0) = 0.0F;  M(2,1) = 0.0F;  M(2,2) = z;     M(2,3) = tz;
     M(3,0) = 0.0F;  M(3,1) = 0.0F;  M(3,2) = 0.0F;  M(3,3) = 1.0F;
#undef M

     near = nearval;
     far  = farval;

/*     if (ctx->Driver.NearFar) {
          (*ctx->Driver.NearFar)( ctx, nearval, farval );
     }*/

     update = true;
}

void
vePerspective( double fovy,  double aspect,
               double zNear, double zFar )
{
     double xmin, xmax, ymin, ymax;

     D_DEBUG( "VE/Perspective: "
              "fovy %.1f, aspect %.1f, near %.1f, far %.1f\n", fovy, aspect, zNear, zFar );

     ymax = zNear * tan( fovy * M_PI / 360.0 );
     ymin = -ymax;

     xmin = ymin * aspect;
     xmax = ymax * aspect;

     veFrustum( xmin, xmax, ymin, ymax, zNear, zFar );
}

void
vePushMatrix()
{
     VeMatrix *matrix;

     D_DEBUG( "VE/Matrix: vePushMatrix()\n" );

     matrix = D_CALLOC( 1, sizeof(VeMatrix) );
     if (!matrix) {
          D_WARN( "out of memory" );
          return;
     }

     direct_memcpy( matrix, &modelview, sizeof(VeMatrix) );

     direct_list_prepend( &stack, &matrix->link );
}

void
vePopMatrix()
{
     DirectLink *first;

     D_ASSUME( stack != NULL );

     D_DEBUG( "VE/Matrix: vePopMatrix()\n" );

     first = stack;
     if (!first)
          return;

     direct_memcpy( &modelview, first, sizeof(VeMatrix) );

     direct_list_remove( &stack, first );

     D_FREE( first );

     update = true;
}

void
veLoadIdentity()
{
     D_DEBUG( "VE/Matrix: veLoadIdentity()\n" );

     direct_memcpy( modelview.m, Identity, 16*sizeof(float) );

     update = true;
}

void
veRotate( float radian, float x, float y, float z )
{
     float m[16];

     D_DEBUG( "VE/Rotate: %.1f - %.1f, %.1f, %.1f\n", radian, x, y, z );

     if (radian == 0.0F)
          return;

     rotation_matrix( radian, x, y, z, m );

     matmul4( modelview.m, modelview.m, m );

     update = true;
}

void
veScale( float x, float y, float z )
{
     D_DEBUG( "VE/Scale: %.1f, %.1f, %.1f\n", x, y, z );

     modelview.m[0] *= x;   modelview.m[4] *= y;   modelview.m[8]  *= z;
     modelview.m[1] *= x;   modelview.m[5] *= y;   modelview.m[9]  *= z;
     modelview.m[2] *= x;   modelview.m[6] *= y;   modelview.m[10] *= z;
     modelview.m[3] *= x;   modelview.m[7] *= y;   modelview.m[11] *= z;

     update = true;
}

void
veTranslate( float x, float y, float z )
{
     D_DEBUG( "VE/Translate: %.1f, %.1f, %.1f\n", x, y, z );

     modelview.m[12] = modelview.m[0] * x + modelview.m[4] * y + modelview.m[8]  * z + modelview.m[12];
     modelview.m[13] = modelview.m[1] * x + modelview.m[5] * y + modelview.m[9]  * z + modelview.m[13];
     modelview.m[14] = modelview.m[2] * x + modelview.m[6] * y + modelview.m[10] * z + modelview.m[14];
     modelview.m[15] = modelview.m[3] * x + modelview.m[7] * y + modelview.m[11] * z + modelview.m[15];

     update = true;
}

void
veViewport( int x, int y, int width, int height )
{
     D_DEBUG( "VE/Viewport: %d, %d - %dx%d\n", x, y, width, height );

     if (width<1 || height<1) {
          D_ERROR( "VE/Viewport: Invalid values!\n" );
          return;
     }

     /* Save viewport */
     viewport.x = x;
     viewport.w = width;
     viewport.y = y;
     viewport.h = height;

     /* compute scale and bias values */
     windowmap.m[MAT_SX] = (float) width / 2.0F;
     windowmap.m[MAT_TX] = windowmap.m[MAT_SX] + x;
     windowmap.m[MAT_SY] = (float) height / 2.0F;
     windowmap.m[MAT_TY] = windowmap.m[MAT_SY] + y;
     windowmap.m[MAT_SZ] = 0.5;
     windowmap.m[MAT_TZ] = 0.5;
}

void
veTransform( VeVector *dest, const VeVector *source )
{
     VeVector tmp;
     float    oow = 0.0f;

     update_composite();

     TRANSFORM_POINT( tmp.v, composite.m, source->v );

     if (tmp.v[3] > 0.0001f)
          oow = 1.0f / tmp.v[3];

     dest->v[0] = oow * tmp.v[0] * windowmap.m[MAT_SX] + windowmap.m[MAT_TX];
     dest->v[1] = oow * tmp.v[1] * windowmap.m[MAT_SY] + windowmap.m[MAT_TY];
     dest->v[2] = oow * tmp.v[2] * windowmap.m[MAT_SZ] + windowmap.m[MAT_TZ];
     dest->v[3] = oow;

     D_DEBUG( "VE/Transform: %5.1f, %5.1f, %5.1f, %5.1f  ->  "
              "%5.1f, %5.1f, %5.1f, %5.1f  ->  %5.1f, %5.1f, %5.1f, %5.1f\n",
              source->v[X], source->v[Y], source->v[Z], source->v[W],
              tmp.v[X], tmp.v[Y], tmp.v[Z], tmp.v[W],
              dest->v[X], dest->v[Y], dest->v[Z], dest->v[W] );
}

/**************************************************************************************************/

static const char *type_names[2] = {
     "TRIANGLE_FAN", "QUAD_STRIP"
};

VeVertexBuffer *
vbNew( VePrimitiveType type,
       int             size )
{
     VeVertexBuffer *buffer;

     (void) type_names;

     D_ASSERT( type == VE_TRIANGLE_FAN || type == VE_QUAD_STRIP );
     D_ASSERT( size > 0 );

     buffer = D_CALLOC( 1, sizeof(VeVertexBuffer) );
     if (!buffer) {
          D_WARN( "out of memory" );
          return NULL;
     }

     D_DEBUG( "VB/New:     %s, %d\n", type_names[type], size );

     buffer->type = type;
     buffer->size = size;

     buffer->max_vertices = size << 2;
     buffer->max_indices  = (size - 2) * 9;

     if (! (buffer->data     = D_MALLOC( size                 * sizeof(VeVertex)  )) ||
         ! (buffer->vertices = D_MALLOC( buffer->max_vertices * sizeof(DFBVertex) )) ||
         ! (buffer->indices  = D_MALLOC( buffer->max_indices  * sizeof(int)       ))   )
     {
          D_WARN( "out of memory" );

          if (buffer->data)
               D_FREE( buffer->data );

          if (buffer->vertices)
               D_FREE( buffer->vertices );

          D_FREE( buffer );

          return NULL;
     }

     D_MAGIC_SET( buffer, VeVertexBuffer );

     return buffer;
}

void
vbAdd( VeVertexBuffer *buffer,
       float           x,
       float           y,
       float           z,
       float           s,
       float           t )
{
     VeVertex *vtx;

     D_MAGIC_ASSERT( buffer, VeVertexBuffer );

     D_DEBUG( "VB/Adding:  %7.3f, %7.3f, %7.3f  [%.3f, %.3f]\n", x, y, z, s, t );

     if (buffer->count == buffer->size) {
          D_WARN( "vertex buffer full" );
          return;
     }

     vtx = &buffer->data[buffer->count++];

     vtx->obj.v[X] = x;
     vtx->obj.v[Y] = y;
     vtx->obj.v[Z] = z;
     vtx->obj.v[W] = 1.0f;

     vtx->s = s;
     vtx->t = t;

     vtx->index = -1;

     buffer->age = 0;
}

void
vbClear( VeVertexBuffer *buffer )
{
     D_MAGIC_ASSERT( buffer, VeVertexBuffer );

     D_DEBUG( "VB/Clear:   Discarding %d elements\n", buffer->count );

     buffer->count = 0;
     buffer->age   = 0;
}

/**************************************************************************************************/

static inline int
add_vertex( VeVertexBuffer *buffer, const VeVertex *vtx )
{
     int        index;
     float      oow;
     DFBVertex *dst;

     /* Use the next free index. */
     index = buffer->num_vertices++;

     /* Get the pointer to the element. */
     dst = &buffer->vertices[index];

     /* Calculate one over W. */
     oow = 1.0f / vtx->clip.v[W];

     /* Transform to window coordinates. */
     dst->x = oow * vtx->clip.v[X] * windowmap.m[MAT_SX] + windowmap.m[MAT_TX];
     dst->y = oow * vtx->clip.v[Y] * windowmap.m[MAT_SY] + windowmap.m[MAT_TY];
     dst->z = oow * vtx->clip.v[Z] * windowmap.m[MAT_SZ] + windowmap.m[MAT_TZ];
     dst->w = oow;

     /* Copy texture coordinates. */
     dst->s = vtx->s;
     dst->t = vtx->t;

     /* Return index within the output buffer. */
     return index;
}

/**************************************************************************************************/

static const char *clip_names[6] = {
     "RIGHT",
     "LEFT",
     "TOP",
     "BOTTOM",
     "FAR",
     "NEAR"
};

#define INOUT(flag)  ((flag) ? "inside" : "outside")

#define INSIDE(c)    ((p & 1) ? ((c).v[pc] >= -(c).v[W]) : ((c).v[pc] <= (c).v[W]))

/**************************************************************************************************/

static int
clip_polygon( VeVertexBuffer *buffer, const int input[], int count, VeClipMask clipOr, int output[] )
{
     int       i, p;
     VeVertex  tmp1[count << 2];
     VeVertex  tmp2[count << 2];

     VeVertex *from = tmp1;
     VeVertex *to   = tmp2;

     float t;
     float d[4];

     for (i=0; i<count; i++)
          from[i] = buffer->data[ input[i] ];

     (void) clip_names;

     for (p=0; p<6; p++) {
          int pc = p >> 1;

          if (clipOr & (1 << p)) {
               int       out   = 0;
               VeVertex *prev  = &from[count - 1];
               int       pflag = INSIDE( prev->clip );

               D_DEBUG( "VB/Clip:     => Clipping against '%s' plane, starting %s ...\n",
                        clip_names[p], INOUT(pflag) );

               for (i=0; i<count; i++) {
                    VeVertex *vtx = &from[i];

                    (void) vtx;

                    D_DEBUG( "VB/Clip:        (%d)  %7.3f, %7.3f, %7.3f, %7.3f  [%.3f, %.3f]\n",
                             i, vtx->clip.v[0], vtx->clip.v[1], vtx->clip.v[2], vtx->clip.v[3],
                             vtx->s, vtx->t );
               }

               for (i=0; i<count; i++) {
                    VeVertex *curr = &from[i];
                    int       flag = INSIDE( curr->clip );

                    if (flag ^ pflag) {
                         VeVertex *N = &to[out++];
                         VeVertex *I, *O;

                         if (flag) {
                              D_DEBUG( "VB/Clip:        ... coming back in ...\n" );
                              I = curr;
                              O = prev;
                         }
                         else {
                              D_DEBUG( "VB/Clip:        ... going out ...\n" );
                              I = prev;
                              O = curr;
                         }

                         d[0] = O->clip.v[0] - I->clip.v[0];
                         d[1] = O->clip.v[1] - I->clip.v[1];
                         d[2] = O->clip.v[2] - I->clip.v[2];
                         d[3] = O->clip.v[3] - I->clip.v[3];

                         if (p & 1)
                              t  = (- I->clip.v[pc] - I->clip.v[3]) / (d[3] + d[pc]);
                         else
                              t  = (  I->clip.v[pc] - I->clip.v[3]) / (d[3] - d[pc]);

                         N->clip.v[0] = I->clip.v[0] + t * d[0];
                         N->clip.v[1] = I->clip.v[1] + t * d[1];
                         N->clip.v[2] = I->clip.v[2] + t * d[2];
                         N->clip.v[3] = I->clip.v[3] + t * d[3];

                         N->s = I->s + t * (O->s - I->s);
                         N->t = I->t + t * (O->t - I->t);

                         N->index = -1;
                    }
                    else
                         D_DEBUG( "VB/Clip:        ... staying %s ...\n", INOUT(flag) );

                    if (flag)
                         to[out++] = from[i];

                    prev  = curr;
                    pflag = flag;
               }

               D_DEBUG( "VB/Clip:     => New vertex count is %d ...\n", out );

               for (i=0; i<out; i++) {
                    VeVertex *vtx = &to[i];

                    (void) vtx;

                    D_DEBUG( "VB/Clip:        (%d)  %7.3f, %7.3f, %7.3f, %7.3f  [%.3f, %.3f]\n",
                             i, vtx->clip.v[0], vtx->clip.v[1], vtx->clip.v[2], vtx->clip.v[3],
                             vtx->s, vtx->t );
               }

               if (out >= 3) {
                    VeVertex *tmp;

                    tmp   = from;
                    from  = to;
                    to    = tmp;

                    count = out;
               }
               else
                    return 0;
          }
     }

     for (i=0; i<count; i++)
          output[i] = from[i].index != -1 ? from[i].index : add_vertex( buffer, &from[i] );

     return count;
}

static void
build_polygon( VeVertexBuffer *buffer, const int input[], int count )
{
     int        i;
     VeClipMask clipOr  = VE_CLIP_NONE;
     VeClipMask clipAnd = VE_CLIP_ALL;

     D_ASSERT( count >= 3 );

     if (count == 4)
          D_DEBUG( "VB/Build:   %d, %d, %d, %d\n", input[0], input[1], input[2], input[3] );
     else
          D_DEBUG( "VB/Build:   %d, %d, %d\n", input[0], input[1], input[2] );

     /* Combine clipping masks. */
     for (i=0; i<count; i++) {
          VeClipMask mask = buffer->data[ input[i] ].clipMask;

          clipOr  |= mask;
          clipAnd &= mask;
     }

     if (clipAnd) {
          /* At least one plane clips them all, the polygon is outside the view volume. */
          D_DEBUG( "VB/Build:   Completely clipped -> [0x%02x] (0x%02x)\n", clipOr, clipAnd );
     }
     else if (clipOr) {
          /* At least one vertex is clipped by at least one plane. */
          int num;
          int output[count << 2];

          D_DEBUG( "VB/Build:   Partially clipped  -> [0x%02x] (0x%02x)\n", clipOr, clipAnd );

          num = clip_polygon( buffer, input, count, clipOr, output );

          D_DEBUG( "VB/Build:   Clipping produced %d/%d indices\n", num, count );

          for (i=2; i<num; i++) {
               buffer->indices[ buffer->num_indices++ ] = output[0];
               buffer->indices[ buffer->num_indices++ ] = output[i-1];
               buffer->indices[ buffer->num_indices++ ] = output[i];
          }
     }
     else {
          /* No vertex is clipped. */
          for (i=2; i<count; i++) {
               buffer->indices[ buffer->num_indices++ ] = buffer->data[ input[0] ].index;
               buffer->indices[ buffer->num_indices++ ] = buffer->data[ input[i-1] ].index;
               buffer->indices[ buffer->num_indices++ ] = buffer->data[ input[i] ].index;
          }
     }
}

void
vbExec( VeVertexBuffer   *buffer,
        IDirectFBSurface *surface,
        IDirectFBSurface *texture )
{
     int i;
     int count;

     D_MAGIC_ASSERT( buffer, VeVertexBuffer );

     D_DEBUG( "VB/Execute: %s, %d\n", type_names[buffer->type], buffer->count );

     D_ASSERT( surface != NULL );
     D_ASSERT( texture != NULL );

     if (! (count = buffer->count))
          return;

     D_ASSERT( (buffer->type != VE_TRIANGLE_FAN) || (count >= 3) );
     D_ASSERT( (buffer->type != VE_QUAD_STRIP)   || ((count >= 4) && (count % 2 == 0)) );


     /* Make sure the product of modelview and projection matrix is up to date. */
     update_composite();

     /* Check buffer and matrix age. */
     if (buffer->age != age) {
          buffer->age = age;

          /* Reset the output buffer. */
          buffer->num_vertices = buffer->num_indices = 0;

          /* Prepare input buffer. */
          for (i=0; i<count; i++) {
               VeVertex    *vtx  = &buffer->data[i];
               const float *clip = vtx->clip.v;
               VeClipMask   mask = 0;

               /* Reset the index to the output buffer. */
               vtx->index = -1;

               /* Transform object to clip coordinates using combined modelview & projection matrix. */
               TRANSFORM_POINT( vtx->clip.v, composite.m, vtx->obj.v );

               /* Check each plane of the clipping volume. */
               if (-clip[X] + clip[W] < 0) mask |= VE_CLIP_RIGHT;
               if ( clip[X] + clip[W] < 0) mask |= VE_CLIP_LEFT;
               if (-clip[Y] + clip[W] < 0) mask |= VE_CLIP_TOP;
               if ( clip[Y] + clip[W] < 0) mask |= VE_CLIP_BOTTOM;
               if (-clip[Z] + clip[W] < 0) mask |= VE_CLIP_FAR;
               if ( clip[Z] + clip[W] < 0) mask |= VE_CLIP_NEAR;

               /* Keep result of clipping test. */
               vtx->clipMask = mask;

               /* Transform to perspective window coordinates and
                  store in output buffer if no clipping is required. */
               if (!mask)
                    vtx->index = add_vertex( buffer, vtx );
          }

          /* Build list of indices, simultaneously fill output buffer with original and/or
             extra vertices as needed, transformed to perspective window coordinates. */
          switch (buffer->type) {
               case VE_TRIANGLE_FAN:
                    for (i=2; i<count; i++) {
                         int list[3] = { 0, i-1, i };

                         build_polygon( buffer, list, 3 );
                    }
                    break;

               case VE_QUAD_STRIP:
                    for (i=2; i<count; i+=2) {
                         int list[4] = { i-2, i-1, i+1, i };

                         build_polygon( buffer, list, 4 );
                    }
                    break;

               default:
                    D_BUG( "unknown primitive type" );
                    return;
          }
     }

     D_DEBUG( "VB/Execute: %d/%d vertices, %d/%d indices\n",
              buffer->num_vertices, buffer->count, buffer->num_indices, (buffer->count - 2) * 3 );

     /* Render built triangle list. */
     if (buffer->num_indices > 0)
          surface->TextureTriangles( surface, texture, buffer->vertices,
                                     buffer->indices, buffer->num_indices, DTTF_LIST );
}

void
vbDestroy( VeVertexBuffer *buffer )
{
     D_MAGIC_ASSERT( buffer, VeVertexBuffer );

     D_DEBUG( "VB/Destroy: %s, %d\n", type_names[buffer->type], buffer->count );

     D_MAGIC_CLEAR( buffer );

     D_FREE( buffer->indices );
     D_FREE( buffer->vertices );
     D_FREE( buffer->data );
     D_FREE( buffer );
}

