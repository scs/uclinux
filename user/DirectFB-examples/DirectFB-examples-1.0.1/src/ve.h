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

#ifndef __VE_H__
#define __VE_H__

#include <directfb.h>


typedef struct {
     float v[4];
} VeVector;

typedef enum {
     X = 0,
     Y = 1,
     Z = 2,
     W = 3
} VeVectorElement;

typedef enum {
     VE_CLIP_NONE    = 0x00,

     VE_CLIP_RIGHT   = 0x01,
     VE_CLIP_LEFT    = 0x02,
     VE_CLIP_TOP     = 0x04,
     VE_CLIP_BOTTOM  = 0x08,
     VE_CLIP_FAR     = 0x10,
     VE_CLIP_NEAR    = 0x20,

     VE_CLIP_ALL     = 0x3f
} VeClipMask;

typedef enum {
     VE_TRIANGLE_FAN = 0x00,
     VE_QUAD_STRIP   = 0x01
} VePrimitiveType;

typedef struct {
     /*
      * Object coordinates
      */
     VeVector   obj;

     /*
      * Texture coordinates
      */
     float      s;
     float      t;

     /*
      * Intermediate data of vbExec()
      *
      * Index of transformed version in output buffer, being -1 if vbExec() wasn't
      * called or if the vertex lies outside the view volume.
      */
     int        index;

     /*
      * Intermediate data of vbExec()
      *
      * Clip coordinates are object coordinates after transformation using modelview
      * and projection matrix. The clip mask has a flag for each of the six clipping
      * planes indicating that the vertex lies behind the plane (outside the view volume).
      */
     VeVector   clip;
     VeClipMask clipMask;
} VeVertex;

typedef struct {
     int              magic;

     /*
      * Properties chosen with vbNew()
      */
     VePrimitiveType  type;
     int              size;

     /*
      * Input data as provided by vbAdd()
      *
      * Also contains intermediate data calculated in vbExec().
      */
     VeVertex        *data;
     int              count;

     /*
      * Matrix age (serial) during last vbExec()
      *
      * Avoids doing transformations, clipping and setup again
      * when nothing relevant happened between vbExec() calls.
      *
      * The default is zero (invalid age) and gets reset by vbAdd() and vbClear().
      */
     unsigned int     age;

     /*
      * Calculated space with enough room for the worst clipping case
      *
      * max_vertices = (size << 2)
      * max_indices  = (size  - 2) * 9
      */
     int              max_vertices;
     int              max_indices;

     /*
      * Output data as accepted by TextureTriangles()
      *
      * These are the final window coordinates after clipping all primitives.
      */
     DFBVertex       *vertices;
     int              num_vertices;

     int             *indices;
     int              num_indices;
} VeVertexBuffer;


/** Projection Matrix **/

void veFrustum( double left,    double right,
                double bottom,  double top,
                double nearval, double farval );

void veOrtho( double left,    double right,
              double bottom,  double top,
              double nearval, double farval );

void vePerspective( double fovy,  double aspect,
                    double zNear, double zFar );


/** Modelview Matrix **/

void vePushMatrix( void );

void vePopMatrix( void );

void veLoadIdentity( void );

void veRotate( float angle, float x, float y, float z );

void veScale( float x, float y, float z );

void veTranslate( float x, float y, float z );


/* Viewport Matrix */
void veViewport( int x, int y, int width, int height );


/* Runs the vertex pipeline except clipping */
void veTransform( VeVector *dest, const VeVector *source );




VeVertexBuffer *vbNew    ( VePrimitiveType   type,
                           int               size );

void            vbAdd    ( VeVertexBuffer   *buffer,
                           float             x,
                           float             y,
                           float             z,
                           float             s,
                           float             t );

void            vbClear  ( VeVertexBuffer   *buffer );

void            vbExec   ( VeVertexBuffer   *buffer,
                           IDirectFBSurface *surface,
                           IDirectFBSurface *texture );

void            vbDestroy( VeVertexBuffer   *buffer );

#endif

