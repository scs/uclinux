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

#define SELFRUNNING

#include <directfb.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#define PI 3.1415926536f

static unsigned int rand_pool = 0x12345678;
static unsigned int rand_add  = 0x87654321;

static inline unsigned int myrand()
{
     rand_pool ^= ((rand_pool << 7) | (rand_pool >> 25));
     rand_pool += rand_add;
     rand_add  += rand_pool;

     return rand_pool;
}

static IDirectFB *dfb;
static IDirectFBSurface *primary;
static IDirectFBEventBuffer *buffer;

typedef struct _Particle
{
     float w;
     int sw, sh;
     int size;
     int launch;
     struct _Particle *next;
} Particle;

static Particle *particles = NULL;
static Particle *last_particle = NULL;

static float f = 0;

static int sx, sy;

static void
spawn_particle()
{
     Particle *new_particle = (Particle*)malloc( sizeof(Particle) );

     new_particle->w = 0.05f;
     new_particle->sw = myrand()%(int)(sx/3.2f) + (int)(sx/3.2f)*sin(f)
                                              + (int)(sx/3.2f);// + 40*sin(f*5);
     new_particle->sh = myrand()%100 + sy-130;// + 40*cos(f*5);
     new_particle->size = myrand()%(sx/160) +2;
     new_particle->launch = myrand()%(sx/70);
     new_particle->next = NULL;

     if (!particles) {
          particles = new_particle;
          last_particle = new_particle;
     }
     else {
          last_particle->next = new_particle;
          last_particle = new_particle;
     }
}

static void
draw_particles()
{
     Particle *p = particles;

     while (p) {
          primary->SetColor( primary, 0xA0+myrand()%0x50, 0xA0+myrand()%0x50, 0xFF, 0x25 );
          primary->FillRectangle( primary, p->launch + sin(p->w/2)*(p->sw),
                                  sy - sin(p->w)*p->sh, p->w*p->size+1,
                                  p->w*p->size+1 );

          p->w += PI/500 * sqrt(p->w) * sx/640.0f;

          if (p->w > PI) {
               particles = p->next;
               free(p);
               p = particles;
               if (!p)
                    last_particle = NULL;
          }
          else {
               p = p->next;
          }
     }
}

static void
destroy_particles()
{
     Particle *p = particles;

     while (p) {
          particles = p->next;
          free(p);
          p = particles;
     }
}

int
main( int argc, char *argv[] )
{
     int i;
     int quit = 0;
     int spawn = 0;
     int right = 0;
     int left = 0;
     DFBResult err;
     DFBGraphicsDeviceDescription gdesc;

     if (DirectFBInit( &argc, &argv ) != DFB_OK)
          return 1;

     if (DirectFBCreate( &dfb ) != DFB_OK)
          return 1;

     dfb->GetDeviceDescription( dfb, &gdesc );

     err = dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );
     if (err != DFB_OK)
          DirectFBError( "Failed requesting exclusive access", err );

     err = dfb->CreateInputEventBuffer( dfb, DICAPS_ALL, DFB_FALSE, &buffer );
     if (err != DFB_OK) {
          DirectFBError( "CreateInputEventBuffer failed", err );
          dfb->Release( dfb );
          return 1;
     }

     {
          DFBSurfaceDescription dsc;

          dsc.flags = DSDESC_CAPS;
          dsc.caps = (gdesc.drawing_flags & DSDRAW_BLEND) ?
                         DSCAPS_PRIMARY | DSCAPS_FLIPPING :
                         DSCAPS_PRIMARY | DSCAPS_FLIPPING | DSCAPS_SYSTEMONLY;

          err = dfb->CreateSurface( dfb, &dsc, &primary );
          if (err != DFB_OK) {
               DirectFBError( "Failed creating primary surface", err );
               buffer->Release( buffer );
               dfb->Release( dfb );
               return 1;
          }

          primary->GetSize( primary, &sx, &sy );
     }

     primary->Clear( primary, 0xFF, 0xFF, 0xFF, 0xFF );
     err = primary->Flip( primary, NULL, 0 );
     if (err != DFB_OK) {
          DirectFBError( "Failed flipping the primary surface", err );
          primary->Release( primary );
          buffer->Release( buffer );
          dfb->Release( dfb );
          return 1;
     }

     sleep(2);

     for (i=254; i>=0; i-=4) {
          primary->Clear( primary, i, i, i, 0xFF );

          err = primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
          if (err != DFB_OK) {
               DirectFBError( "Failed flipping the primary surface", err );
               primary->Release( primary );
               buffer->Release( buffer );
               dfb->Release( dfb );
               return 1;
          }
     }

     primary->SetDrawingFlags( primary, DSDRAW_BLEND );

     while (!quit) {
          DFBInputEvent evt;

          primary->SetColor( primary, 0, 0, 0, 0x17 );
          primary->FillRectangle( primary, 0, 0, sx, sy );

          if (!(myrand()%50))
               left = !left;

          if (left)
               f -= 0.02f;

          if (f < -PI/2)
               f = -PI/2;

          if (!(myrand()%50))
               right = !right;

          if (right)
               f += 0.02f;

          if (f > PI/2)
               f = PI/2;

          spawn = sx >> 7;
          while (spawn--)
               spawn_particle();

          draw_particles();

          err = primary->Flip( primary, NULL, DSFLIP_BLIT | DSFLIP_WAITFORSYNC );
          if (err != DFB_OK) {
               DirectFBError( "Failed flipping the primary surface", err );
               break;
          }

          while (buffer->GetEvent( buffer, DFB_EVENT(&evt) ) == DFB_OK) {
               if (evt.type == DIET_KEYPRESS  &&  evt.key_id == DIKI_ESCAPE)
                    quit = 1;
          }
     }

     destroy_particles();

     primary->SetColor( primary, 0, 0, 0, 10 );

     for (i=0; i<70; i++) {
          primary->FillRectangle( primary, 0, 0, sx, sy );

          err = primary->Flip( primary, NULL, DSFLIP_BLIT | DSFLIP_WAITFORSYNC );
          if (err != DFB_OK) {
               DirectFBError( "Failed flipping the primary surface", err );
               break;
          }
     }

     primary->Release( primary );
     buffer->Release( buffer );
     dfb->Release( dfb );

     return 42;
}

