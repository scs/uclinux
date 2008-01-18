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

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>

#define PI 3.1415926536f
#define MAX_JOYSTICKS 8

IDirectFB *dfb;
IDirectFBSurface *primary;

IDirectFBInputDevice *keyboard;

IDirectFBInputDevice *joystick[MAX_JOYSTICKS] =
                    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

int nr_joysticks = 0;

typedef struct _Particle
{
     float w;
     int sw, sh;
     int size;
     int launch;
     unsigned char r;
     unsigned char g;
     unsigned char b;
     struct _Particle *next;
} Particle;

Particle *particles = NULL;
Particle *last_particle = NULL;

DFBEnumerationResult enum_devices_callback( unsigned int id,
                           DFBInputDeviceDescription desc, void *data )
{
     if (desc.type & DIDTF_JOYSTICK) {
          dfb->GetInputDevice( dfb, id, &joystick[nr_joysticks] );
          nr_joysticks++;
     }

     return DFENUM_OK;
}


void spawn_particle(unsigned int r, unsigned int g,unsigned int b, float f)
{
     Particle *new_particle = (Particle*)malloc( sizeof(Particle) );

     new_particle->w = 0.05f;
     new_particle->sw = rand()%200 + 200*sin(f) + 200;// + 40*sin(f*5);
     new_particle->sh = rand()%100 + 350;// + 40*cos(f*5);
     new_particle->size = rand()%4 +2;
     new_particle->launch = rand()%5;
     new_particle->r = r;
     new_particle->g = g;
     new_particle->b = b;

     new_particle->next = NULL;


     if (!particles) {
          particles = new_particle;
          last_particle = new_particle;
     }
     else {
          last_particle->next = new_particle;
          last_particle = new_particle;
/*          Particle *next = particles;

          while (next->next)
               next = next->next;

          next->next = new_particle;*/
     }
}

void draw_particles()
{
     Particle *p = particles;

     while (p) {

          primary->SetColor( primary, p->r, p->g, p->b, 0x17 ); 
          primary->FillRectangle( primary, p->launch + sin(p->w/2)*(p->sw),
                                  480 - sin(p->w)*p->sh, p->w*p->size+1,
                                  p->w*p->size+1 );

          p->w += PI/500 * sqrt(p->w);

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

void destroy_particles()
{
     Particle *p = particles;

     while (p) {
          particles = p->next;
          free(p);
          p = particles;
     }
}

int main( int argc, char *argv[] )
{
     int i;
     DFBInputDeviceKeyState quit = DIKS_UP;
     DFBResult err;

     if (DirectFBInit( &argc, &argv ) != DFB_OK)
          return 1;

     if (DirectFBCreate( &dfb ) != DFB_OK)
          return 1;

     err = dfb->EnumInputDevices( dfb, enum_devices_callback, NULL );
     if (err != DFB_OK) {
          DirectFBError( "IDirectFBInput->EnumDevices failed", err );
          dfb->Release( dfb );
          return 1;
     } else
     if (nr_joysticks == 0) {
          printf( "No joysticks found!\n" );
          dfb->Release( dfb );
          return 1;
     }

     err = dfb->GetInputDevice( dfb, DIDID_KEYBOARD, &keyboard );
     if (err != DFB_OK) {
          DirectFBError( "IDirectFBInput->CreateDevice for keyboard failed",
                          err );

          dfb->Release( dfb );
          return 1;
     }

     err = dfb->SetCooperativeLevel( dfb, DFSCL_FULLSCREEN );
     if (err != DFB_OK) {
          DirectFBError( "Failed requesting exclusive access", err );
          keyboard->Release( keyboard );
          keyboard->Release( keyboard );
          dfb->Release( dfb );
          return 1;
     }

     err = dfb->SetVideoMode( dfb, 640, 480, 16 );
     if (err != DFB_OK) {
          DirectFBError( "Failed setting video mode", err );
          keyboard->Release( keyboard );
          dfb->Release( dfb );
          return 1;
     }

     {
          DFBSurfaceDescription dsc;

          dsc.flags = DSDESC_CAPS;
          dsc.caps = DSCAPS_PRIMARY | DSCAPS_VIDEOONLY | DSCAPS_DOUBLE;

          err = dfb->CreateSurface( dfb, &dsc, &primary );
          if (err != DFB_OK) {
               DirectFBError( "Failed creating primary surface", err );
               keyboard->Release( keyboard );
               dfb->Release( dfb );
               return 1;
          }
     }

     primary->Clear( primary, 0xFF, 0xFF, 0xFF, 0xFF );

     sleep(2);

     for (i=255; i>=0; i-=5) {
          primary->Clear( primary, i, i, i, 0xFF );
          err = primary->Flip( primary, NULL, DSFLIP_WAITFORSYNC );
          if (err != DFB_OK) {
               DirectFBError( "Failed flipping the primary surface", err );
               primary->Release( primary );
               keyboard->Release( keyboard );
               dfb->Release( dfb );
               return 1;
          }
          usleep(20000);
     }

     /* from now on we will always draw with alpha blending enabled */

     primary->SetDrawingFlags( primary, DSDRAW_BLEND );      

     while (!quit) {
          float normx;
          float normy;
          float f = 0;
          int joyx, joyy;
          unsigned int spawn = 0;
          unsigned int buttonmask = 0;

          primary->Clear( primary, 0, 0, 0, 0x17 );

          for (i=0; i<nr_joysticks; i++)
          {
               joystick[i]->GetButtons( joystick[i], &buttonmask );
               spawn |= buttonmask;
               joystick[i]->GetAxis(joystick[i], 0, &joyx);
               joystick[i]->GetAxis(joystick[i], 1, &joyy);
               normx = (joyx/32768.0f);
               normy = (joyy/32768.0f);
               f += normx *  PI/2;
               primary->SetColor( primary, 0xFF, 0xFF , 0xFF, 0x17 );
               primary->FillRectangle( primary,  (normx +1) * 310 ,
                                       (normy +1) * 230, 20, 20 );
          }
          if (nr_joysticks)
               f /= nr_joysticks;

          if (spawn & 1) {
               spawn_particle( 0xFF, 0x40, 0x40, f );
               spawn_particle( 0xFF, 0x40, 0x40, f );
               spawn_particle( 0xFF, 0x40, 0x40, f );
          }
          if (spawn & 2) {
               spawn_particle( 0x40, 0x40, 0xFF, f );
               spawn_particle( 0x40, 0x40, 0xFF, f );
               spawn_particle( 0x40, 0x40, 0xFF, f );
          }
          if (spawn & 4) {
               spawn_particle( 0xFF, 0xFF, 0x00, f );
               spawn_particle( 0xFF, 0xFF, 0x00, f );
               spawn_particle( 0xFF, 0xFF, 0x00, f );
          }
          if (spawn & 8) {
               spawn_particle( 0x40, 0xFF, 0x40, f );
               spawn_particle( 0x40, 0xFF, 0x40, f );
               spawn_particle( 0x40, 0xFF, 0x40, f );
          }

          draw_particles();

          err = primary->Flip( primary, NULL, DSFLIP_BLIT );
          if (err != DFB_OK) {
               DirectFBError( "Failed flipping the primary surface", err );
               break;
          }

          keyboard->GetKeyState( keyboard, DIKI_ESCAPE, &quit );
     }

     destroy_particles();

     primary->Release( primary );
     keyboard->Release( keyboard );
     for (i=0; i<nr_joysticks; i++) {
          joystick[i]->Release( joystick[i] );
     }

     dfb->Release( dfb );

     return 0;
}
