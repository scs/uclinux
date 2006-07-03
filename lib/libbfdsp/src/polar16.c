// Copyright (C) 2000 - 2005 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************
   File: polar16.c

   This function takes the magnitude and phase, describing the complex
   number a in polar notation, as input argument. 
   The output argument is the complex number a in cartesian notation: 
    
     a.real = Magnitude * cos(Phase);
     a.imag = Magnitude * sin(Phase);

   Magnitude: [0x8000 .. 0x7fff], length of vector A
   Phase:     [0x8000 .. 0x7fff], angle in radians, scaled by 2*pi.
              A negative phase is equivalent to traversing a circle,
              with the radius equal to the magnitude, clockwise. 
              A positive phase is equivalent to traversing the circle
              anti-clockwise. 

***************************************************************************/

#include <math.h>
#include <complex.h>
#include <fract.h> 

#define  __MULTIPLY_32_16_16(a,b)  mult_fr1x32(a,b)
#define  __NEGATE_16(a)            negate_fr1x16(a)


complex_fract16 _polar_fr16(fract16 mag, fract16 phase )
{
   complex_fract16   result;

   // Convert negative phase (traversing circle clockwise)
   // to positive phase (traversing circle anti-clockwise)
   // A phase of -1.00 is equal to a phase of 0.00
   // A phase of -0.25 is equal to a phase of 0.75
   // A phase of -0.50 is equal to a phase of 0.50
   // A phase of -0.75 is equal to a phase of 0.25 
   // etc.
   //
   // positive phase = 1 + negative phase     
   //    Problem: 1.0 is outwith the range of the type fract16 
   //    => (1 - max. positive value + max. positive value + negative phase 
   //    =  (max. positive value + negative phase)+(1 - max. positive value)             
   //    =  (0x7fff + negative phase) + 0x0001
   //
   // If the phase is zero or minus one, the computation can be reduced to:
   //    a.real = mag * cos(0) = mag
   //    a.imag = mag * sin(0) = 0
   //
   if( (phase == 0x0) || (phase == 0x8000) )
   {
     result.re = mag;
     result.im = 0x0;
     
     return result;
   }
   else if( phase < 0x0 )
   {
     phase = (0x7fff + phase) + 0x1;
   }


   // The fractional cosine and sine functions are limited in their
   // input and output range:
   // cos_fr16():                        sin_fr16():
   //       0x8000 (=-pi/2) = 0x0,             0x8000 (=-pi/2) = 0x8000,
   //       0x0000 (=0)     = 0x7fff,          0x0000 (=0)     = 0x0,
   //       0x7fff (=pi/2)  = 0x0              0x7fff (=pi/2)  = 0x7fff
   //
   // To compute the cosine and sine across the entire range of the phase, 
   // it is necessary to modify the phase. This can be done by taking
   // advantage of the symmetrical nature of the cosine and sine function:
   //   Q1: [  0   .. 1/2pi) :  cos_fr16(x),  sin_fr16(x), x=[0x0..0x7fff)
   //   Q2: [1/2pi ..    pi) : -cos_fr16(x), -sin_fr16(x), x=[0x8000..0x0)
   //   Q3: [   pi .. 3/2pi) : -cos_fr16(x), -sin_fr16(x), x=[0x0..0x7fff)
   //   Q4: [3/2pi ..   2pi) :  cos_fr16(x),  sin_fr16(x), x=[0x8000..0x0) 
   //
   // To match the phase [0..1.0) to x requires at most two transformations.
   // Firstly, the range for the phase in each quarter Q1 to Q4 is 0.25 
   // while the range for x is 1.0. Therefore the phase has to be multiplied 
   // by four. For example:
   //   Q1: x=[0x0..0x7fff), phase=[0..0.25)    => phase_m = phase * 4
   // 
   // Secondly for Q2, Q3 and Q4 it is also necessary to modify the phase
   // in such a way that it falls into the desired input range for x:
   //   Q2: x=[0x8000..0x0), phase=[0.25..0.50) => phase_m = (-0.5+phase)*4   
   //   Q3: x=[0x0..0x7fff), phase=[0.50..0.75) => phase_m = ( phase-0.5)*4
   //   Q4: x=[0x8000..0x0), phase=[0.75..1.00) => phase_m = (-1.0+phase)*4
   //
   if(phase < 0x2000)  // <0.25
   {
     // first quarter [0..pi/2):
     //   cos_fr16([0x0..0x7fff]) = [0x7fff..0)
     //   sin_fr16([0x0..0x7fff]) = [0..0x7fff)
     phase = phase * 4;
   }
   else if( phase < 0x6000 )  // < 0.75
   {
     // if( phase < 0x4000 )  // <0.5
     // second quarter [pi/2..pi):
     //   -cos_fr16([0x8000..0x0)) = [0..0x8000)
     //   -sin_fr16([0x8000..0x0)) = [0x7fff..0)
     //   a.real = mag * (-cos_fr16(phase)) = -mag * cos_fr16(phase)
     //   a.imag = mag * (-sin_fr16(phase)) = -mag * sin_fr16(phase)
     //
     // if( phase < 0x6000 )  // < 0.75
     // third quarter [pi..3/2pi):
     //   -cos_fr16([0x0..0x7fff]) = [0x8000..0)
     //   -sin_fr16([0x0..0x7fff]) = [0..0x8000)
     //   a.real = mag * (-cos_fr16(phase)) = -mag * cos_fr16(phase)
     //   a.imag = mag * (-sin_fr16(phase)) = -mag * sin_fr16(phase)
     phase = (0xc000 + phase) * 4;
     mag   = __NEGATE_16(mag);
   }
   else   
   {
     // fourth quarter [3/2pi..pi):
     //   cos_fr16([0x8000..0x0)) = [0..0x7fff)
     //   sin_fr16([0x8000..0x0)) = [0x8000..0)
     phase = (0x8000 + phase) * 4 ;
   }

   result.re = (__MULTIPLY_32_16_16(mag,cos_fr16(phase))) >> FRACT16_BIT;
   result.im = (__MULTIPLY_32_16_16(mag,sin_fr16(phase))) >> FRACT16_BIT;

   return (result);
}

/*end of file*/
