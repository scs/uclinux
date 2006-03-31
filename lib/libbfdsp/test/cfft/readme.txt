****************************************************************************

ADSP-BF535 Complex FFT Demo

Analog Devices, Inc.
DSP Division
Three Technology Way
P.O. Box 9106
Norwood, MA 02062

Date Created:	3/11/02	

This directory contains example ADSP-BF535 program that implements a complex FFT 
routine.

Files contained in this directory:

readme.txt			this file
test_cfft.c			C source file for the fir routine
twiddles.dat		twiddle factors
in.dat				example input data file
 _________________________________________________________________

I. FUNCTION/ALGORITHM DESCRIPTION

The project contains the implementation of an 8K complex FFT algorithm.
  
II.   IMPLEMENTATION DESCRIPTION

The Blackfin DSP library routine is used to apply the FIR filter.  The twiddle 
factors are stored in twiddles.dat

Note that the twiddle factors can also be derived using the twidfft function 
using from the DSP library.

The output is stored in out.dat. You can run this test case in VDSP and compare the result. 

Note: 1.15 fractional data is used in this example.
