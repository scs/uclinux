/******************************************************************************
File Name   : FFT_Rad4_Twiddle_Factors.h
Description : This file contains the twiddle factors required for testing Radix 
              4 FFT for 16, 32, 64, 128, 256, 512, 1024, 2048 or 4096 points.
              The twiddle factor array is generated using the formula
              
                             twiddles(3k)   = exp(-2*j*pi*2*k/N)
                             twiddles(3k+1) = exp(-2*j*pi*  k/N)
                             twiddles(3k+2) = exp(-2*j*pi*3*k/N)
                             
                             k=0,1,...,N/4-1
                             where N is the number of points.
                             
			  Note the swap of the middle two terms.                             
			  
			  For last radix-2 stage two more terms are added at the end:
			  
							 0x0000,	0x8000,
							 0x0000,	0x8000,

              For finding Radix 4 FFT 3*N/4 twiddle factors are required 
              and are stored as real and imaginary values alternately, 
              i.e, cos and -sin.
****************************************************************************/

#if N == 16
#pragma align 4
section ("L1_data_a")
short twiddles[3*N/2+4] = {
                          #include "twiddles16rad4.dat"
		             	  };                    

#elif N == 32
#pragma align 4
//section ("L1_data_a")
__attribute__ ((aligned(4)))          
short twiddles[3*N/2+4] = {
                          #include "twiddles32rad4.dat"
		             	  };           

#elif N == 64
#pragma align 4
section ("L1_data_a")
short twiddles[3*N/2+4] = {
                          #include "twiddles64rad4.dat"
		             	  };                    

#elif N == 128
#pragma align 4
section ("L1_data_a")
short twiddles[3*N/2+4] = {
                          #include "twiddles128rad4.dat"
		             	  };                    

#elif N == 256
#pragma align 4
section ("L1_data_a")
short twiddles[3*N/2+4] = {
                          #include "twiddles256rad4.dat"
		             	  };                    

#elif N == 512
#pragma align 4
section ("L1_data_a")
short twiddles[3*N/2+4] = {
                          #include "twiddles512rad4.dat"
		              	  };                    

#elif N == 1024
#pragma align 4
//section ("L1_data_a")
__attribute__ ((aligned(4)))  
short twiddles[3*N/2+4] = {
                          #include "twiddles1024rad4.dat"
		             	  };                    

#elif N == 2048
#pragma align 4
//section ("L1_data_a")
__attribute__ ((aligned(4))) 
short twiddles[3*N/2+4] = {
                          #include "twiddles2048rad4.dat"
		             	  };                    

#elif N == 4096
#pragma align 4
//section ("L1_data_a")
__attribute__ ((aligned(4))) 
short twiddles[3*N/2+4] = {
                          #include "twiddles4096rad4.dat"
		             	  };                       
#endif

 



