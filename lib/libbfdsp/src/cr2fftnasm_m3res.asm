/****************************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ****************************************************************************************
  File Name    : cr2fftn.asm
  Module Name  : one dimensional radix 2 forward FFT for complex data.
  Label name   :  __cfftN_fr16
  Description  : This file contains the code for the implementation of FFT. The algorithm 
		 used is Decimation in Time. For the optimization point of view, the whole
		 computation of butterfly signal flow has been divided in three parts. The
		 first part, the middle part and the last part. In the first part, the 
		 Stage 1 and Stage 2 of the butterfly structure are implemented. In the 2nd
		 part the general butterfly computation is done, which corresponds to the 
		 middle stages of butterfly. In the last part the last stage of the butterfly
		 structure is implemented, where mainly the loop overheads are saved.

		 Input and output both are complex and 16 bit and represented in 1.15 
		 format. The loop unrolling is also done for optimization point of view. 
		
		 The C callable prototype of the function is as follows:

		 void cfftN(const complex_fract16  *in,  complex_fract16 *t, complex_fract16 *out,
			    const complex_fract16 *w, int wst, int n, int block_exponent, 
			    int scale method);
	  
		*in -> Pointer to Input array. 
		*t -> Pointer to temporary buffer. 
		*out -> Pointer to Output array.
		*w -> Pointer to Twiddle factor. 
		wst -> Twiddle factor Stride. It is equal to 512/(size of input).
		n -> length of Input data.
		block_exponent -> Block exponent of Output data, set to 0.
		scale_method -> Scaling method done. Static Scaling is used. Set to 0.

		 The C equivalent code for the main loop of each butterfly is 
		 as follows.

		 for(i=0; i<le; i++)
		 {   
		   xire = out[add].re >> 1;
		   xiim = out[add].im >> 1;
		   xipre = out[add+indx].re >> 1;
		   xipim = out[add+indx].im >> 1;

		   mult.re = ((xipre * wptr[indx_w].re - xipim * wptr[indx_w].im) >>15);
		   mult.im = ((xipre * wptr[indx_w].im + xipim * wptr[indx_w].re) >>15);
		
		   out[add].re = xire + mult.re; 
		   out[add].im = xiim + mult.im;
		   out[add+indx].re = xire - mult.re;
		   out[add+indx].im = xiim - mult.im;
		   add = add + 2*offset;
		}
		The output is provided in normal order.
 
  Restrictions : The length of input array should be more than 4.i.e, 8, 16, 32
		 and it should be power of 2.

  Registers Used : 
       R0 -> It is mainly used for counter for middle stages. Its value is equal to m-3.
	     if m are the total number of stages for a particular n.
       R1 -> It is used for the storing the value of wst. wst = 512/n.
       R2 -> Used for storing Input/Output data.
       R3 -> used for storing the twiddle factor value.
       R4 -> Used for storing Input/Output data.
       R5 -> Used for storing Input/Output data.
       R6 -> Used for storing Input/Output data.
       R7 -> Used for calculating and storing the address offset for twiddle factor 
	     array.
       P0 -> It is used for storing the address offset of output buffer in middle part
	     of implementation.
       P1 -> It is used for storing the address offset of output buffer in middle part
	     of implementation.
       P2 -> It is used for storing the address offset of output buffer in middle part
	     of implementation.
       P3 -> It stores the number of lines for the butterflies at a particular stage.
       P4 -> It stores the value of input array length.
       P5 -> It stores the number of butterflies at a particular stage.
       A0 -> Used for storing the value of MAC temporarily.
       A1 -> Used for storing the value of MAC temporarily.
       B0 -> Start address of Input array.
       B2 -> start address of output array.
       B3 -> Start address of twiddle factor buffer.
       L3 -> Length of twiddle table.
       I0 -> Address for input array.
       I1 -> Address for output and temporary array while computing.
       I2 -> Address for output array while computing.
       I3 -> Address for twiddle factor array.
      
       
       All the input buffers are in different memory bank.

Performance:
	    The code size = 444 Bytes.

	    The cycle count for N = 32  =  503 cycles.
	    The cycle count for N= 256  = 4968 cycles.

Code Modified on 22.01.2002 for removing the usage of M3 register in the correct version


****************************************************************************************/

/***************************************************************************************/
.text;
.global                 __cfftN_fr16;
.align                  2;

__cfftN_fr16:

/**************** Function Prologue ****************************************************/
	[--SP] = (R7:4, P5:3);
	B0 = R0;             //Address of Input buffer
	B1 = R1;             //Address of temporary buffer
	B2 = R2;             //Address of output buffer
	R0 = [SP+40];        //The address of Twiddle factor
	R3 = [SP+44];        //The value of wst.  wst = 512/n.
	R2 = [SP+48];        //The value of length of input array

	R4 = 4;
	CC = R2 <= R4;       //Exit if the number of input samples is <= 4
	If CC Jump Terminate;

	P1 = R3;             //Preserve wst

	B3 = R0;             //Address of twiddle table
	R3<<= 1;             //Length of twiddle table = wst * 2
	R3*= R2;             //Length of twiddle table = wst * 2 * N
	L3 = R3;
	    // This function will speculatively load values out of the
	    // twiddle table that are beyond the end of the array - this
	    // will cause an exception if the memory referenced does not
	    // exist.
	    //
	    // The twiddle table is therefore accessed as a circular buffer.

/***************************************************************************************/

/************************** Implementation of First part *******************************/

/*
* First of all the input array is copied in temporary buffer in bit reversed order.  
* Then the stage 1 and 2 of the butterfly structure are implemented. After the comput-
* ation the result is stored to output array. The main reason for separating it out from
* the general computation, is that the multiplications of both the stages can be avoided. 
* 
* In the first stage of signal flow, there are n/2 number of butterflies. Each butterfly
* works on two inputs. These input are multiplied by W0 and added and subtracted. 
* Multiplying a data with W0 which is eqaul to 1 +0j will result the same data.
* 
* In the  second stage the number of butterflies are n/4. The data are added and subtra-
* cted after multiplication with W0 and Wn/4. The multiplication with W0 doesn't have
* any impact. The multiplication of data x+jy with Wn/4 will give the value y-jx. 
*
* Therefore, the multiplications involved in both the stages 1 and 2, can be reduced to 
* additions only. The output is stored after dividing by 2 for scaling purpose. In one loop
* data corresponding to 2 butterflies are processed.
*/

	I0 = B0;               //Address of Input array
	P4 = R2;               //The length of Input array.
	R3 = R2 << 1;    
	M0 = R3;              //M0 stores the offset required for bit reversing
	M1 = B1;              //M1 stores the address for temporary buffer.
	P5 = P4 >> 2;         //P5 is equal to number of butterflies at Stage 2.
	I1 = 0;               //I1 is initialized to 0 for bit reversing.
	R0 = [I0++];
	lsetup (copy_strt, copy_end) LC0 = P4;   //Loop for the size of input length.
copy_strt:
	I2 = I1;
	R1 = R0 >>> 1 (V) || I2 += M1 || R0 = [I0++]; 
copy_end: MNOP || I1 += M0 (BREV) || [I2] = R1;



	MNOP;
	NOP;
	I2 = B2;             //Address of output array
	I1 = B1;             //Address of temporary buffer.
//Below the loop is set for half of the number of butterflies at Stage 2.

	R2 = [I1++];         //R2 reads the data
	R3 = [I1++];
	R4 = [I1++];
	R2 = R2 +|+ R3, R3 = R2 -|- R3 (ASR) || R5 = [I1++] || NOP;

	lsetup(Stage12_strt, Stage12_end) LC0 = P5 >> 1;
Stage12_strt:
	R0 = [I1++];
	R1 = [I1++];
	R4 = R4 +|+ R5, R5 = R4 -|- R5 (ASR, CO) || R6 = [I1++];
	R2 = R2 +|+ R4, R4 = R2 -|- R4 (ASR) || R7 = [I1++] ;
	R5 = R3 +|- R5, R3 = R3 -|+ R5 (ASR) || [I2++] = R2;
	R0 = R0 +|+ R1, R1 = R0 -|- R1 (ASR) || [I2++] = R3;

	R6 = R6 +|+ R7, R7 = R6 -|- R7 (ASR, CO) || [I2++] = R4;
	R0 = R0 +|+ R6, R6 = R0 -|- R6 (ASR) || [I2++] = R5;
	R7 = R1 +|- R7, R1 = R1 -|+ R7 (ASR) || [I2++] = R0 || R2 = [I1++];
	[I2++] = R1 || R3 = [I1++];
	[I2++] = R6 || R4 = [I1++];
Stage12_end: R2 = R2 +|+ R3, R3 = R2 -|- R3 (ASR) || [I2++] = R7 || R5 = [I1++];


	R1 = P1;                 //R1 = wst.
	R1 = R1 << 2;            //R1 = wst * 4
	P3 = 4;                  //P3 holds the number of lines 
					 //   in each butterfly at stage 3.
	R7 = P5;  
		R7 *= R1;                //R7 = wst * 4  * twiddle offset
	R2 = P4;  
	R3 = 8;
	M1 = 16;
	CC = R2 == R3;           //If input array size is eqaul to 8, then go to last stage, because
	If CC Jump Esc_mid;      //middle stages does n't occur.
	R0 = 0;        //Counter for number of stages.

    Find_m:            //The computation of number of stages is done here.
	R2 >>= 1;
	R0 += 1;
	CC = R2 == R3;
	If !CC Jump Find_m (BP);  //R0 holds the value of m-3 and is never free


/*
* First of all, a loop for the number of stages - 3 is set. It is a general implementation
* of butterfly computation. The first nested loop is set for half of the number of butter-
* flies at each stage. The second nested loop is set for the number of lines in each butt-
* erfly. The computation is done on the output array. The output is stored after dividing
* by 2 for scaling purpose. In one loop two butterfly data are read and processed.
*/
    Loopfor_m:
	I2 = B2;             //Address of output array.
	I1 = B2;             //Address of output array.
	P0 = P3 << 2; 
	M2 = P0;             //M2 holds the offset of counterpart line.
	P2 = P0 << 1;
//      M1 = P2;             //M1 holds the offset of next butterfly.
	P1 = P2 + P0;
	M0 = P1;             //The offset used for the third butterfly.
	P5 = P5 >> 1;
	R7 = R7 >>> 1 || I1 += M0;
	M1 = R7;             //Twiddle factor offset.
	lsetup(Loop1_strt, Loop1_end) LC0 = P5 >> 1;  //Loop is set for half of the butterfly

    Loop1_strt:
	I3 = B3;            //Address of twiddle factor.
	R2 = [I2++M2];
	I2 -= M2 || R4 = [I2];
	R3 = [I3++M1];

	lsetup(Loop2_strt, Loop2_end) LC1 = P3;    //Loop is set for the number of lines 
    Loop2_strt:                                    //per butterfly. 
	R2 = R2 +|+ R4, R4 = R2 -|- R4 (ASR) || I1 -= M2 || R6 = [I1];
	A1 = R3.L * R6.H, A0 = R3.L * R6.L || [I2++M2] = R2 || R5 = [I1];
	R6.H = (A1 += R3.H *R6.L), R6.L = (A0 -= R3.H * R6.H) || R3 = [I3++M1] || [I2++] = R4;
	R5 = R5 +|+ R6, R6 = R5 -|- R6 (ASR) || I2 -= M2 || R4 = [I2];
	A1 = R3.L * R4.H, A0 = R3.L * R4.L || [I1++M2] = R5;

    Loop2_end:R4.H = (A1 += R3.H * R4.L), R4.L = ( A0 -= R3.H * R4.H) || [I1++] = R6 || R2 = [I2];
	I1 += M0;
    Loop1_end: I2 += M0; 
	M1 = P2;
	P3 = P3 << 1;
	R0 += -1;
	CC = R0 == 0;
	If !CC Jump Loopfor_m (BP);   //Loop for m.


/*
* This part implements the last stage of the butterfly. The label Esc_mid is used
* when the size of input data is 8. In this case the computation of middle stages have
* to be escaped. The increment in the twiddle factor offset is just 1. In the last stage
* there is only one butterfly. The loop is set for n/4. 4 data are read and processed at
* the same time.
*/

Esc_mid:I2 = B2;      //I2 holds the address output array
	I0 = B2;
	I1 = B2;      //Address of output array
	I3 = B3;      //I3 holds the twiddle factor address.
	R7 = R7 >>> 1 || I1 += M1 || NOP;
	M2 = R7;      //M2 holds twiddle factor offset.
	M0 = 8;

	I2 += M1 || R2 = [I0];
	I1 += 4 || R3 = [I3++M2];
	R4 = [I2];

	lsetup(Last_strt, Last_end) LC1 = P3 >> 1;    //Loop is set for the number of lines 
    Last_strt:                                    //per butterfly.
	R3 = [I3++M2];
	R2 = R2 +|+ R4, R4 = R2 -|- R4      || I1 -= M1         || R6 = [I1];
	A1 = R3.L * R6.H, A0 = R3.L * R6.L  || [I2++M0] = R4    || R5 = [I1];
	R6.H = (A1 += R3.H * R6.L), R6.L = (A0 -= R3.H * R6.H)  || R3 = [I3++M2];
	R5 = R5 +|+ R6, R6 = R5 -|- R6      || [I0++M0] = R2    || R4 = [I2];
	A1 = R3.L * R4.H, A0 = R3.L * R4.L  || [I1++M1] = R5;
    Last_end: R4.H = (A1 += R3.H * R4.L), R4.L = ( A0 -= R3.H * R4.H) || [I1++M0] = R6 || R2 = [I0];

/***************************************************************************************/

    Terminate:
	L3 = 0;
	(R7:4, P5:3) = [SP++]; //Pop the registers before returning.
	RTS;                            //Return.
.__cfftN_fr16.end:

