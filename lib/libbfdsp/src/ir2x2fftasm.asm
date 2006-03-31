/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File Name    : ir2x2fftasm.asm
  Module Name  : Two dimensional radix 2x2 inverse FFT for complex data.
  Label name   :  __ifft2d_fr16
  Description  : This file contains the code for the implementation of FFT. The
		 algorithm used is Decimation in Frequency. For the optimization
		 point of view, the whole computation has beeen divided in three
		 parts. The first stage, the middle stages and the last stage
		 of butterfly structures are computed separately. In the Last
		 stage there is no need to multiply with twiddle factor, while
		 in the first stage the computation of address index for data
		 and twiddle factor is much easier than middle stages. Input 
		 and output both are complex and 16 bit and represented in
		 1Q15 format.

		 The input and the output are in normal order. First of all it 
		 interchanges the real and imaginary part of input data and then
		 computes forward fft on that and again the real and imaginary
		 part of output data is interchanged.

		 The C equivalent code for the main loop of each stage is 
		 as follows. The algorithm is Inplace.

		 for(k1= 0; k1 < le; k1++)
		 {
		  indxk1 = indx * k1;     // first twiddle factor index.
		  for(k2 = 0; k2 < le; k2++)
		  {
		   indxk2 = indx * k2; //second twiddle factor index.
		   indxk1k2 = indx * (k1+k2);  //Third twiddle factor index.
		   for(n1= k1; n1 < n; n1 = n1 + 2*le)
		   {
		    for(n2 = k2; n2 < n; n2 = n2 + 2*le)
		    {
		      offset1 = n1*n +n2;   
		      offset2 = (n1+le)*n + n2;

		      temp1.re = (out[offset1].re + out[offset1+le].re + 
				  out[offset2].re + out[offset2+le].re)>>2;
		      temp1.im = (out[offset1].im + out[offset1+le].im + 
				  out[offset2].im + out[offset2+le].im)>>2;
		      temp2.re = (out[offset1].re - out[offset1+le].re + 
				  out[offset2].re - out[offset2+le].re)>>2;
		      temp2.im = (out[offset1].im - out[offset1+le].im + 
				  out[offset2].im - out[offset2+le].im)>>2;
		      temp3.re = (out[offset1].re + out[offset1+le].re - 
				  out[offset2].re - out[offset2+le].re)>>2;
		      temp3.im = (out[offset1].im + out[offset1+le].im - 
				  out[offset2].im - out[offset2+le].im)>>2;
		      temp4.re = (out[offset1].re - out[offset1+le].re - 
				  out[offset2].re + out[offset2+le].re)>>2;
		      temp4.im = (out[offset1].im - out[offset1+le].im - 
				  out[offset2].im + out[offset2+le].im)>>2;
	    
		      temp = ((temp2.re * w[indxk2].re - 
			       temp2.im * w[indxk2].im)>>15);
		      temp2.im = ((temp2.re * w[indxk2].im + 
				   temp2.im * w[indxk2].re)>>15);
		      temp2.re = temp;
		      temp = ((temp3.re * w[indxk1].re - 
			       temp3.im * w[indxk1].im)>>15);
		      temp3.im = ((temp3.re * w[indxk1].im + 
				   temp3.im * w[indxk1].re)>>15);
		      temp3.re = temp;
		      temp = ((temp4.re * w[indxk1k2].re - 
			       temp4.im * w[indxk1k2].im)>>15);
		      temp4.im = ((temp4.re * w[indxk1k2].im + 
				   temp4.im * w[indxk1k2].re)>>15);
		      temp4.re = temp;

		      out[offset1].re = temp1.re;
		      out[offset1].im = temp1.im;
		      out[offset1 + le].re = temp2.re;
		      out[offset1 + le].im = temp2.im;
		      out[offset2].re = temp3.re;
		      out[offset2].im = temp3.im;
		      out[offset2 + le].re = temp4.re;
		      out[offset2 + le].im = temp4.im;
		     }
		    }
		   }
		  }
 
  Assumptions : The minimum size of input matrix is 4 x 4.
  Registers Used : R0, R1, R2, R3, R4, R5, R6, R7, P0, P1, P2, P3, P4, P5.
  Other Register Used : A0, A1, I0, I1, I2 set and LC0 and LC1.

   All the input buffers are in different memory bank.

Performance:
	    The code size   =  800 bytes.
	    The cycle count for 8 x 8 input     =   3111  cycles.
	    The cycle count for 16 x 16 input   =  14617  cycles.

**********************************************************************************/

/************************ Program Section ****************************************/
//The name for the Radix 2x2 FFT label is __ifft2d_fr16.

.text;
.global                 __ifft2d_fr16;
.align                  2;

__ifft2d_fr16:
/*********************** Function Prologue ***************************************/
	[--SP] = (R7:4, P5:3);    //Saves the context of registers
	B0 = R0;               //Start Address of Input data
	B1 = R1;               //Start Address of temporary array t
	B2 = R2;               //Start Address of output data
	R0 = [SP+40];             
	P0 = [SP+44];           //It provides the multiplication factor wst
	P1 = [SP+48];             //Number of rows/columns (n) in Input array
	I0 = B0;             //Address of Input array
	I1 = B2;             //Address of output array 
	L0 = 0; 
	L1 = 0;
	L2 = 0;
	L3 = 0;
	B3 = R0;             //Start Address of Twiddle factor
	SP += -32;
	[SP+4] = P1;
	R0 = P1;              //R0 = n
	CC = P1 <= 2;          //If input matrix has rows/colums less than 4
	If CC Jump Terminate;  //then Terminate the program.

/*****************************************************************************/
//Copy the input data to output buffer so that input values can be preserved.

	R0 = R0.L * R0.L (IS);            //R0 = n square
	P2 = R0;
	R0 = [I0++];
	P3 = P1;                          //P3 holds the values of n 
	I2 = B2;
	R1 = R0 >>> 2 (V);
	lsetup(Copy_strt, Copy_end) LC0 = P2;
    Copy_strt:
	    R1 = PACK (R1.L, R1.H) || R0 = [I0++];
    Copy_end: R1 = R0 >>> 2 (V) || [I1++] = R1;  //Copy the data

/*****************************************************************************/
//If the number of rows in matrix is n, then following loop finds the value of
//m for which 2 powers m equals n.


	R1 = P1;
	R2 = R1 << 1;
	M2 = R2;            //offset1+le

	P2 = 0;                   
    Find_m:
	P3 = P3 >> 1;
	P2 += 1;
	CC = P3 == 2;
	if !CC Jump Find_m;  //P2 holds the value of m - 1           

//I0, I1, I2, I3 all stores the starting address of output buffer.
	
/**********************************************************************************/

/***************** Implementation of First Stage **********************************/

	R1 = R1.L * R1.L (IS) || I2 += M2;
	R1 = R1 << 1;             //I2 stores the Even-odd address of butterfly.
	M1 = R1;                  //offset2
	I1 = B2;
	[SP+16] = P2;             //P2 is made free for furthe use.
	I0 = B2;                  //I0 stores the starting address of output.
				  //and works as Even-even.
	R1 = R1 + R2 (NS)  || I1 += M1;
	M3 = R1;                 //I1 stores the Odd-even address of butterfly.
	I3 = B2;                 // M3 = offset2 +le
	P3 = B3;                 //Starting address of Twiddle factor
	P5 = P0 << 2;            //wst * 4 to get correct byte in buffer.
	I3 += M3;                //I3 stores the Odd-Odd address of butterfly.

	lsetup (First_n1_strt, First_n1_end) LC0 = P1 >> 1;   //Loop for n/2.
    First_n1_strt:
	lsetup (First_n2_strt, First_n2_end) LC1 = P1 >> 1;    //Loop for n/2.
	P4 = B3;                 //P4 holds the address of Twiddle factor.
	P2 = P3;                 //P4 as k2, P3 as k1 and P2 as k1+k2.
    First_n2_strt:

//The value of address offset1 and offset1 + le are read. The upper half stores
//the imaginary part of data, while the lower half stores the real part of
//data.
	R4 = [I0];
	R5 = [I2];
	R6 = [I1];

//The registers are added with corresponding offsets. R6 works as temp1, 
//R7 as temp3, R2 as temp2 and R4 as temp4.
 
	R2 = R4 +|+ R5, R3 = R4 -|- R5 (ASR) || R7 = [I3];
	R4 = R6 +|+ R7, R5 = R6 -|- R7 (ASR);
	R6 = R2 +|+ R4, R7 = R2 -|- R4 (ASR); 
	R2 = R3 +|+ R5, R4 = R3 -|- R5 (ASR) || R1 = [P3];


 
//Multiplication  of R7 with w[wst*k1]. The value of out[offset1 +le ] is
//restored. At the same time the value of w[wst*(k1+k2)] is read in R3. I2
//is incremented by 1 in offset.
       
	A1 = R7.L * R1.H, A0 = R7.L * R1.L;  
	R7.H = (A1 += R7.H * R1.L), R7.L = (A0 -= R7.H * R1.H) || R0 = [P4];
 
//Multiplication  of R2 with w[wst*k2]. The value of out[offset1] is restored.
//At the same time the value of w[wst*k1] is read in R1. I0 is incremented by
//1 in offset.

	A1 = R2.L * R0.H, A0 = R2.L * R0.L || I0 += 4 || [I0] = R6;
	R2.H = (A1 += R2.H * R0.L), R2.L = (A0 -= R2.H * R0.H) || R3 = [P2];

//Multiplication  of R4 with w[wst*(k1+k2)]. The value of out[offset2] is
//restored. After multiplication the value of out[offset2+le] is also stored
//back and I1 and I3 are incremented by i offset value.

	A1 = R4.L * R3.H, A0 = R4.L * R3.L || [I1++] = R7;
	R4.H = (A1 += R4.H * R3.L), R4.L = (A0 -= R4.H * R3.H) || [I2++] = R2;
	I3 += 4 || [I3] = R4;
	P2 = P2 + P5;              //P2 is incremented by 2*le.
    First_n2_end :  P4 = P4 + P5;  //P4 is incremented by 2*le.

//The value of I0, I1, I2, I3 are modified acoording to their role.
//In last P2 is incremented by 2*le.

	I0 += M2; 
	I1 += M2;
	I2 += M2;
	I3 += M2;
    First_n1_end: P3 = P3 + P5;

/*****************************************************************************/

/**************** Implementation of Middle Stages ****************************/

	P3 = P1 >> 1;          //P3 works as le
	P5 = 2;                //P5 works for twiddle factor index.
	P2 = [SP+16];          //P2 stores the value of m-1.
	I1 = B2;               //I1, I2 holds the start address of output.
	I2 = B2;
	I3 = B3;               //I3 holds the start address of Twiddle factor.

	CC = P2 == 1;          //This condition has been put for the matrix
	If CC Jump Last_Stage; //size of 4x4.

//The loop_for_m is executed for m-2 times due to the separation of
//first and last stage.

    Loop_for_m:
	P3 = P3 >> 1;          //P3 works as le.
	P1 = 0;                //Counter for Loop_for_k1.
    Loop_for_k1:
	R3 = P0;               //R3 = wst
	R4 = P5;               //R4 = indx
	R3 = R3.L * R4.L (IS); //R3 = wst * indx.
	R4 = P1;               //R4 = k1.
	R3 = R3.L * R4.L (IS); //R3 = wst * indx * k1
	R3 = R3 << 2;          //R3 is left shifted by 4 to get correct byte.
	B0 = R3;               //B0 stores indx * k1 * wst * 4.
	P4 = 0;                //Counter for Loop_for_k2.
    Loop_for_k2:
	R3 = P0;               //R3 = wst.
	R4 = P5;               //R4 = indx.
	M0 = B0;               //M0 = indx * k1 * wst * 4
	R3.L = R3.L * R4.L (IS) || I3 += M0;    //RL3 = wst * indx
	R5 = P4;               //R5 = k2.
	R3.L = R3.L * R5.L (IS) || R4 = [I3]; //RL3 = wst * indx * k2
	R3 = R3 << 2 || [SP+20] = R4;         //R3 = wst * indx * k2 * 4.
	M1 = R3;                //M3 = indx * k2 * wst * 4.

	R0 = P1;                 //n1 = k1.
	R0 = R0 << 16;
	lsetup(Loop_n1_strt, Loop_n1_end) LC0 = P5;
	I3 += M1;

	I3 -= M0 || R6 = [I3]; 
	I3 -= M1 || R5 = [I3];

//In the above packed operations R4 finally stores w[k1], R5 w[k2], and
//R6 w[k1+k2]. Below they are saved to make registers R4, R5, R6 free, so
//that they can be used further.

	[SP+12] = R5;               
	[SP+8] = R6;
	
    Loop_n1_strt:
	R1 = P4;                 //n2 = k2;
	R0 = PACK (R0.H, R1.L) || R2 = [SP+4];  //RH0 = n1, RL0 = n2;
						  //R2 stores the value of n.
	R3 = P3;                  //le
	R1.L = R0.H * R2.L (IS);    //RL1 = n1 * n
	R3.L = R0.H + R3.L(NS);   //n1+le
	lsetup(Loop_n2_strt, Loop_n2_end) LC1 = P5;
	R1.H = R3.L * R2.L (IS);  //RH1 = (n1+le) * n
    Loop_n2_strt:
	R3 = PACK (R0.L, R0.L);               //RL3 = RH3 = n2.
	R3 = R3 + R1 (NS);                    //RH3 = (n1+le) * n + n2.
	R3 = R3 << 2 (V);                     //Left shifted to get correct byte

	R4 = R3.L (X);                        //R4 = offset1
	M0 = R4;                              //M0 = offset1
	R4 = R3 >> 16;                        //R3 = offset2
	M1 = R4;                              //M1 = offset2

	R2 = P3;
	R2 = PACK (R2.L, R2.L);
	R2 = R2 << 2(V);                      //RH2 = le, RL2 = le.
	R2 = R3 + R2 (NS);

	R4 = R2 >> 16 || I2 += M1;            //R2 = offset2+le
	M3 = R4;                              //M3 = offset2+le
	R5 = R2.L (X);                        //R5 = offset1+le
	M2 = R5;                              //M2 = offset1+le

//R4, R5, R6 and R7 holds the value of out[offset1], out[offset1+le],
//out[offset2], out[offset2+le] respectively. After that they all are 
//right shifted by 2 to avoid the overflow. The upper 16 bits of register
//contains imaginary part of data while lower 16 bits contains real data.

	R6 = [I2++M0];
	
	I1 += M3;
	I2 -= M1 || R7 = [I1];
	I1 += M2 || R4 = [I2]; 
	I1 -= M3;
	R5 = [I1];

//The registers are added with corresponding offsets. R6 works as temp1, 
//R7 as temp3, R2 as temp2 and R4 as temp4.

	R2 = R4 +|+ R5, R3 = R4 -|- R5 (ASR);
	R4 = R6 +|+ R7, R5 = R6 -|- R7 (ASR);
	R6 = R2 +|+ R4, R7 = R2 -|- R4 (ASR);
	R2 = R3 +|+ R5, R4 = R3 -|- R5 (ASR);
	R3 = [SP+12];   //R3 = w[k2]

//The value of R2 is multiplied with w[k2]. The value of out[offset1] 
//is stored back.

	
	A1 = R2.L * R3.H, A0 = R2.L * R3.L  || R5 = [SP+20];    //R3 = w[k1]  
	R2.H = (A1 += R2.H * R3.L), R2.L = (A0 -= R2.H * R3.H) || I2 -= M0 || [I2] = R6;  //out[offset1] = temp1    
	
//The value of R7 is multiplied with w[k1]. The value of out[offset1+le] 
//is stored back.

	A1 = R7.L * R5.H, A0 = R7.L * R5.L || I2 += M1 || [I1] = R2; 
	R7.H = (A1 += R7.H * R5.L), R7.L = (A0 -= R7.H * R5.H) || I1 -= M2;
	R3 = [SP+8];  //R3 = w[k1+k]

//The value of R4 is multiplied with w[k1+k2]. The value of out[offset2] 
//is stored back. Then value of out[offset2+le] is also stored back.

	A1 = R4.L * R3.H, A0 = R4.L * R3.L || I2 -= M1 || [I2] = R7;
	R4.H = (A1 += R4.H * R3.L), R4.L = (A0 -= R4.H * R3.H) || I2 += M3;

	R5 = P3;
	R5.L = R5.L << 1 || I2 -= M3 || [I2] = R4;               //2*le
    Loop_n2_end: R0.L = R0.L + R5.L (NS);  //n1 is incremented by 2*le
	R4 = P3;
	R4.L = R4.L << 1;
    Loop_n1_end: R0.H = R0.H + R4.L (NS);     //n2 is incremented by 2*le

	P4 += 1;                 //counter for k2 is incremented.     
	CC = P4 == P3;
	If !CC Jump Loop_for_k2 (BP);
	P1 += 1;                //counter for k1 is incremented
	CC = P1 == P3;
	If !CC Jump Loop_for_k1 (BP);

	P5 = P5 << 1;          //indx is multiplied by 2.
	P2 += -1;              //counter for m is decremented
	CC = P2 == 1;
	If !CC Jump Loop_for_m (BP);

/*****************************************************************************/

/*************** Implementation of Last Stage ********************************/

    Last_Stage: P5 = P5 << 1;          //P5 = n
	P4 = P5 << 2;          //basically P5 is multiplied by 8.

//All the address registers I0. I1, I2, I3 hold the atarting address of
//output buffer. I0 works as offset1, I1 as offset2, I2 as offset1+le, and
//I3 as offset2+le.

	I0 = B2;
	I3 = B2;
	M1 = P4;
	I1 += M1;
	I2 = I0;
	I3 = I1;

	I2 += 4;
	I3 += 4;  //I2 and I3 are incremented by 1
	M0 = 8;                  //To increment the address offset by 2.
	lsetup(Last_n1_strt, Last_n1_end) LC0 = P5 >> 1;  
    Last_n1_strt:   
	lsetup(Last_n2_strt, Last_n2_end) LC1 = P5 >> 1; 
    Last_n2_strt:

//R4, R5, R6 and R7 holds the value of out[offset1], out[offset1+le],
//out[offset2], out[offset2+le] respectively. After that they all are 
//right shifted by 2 to avoid the overflow. The upper 16 bits of register
//contains imaginary part of data while lower 16 bits contains real data.

	R4 = [I0];
	R5 = [I2];
	R6 = [I1];
      
//The registers are added with corresponding offsets. R6 works as temp1, 
//R7 as temp3, R2 as temp2 and R4 as temp4.

	R2 = R4 +|+ R5, R3 = R4 -|- R5 (S) || R7 = [I3];
	R4 = R6 +|+ R7, R5 = R6 -|- R7 (S);
	R6 = R2 +|+ R4, R7 = R2 -|- R4 (S);
	R2 = R3 +|+ R5, R4 = R3 -|- R5 (S) || I0 += M0 || [I0] = R6;

//All the data are inplaced.
	I2 += M0 || [I2] = R2; 
	I1 += M0 || [I1] = R7;
    Last_n2_end: I3 += M0 || [I3] = R4; 
	I0 += M1;
	I1 += M1;
	I2 += M1;
    Last_n1_end: I3+=M1;

/*****************************************************************************/
//This code Bit reverses the output array.

	P1 = [SP+4];    //P1 stores back the value n.
	I2 = B2;
	I3 = B2;
	I0 = 0;
	P2 = P1 << 1;
	M1 = P2;         //M1 is used for bit reversing   
	A1 = 0;
	R0 = P1;         //R0 = n
	R1 = 0;          //Counter for first loop
	lsetup (Copy_row_strt, Copy_row_end) LC0 = P1;  //k1
    Copy_row_strt:
	R4 = I0;         //R4 = BR[k1];
	R3 = R1 << 2 || I0 += M1 (BREV) || NOP;    //I0 stores the bit reversed value  
							    //k1*4              
	R2 = 0;               //Counter for second loop
	I1 = 0;
	lsetup (Copy_col_strt, Copy_col_end) LC1 = P1;  //k2
    Copy_col_strt:
	R6 = I1;               //R6 = BR[k2]
	R5 = R2 << 2 || I1 += M1 (BREV) || NOP;  //I1 stores the bit reverse value

	A0 = R5;             //If satisfy all the conditions then swap the data.
	R7.H = A1, R7.L = (A0 += R3.L * R0.L) (IS);
	M2 = R7;               //M2 = k1*n + k2     //k2*4

	CC = R3 < R4;          //k1 < BR[k1].
	If CC Jump Swap;
	CC = R3 == R4;         //k1 == BR[k1].
	If !CC Jump Done;
	CC = R5 < R6;          //k2 < BR[k2].
	If !CC Jump Done;

    Swap: A0 = R6;
	R6.L = (A0 += R4.L * R0.L) (IS) || I2 += M2 || NOP;
	M3 = R6;              //M3 = BR[k1] * n + BR[k2]
	I3 += M3 || R6 = [I2];
	R7 = [I3];
	I3 -= M3 || [I3] = R6;
	I2 -= M2 || [I2] = R7;
	
    Done: I2 += M2;             //It Swaps the imaginary and real 
	R6 = [I2];              //part of output array and 
	R6 = PACK (R6.L, R6.H);
	I2 -= M2 || [I2] = R6;
    Copy_col_end:R2 += 1;   
    Copy_row_end:R1 += 1;


/*****************************************************************************/

    Terminate:
	SP += 32;
	(R7:4, P5:3) = [SP++];       //Pop the registers before returning.
	RTS;                           //Return.
.__ifft2d_fr16.end:
