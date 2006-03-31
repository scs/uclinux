/****************************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ****************************************************************************************
 
  File Name     : conv2d.asm
  Module Name   : Convolution
  Label name    :  __conv2d_fr16
  Description   : This file contains two dimensional convolution  of two given
		  matrices. The whole implementation is in Assembly language 
		  for Blackfin Processor. In this implementation convolution of
		  two matrices `a` and `b` is calculted. The dimension of 'a'
		  is na x ma and that of 'b' is nb x mb. The dimension of the
		  output matrix c will nc x mc, where -
		  nc = na + nb - 1.
		  mc = ma + mb - 1.
		  The equivalent C code is as follows:

		  for (i = 0; i < num_rowof_b; i++)
		  {
		     for (j = 0; j < num_colof_b; j++)
		     {
		       w = *(r++); //Starting address of B
	 
		       p = c1 + j + i * num_colof_c; //P points to 32 bit buffer
		       q = a;               //Starting address of A

		       for (k = 0; k < num_rofof_a; k++)
		       {
			 for (l = 0; l < num_colof_a; l++)
			 {
			    *p = *p + ((*q *w)>>15);
			    p++, q++;
			
			 }
			 p += mb - 1;
		       }
		     }
		    }

		 There is no restriction on the size of both the arrays. The
		 whole implementation is for 16 bit fract input output. The
		 format of representation is 1Q15 format. 

  Registers Used : R0, R1, R2, R3, R4, R5, R6, R7, A0, A1, P0, P1.
  Other Register Used : I0, I2, I3 set and LC0 and LC1.

  All the buffers A, B, C and temp are pointing to different memory bank.

  Performance:
	       The Code size = 188 bytes.
	       The cycle count for A = 3 x 4 and B = 2 x 5    =  1073 cycles. 
	       The cycle count for A = 4 x 11 and B = 3 x 15  = 11895 cycles

****************************************************************************************/
/*
* The stack is used for temporary storage of intermediate results.
* It is done to minimize the bit error. The following example illustrates its
* importance.
*
*      Let x_16 = 0x5000;           Let y_16 = 0x6000;          Let z_16 = 0xC000;
*      Let temp_16 and temp_32 are two intermediate storage.
*
*      The operation temp_16 = x_16 + y_16  = 0x5000 + 0x6000 = 0xb000 = 0x7fff.
*      The operation temp_16 = temp_16 + z_16 = 0x7fff + 0xc000 = 0x3fff. ........(1)
*
*      The operation temp_32 = x+16 + y_16 = 0x5000 + 0x6000 = 0xb000.
*      The operation temp_32 = temp_32 + z_16 = 0xb000 + 0xffffc000 = 0x7000. .....(2)
*
* Now, from (1) and (2) the bit error introduced in the first operation is understood. 
*/

/***************************************************************************************/

.text;
.global                 __conv2d_fr16;
.align                  2;

__conv2d_fr16:
/**************************** Function Prologue ****************************************/
	[--SP] = (R7:4, P5:3);
	B0 = R0;         //address of matrix A
	R0 = [SP+40];    //address of matrix B
	I1 = R0;         //Address of matrix B
	P0 = R1;         //na
	P1 = R2;         //ma
	L0 = 0;
	L1 = 0;
	L2 = 0;
	L3 = 0;
	R0 = [SP+44];    //nb
	R1 = [SP+48];    //mb
	P2 = [SP+52];    //Address of matrix C 

/***************************************************************************************/
/*
* In this section Condition checking and some of the basic address offset
* calculations are done.
*/

	P3 = R1; 
	CC = R0 <= 0;        //If nb < =0, then terminate.
	If CC Jump Terminate;
	CC = R1 <= 0;        //If mb <= 0, then terminate.
	If CC Jump Terminate;
	CC = P0 <= 0;        //If na <= 0, then terminate.
	If CC Jump Terminate;
	CC = P1 <= 0;        //If ma <= 0, then terminate.
	If CC Jump Terminate;
 
	P3 += -1;           //P3 stores the value of mb-1.
	P4 = P3 + P1;       //P4 = ma +mb -1
	P3 = P3 << 2;
	M2 = P3;            //M2 holds (mb-1)*4, which is used for address offset.

	P3 = P1 << 2;
	P3 += -4;           
	M0 = P3;           //M0 = (ma -1)*4, which is used for address offset.
	R3 = P0;           //na
	R3 = R3 + R0;      //na +nb;
	R3 += -1;          //na + nb -1;
	R4 = P4;

	R3 = R3.L * R4.L (IS);  //P4 = (na+nb-1)*(ma+mb-1); This register is used as the
	P4 = R3;           //P4 = (na+nb-1)*(ma+mb-1); This register is used as the
	


	P5 = P4 << 2;
	SP -= P5;
	B3 = SP;           // Temporary storage in stack 
	P5 = 2;            //counter for copying the data from 32 bit to 16 bit output.
	R5 = 0;            //Initiatlization of array temporary storage locations.
	I3 = B3;           //I3 points to the stack, latter I2 also points to stack.

	lsetup(Init_strt, Init_strt) LC0 = P4;         //Loop for nc*mc
	Init_strt:[I3++] = R5;

	I3 = B3;           //Address to stack

/***************************************************************************************/

/*
* In the following section the convolution calculation is done and the result is stored
* in stack area, the size of which is equal to twice that of the output buffer.
*/
    Loopfor_nb:           //Loop for number of rows of B, nb.
	R5 = R1;          //Counter for Loopfor_mb.
    Loopfor_mb:           //Loop for number of columns of B, mb.
	R2.L = W[I1++];   //RL2 fetches the data from matrix B, one by one.
	I0 = B0;          //I0 points to matrix A.
	I2 = I3;          //I2 points to temporary 32 bit buffer.
	lsetup(Lna_strt, Lna_end) LC0 = P0;   //Loop for number of rows of matrix A
    Lna_strt:
	lsetup(Lma_strt, Lma_end) LC1 = P1;   //Loop for number of columns of matrix A
    Lma_strt:
	R3.L = W[I0++];       //Load RL3 with data from matrix A
	R6 = R2.L * R3.L (IS) || R4 = [I2];
			      //RL2 and RL3 are multiplied and the result
			      //    is stored in 32 bit register R6
			      //Load R4 with previous data from buffer
	R6 = R6 >>> 15;
	R6 = R6 + R4 (NS);    //R6 is added to R4.
    Lma_end:[I2++] = R6;      //32 bit buffer stores the temporary result.
    Lna_end: I2 += M2;    //Temp buffer is incremented by mb-1.
	I3 += 4;  
	R5 += -1;
	CC = R5 == 0;     //Loop termination for Loopfor_mb.
	If !CC Jump Loopfor_mb (BP);
	I3 += M0;
	R0 += -1;
	CC = R0 == 0;
	If !CC Jump Loopfor_nb (BP);  //Loop termination for Loopfor_nb.

/***************************************************************************************/

/*
* In this section the 32 bit result from above section is saturated, if required and 
* copied to 16 bit output array. 
*/

	I3 = B3;              //Pointer to temp buffer.

	R5.H = 0;
	R5.L = 0x7fff;       // R5 = 0x00007fff. In fract it is +1. 
	R6 = -R5;            // R6 = 0xffff8000 In fract it is -1.
 
	lsetup (Copy_strt, Copy_end) LC0 = P4;  //Loop is set for nc*mc.
    Copy_strt:R4 = [I3++];  //32 bit data is read from temp buffer.
	CC = R5 <= R4;      //If data value is more than 32767 make it 32767.
	if CC R4 = R5;
	CC = R4 <= R6;      // If data value is less than -32768 make it -32768.
	if CC R4 = R6;      //otherwise leave it as such.
    Copy_end:W[P2++P5] = R4.L;  //Copy the temp buffer data to output array.

/***************************************************************************************/
	P5 = P4 << 2;
	SP = SP + P5;
    Terminate:
	
	(R7:4, P5:3) = [SP++];     //Pop up the saved registers.
	RTS;                       //Returns
.__conv2d_fr16.end:         
	
