/*============================================================================
=
=   Copyright (c) 2007 Analog Devices
=
= This file is subject to the terms and conditions of the GNU Library General
= Public License. See the file "COPYING.LIB" in the main directory of this
= archive for more details.
=
==============================================================================
=
=   $RCSfile:  Verification.c,v $
=   $Revision: 1.0 $
=   $Date: 2007/03/05 00:00:00 $
=
=   Project:    Graphics Optimization for Navigation
=   Title:      Verification.c
=   Author(s):  Matthijs Paffen
=   Revised by:
=
=   Description: Verification purposes only
=
============================================================================*/

//#define BMK


#ifdef BMK
 #include <cycle_count_bf.h>
#endif
#include "MatrixMulVec.h"
#include "stdio.h"
#include "math.h"
#include "matrix.h"
#include "fract.h"

// Floating point 3x3 matrices
float A3[Dim3][Dim3] =
	   {{  -4096,    5,  40},
	   	{   10,  -20,  30},
	   	{   30,    2,  12.5}};

float B3[Dim3] =
	   {    3100.5,    6,  1};

float Res3[Dim3];
// Fractional 3x3 matrices	    
long  AFrac3[Dim3][Dim3];
long  BFrac3[Dim3];
long  ResFrac3[Dim3];

int main () {
    int i, j;
    #ifdef BMK
	unsigned long long C_Start=0, C_Stop=0;
	#endif
	  printf("Test single multiplication of fract28_4\n");
	  printf("0xFFFFFFF0 * 0xFFFFFFF0 = 0x00000010 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0xFFFFFFF0, 0xFFFFFFF0)); // should be 0xFFFFFF00
	  printf("0x00000010 * 0x00000010 = 0x00000010 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00000010, 0x00000010)); // should be 0x00020000	  
	  printf("0x00000010 * 0x00010000 = 0x00010000 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00000010, 0x00010000)); // should be 0x00020000	  
	  printf("0x00010000 * 0x00000010 = 0x00010000 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00010000, 0x00000010)); // should be 0x00020000
	  printf("0x00010000 * 0x00010000 = 0x10000000 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00010000, 0x00010000)); // should be 0x00020000
 	  printf("0xFFFFFFF0 * 0x00000010 = 0xFFFFFFF0 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0xFFFFFFF0, 0x00000010)); // should be 0xFFFFFF00
 	  printf("0x00000010 * 0xFFFFFFF0 = 0xFFFFFFF0 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00000010, 0xFFFFFFF0)); // should be 0xFFFFFF00
	  printf("0xFFFFFFF0 * 0xFFFFFFF0 = 0x00000010 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0xFFFFFFF0, 0xFFFFFFF0)); // should be 0xFFFFFF00
	  printf("0xFFFFFFF0 * 0x10000000 = 0xF0000000 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0xFFFFFFF0, 0x10000000)); // should be 0xF0000000
	  printf("0xFFFFFF00 * 0x00000010 = 0xFFFFFF00 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0xFFFFFF00, 0x00000010)); // should be 0xFFFFFF00
	  printf("0x00000020 * 0x00000020 = 0x00000040 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00000020, 0x00000020)); // should be 0x00000040
	  printf("0x00000008 * 0x00000008 = 0x00000004 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00000008, 0x00000008)); // should be 0x00000004
      printf("0xFFFFFF00 * 0x00000020 = 0xFFFFFE00 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0xFFFFFF00, 0x00000020)); // should be 0xFFFFFE00
	  printf("0x00020000 * 0x00020000 = 0x40000000 result=0x%.8x\n", (unsigned int)fract28_4mul_asm(0x00020000, 0x00020000));
	  printf("\n\n");
	  
	  printf("Test matrix*vector multiplication of fract28_4\n");
	// 3x3 copy 3x3 matrix and vector from float32 to fract 28.4
    for(i=0;i < Dim3 ; i++ ) {
        BFrac3[i] = floattofr32(B3[i]/(pow( (float)2,(float) (31-4) ))); // 32bit
		for(j=0; j < Dim3;j++) {
		    AFrac3[i][j] = floattofr32(A3[i][j]/(pow( (float)2,(float) (31-4) )));		    
		}
    }

#ifdef BMK 
	_GET_CYCLE_COUNT(C_Start);
#endif
    MatrixMultVec3x1Frac32(AFrac3, BFrac3, ResFrac3);
#ifdef BMK	
	_GET_CYCLE_COUNT(C_Stop);
	printf("3x1 Fract multiply Cycles    : %d\n", C_Stop-C_Start);	
#endif
	printf("Fract result\n");
    PlotVector3x1Frac32(ResFrac3, 31-4); // -> 28.4
	printf("\n\n");
    
    printf("Test optimized matrix*vector multiplication of fract28_4\n");
    ResFrac3[0]=0; ResFrac3[1]=0; ResFrac3[2]=0;
#ifdef BMK 
	_GET_CYCLE_COUNT(C_Start);
#endif
    MatrixMultVec3x1Frac28_4(AFrac3, BFrac3, ResFrac3);
#ifdef BMK	
	_GET_CYCLE_COUNT(C_Stop);
	printf("3x1 Fract Opt Func multiply Cycles    : %d\n", C_Stop-C_Start);	
#endif
	printf("Fract Opt Func result\n");
    PlotVector3x1Frac32(ResFrac3, 31-4); // -> 28.4

  return 0;
}
