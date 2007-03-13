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
=   $Revision: 1.2 $
=   $Date: 2007/03/12 00:00:00 $
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
#include <matrix.h>

//-------------------------------------------------------------------------------------------

// Floating point 3x3 matrices
float A3[3][3] =
	   {{  -4096,    5     ,  40  },
	   	{     10,  -20     ,  30  },
	   	{     30,    2.0625,  12.5}};

float B3[3] =
	   {    3100.5,  6.0625,   1};

float Res3[3];
// Fractional 3x3 matrices
fract32  AFrac3[3][3];
fract32  BFrac3[3];
fract32  ResFrac3[3];

// Floating point 4x4 matrices
float A4[4][4] =
	   {{    5.0625,    0,  40,  20},
	   	{  -10,  -22,  30,  10},
	   	{   3.5,  20,  2048,  70},
	    {     0, -30,  20,  20}};

float B4[4] =
	   {     50.0625,  60,  2048,  13.75};

float Res4[4];
// Fractional 4x4 matrices
fract32  AFrac4[4][4];
fract32  BFrac4[4];
fract32  ResFrac4[4];

//-------------------------------------------------------------------------------------------

main () {
    int i, j;
    #ifdef BMK
	unsigned long long C_Start=0, C_Stop=0;
#endif
 	  printf("Test single multiplication of fract24_8\n");
	  printf("0xFFFFFFF0 * 0xFFFFFFF0 = 0x00000001 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0xFFFFFFF0)); // -1/16 * -1/16 = 1/256
	  printf("0x00000100 * 0x00000100 = 0x00000100 result=0x%0.8x\n", fract24_8mul_asm(0x00000100, 0x00000100)); //     1 *     1 = 1
	  printf("0x00000010 * 0x00000010 = 0x00000001 result=0x%0.8x\n", fract24_8mul_asm(0x00000010, 0x00000010));
	  printf("0x00000010 * 0x00010000 = 0x00001000 result=0x%0.8x\n", fract24_8mul_asm(0x00000010, 0x00010000));
	  printf("0x00010000 * 0x00000010 = 0x00001000 result=0x%0.8x\n", fract24_8mul_asm(0x00010000, 0x00000010));
	  printf("0x00010000 * 0x00010000 = 0x01000000 result=0x%0.8x\n", fract24_8mul_asm(0x00010000, 0x00010000));
 	  printf("0xFFFFFFF0 * 0x00000010 = 0xFFFFFFFF result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0x00000010));
 	  printf("0x00000010 * 0xFFFFFFF0 = 0xFFFFFFFF result=0x%0.8x\n", fract24_8mul_asm(0x00000010, 0xFFFFFFF0));
	  printf("0xFFFFFFF0 * 0xFFFFFFF0 = 0x00000001 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0xFFFFFFF0));
	  printf("0xFFFFFFF0 * 0x10000000 = 0xFF000000 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0x10000000));
	  printf("0xFFFFFF00 * 0x00000010 = 0xFFFFFFF0 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFF00, 0x00000010));
	  printf("0x00000020 * 0x00000020 = 0x00000004 result=0x%0.8x\n", fract24_8mul_asm(0x00000020, 0x00000020));
	  printf("0x00000008 * 0x00000008 = 0x00000000 result=0x%0.8x\n", fract24_8mul_asm(0x00000008, 0x00000008));
      printf("0xFFFFFF00 * 0x00000020 = 0xFFFFFFE0 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFF00, 0x00000020));
	  printf("0x00020000 * 0x00020000 = 0x04000000 result=0x%0.8x\n", fract24_8mul_asm(0x00020000, 0x00020000));
	  printf("\n\n");

	  printf("Test matrix*vector multiplication of fract24_8\n");
	// 3x3 copy 3x3 matrix and vector from float32 to fract 24.8
    for(i=0;i < 3 ; i++ ) {
        BFrac3[i] = floattofr32(B3[i]/(pow( (float)2,(float) (31-8) ))); // 32bit
		for(j=0; j < 3;j++) {
		    AFrac3[i][j] = floattofr32(A3[i][j]/(pow( (float)2,(float) (31-8) )));
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
    PlotVector3x1Frac32(ResFrac3, 31-8); // -> 24.8
	printf("\n\n");

    printf("Test optimized matrix*vector multiplication of fract24_8\n");
    ResFrac3[0]=0; ResFrac3[1]=0; ResFrac3[2]=0;
#ifdef BMK
	_GET_CYCLE_COUNT(C_Start);
#endif
    MatrixMultVec3x1Frac24_8(AFrac3, BFrac3, ResFrac3);
#ifdef BMK
	_GET_CYCLE_COUNT(C_Stop);
	printf("3x1 Fract Opt Func multiply Cycles    : %d\n", C_Stop-C_Start);
#endif
	printf("Fract Opt Func result\n");
    PlotVector3x1Frac32(ResFrac3, 31-8); // -> 24.8

//-------------------------------------------------------------------------------------------
	// 4x4 verification
	for(i=0;i < 4 ; i++ ) {
	    BFrac4[i] = floattofr32(B4[i]/(pow( (float)2,(float) (31-8) ))); // normal fract32 = 1.31 -> 28.4
		for(j=0; j < 4;j++) {
		    AFrac4[i][j] = floattofr32(A4[i][j]/(pow( (float)2,(float) (31-8) )));

		}
	}

#ifdef BMK
	_GET_CYCLE_COUNT(C_Start);
#endif
    MatrixMultVec4x1Frac32(AFrac4, BFrac4, ResFrac4);
#ifdef BMK
	_GET_CYCLE_COUNT(C_Stop);
	printf("4x1 Fract Opt multiply Cycles    : %d\n", C_Stop-C_Start);
	_GET_CYCLE_COUNT(C_Start);
#endif
	printf("Fract Opt result\n");
    PlotVector4x1Frac32(ResFrac4, 31-8); // -> 24.8
    printf("\n");

#ifdef BMK
	_GET_CYCLE_COUNT(C_Start);
#endif
	ResFrac4[0]=0; ResFrac4[1]=0; ResFrac4[2]=0; ResFrac4[3]=0;
    MatrixMultVec4x1Frac24_8(AFrac4, BFrac4, ResFrac4);
#ifdef BMK
	_GET_CYCLE_COUNT(C_Stop);
	printf("4x1 Fract Opt multiply Cycles    : %d\n", C_Stop-C_Start);
	_GET_CYCLE_COUNT(C_Start);
#endif
	printf("Fract Opt result\n");
    PlotVector4x1Frac32(ResFrac4, 31-8); // -> 24.8
    printf("\n");

}

//-------------------------------------------------------------------------------------------
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
=   $Revision: 1.1 $
=   $Date: 2007/03/07 00:00:00 $
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

main () {
    int i, j;
    #ifdef BMK
	unsigned long long C_Start=0, C_Stop=0;
	#endif
	  printf("Test single multiplication of fract24_8\n");
	  printf("0xFFFFFFF0 * 0xFFFFFFF0 = 0x00000001 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0xFFFFFFF0)); // -1/16 * -1/16 = 1/256
	  printf("0x00000100 * 0x00000100 = 0x00000100 result=0x%0.8x\n", fract24_8mul_asm(0x00000100, 0x00000100)); //     1 *     1 = 1
	  printf("0x00000010 * 0x00000010 = 0x00000001 result=0x%0.8x\n", fract24_8mul_asm(0x00000010, 0x00000010));
	  printf("0x00000010 * 0x00010000 = 0x00001000 result=0x%0.8x\n", fract24_8mul_asm(0x00000010, 0x00010000));
	  printf("0x00010000 * 0x00000010 = 0x00001000 result=0x%0.8x\n", fract24_8mul_asm(0x00010000, 0x00000010));
	  printf("0x00010000 * 0x00010000 = 0x01000000 result=0x%0.8x\n", fract24_8mul_asm(0x00010000, 0x00010000));
 	  printf("0xFFFFFFF0 * 0x00000010 = 0xFFFFFFFF result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0x00000010));
 	  printf("0x00000010 * 0xFFFFFFF0 = 0xFFFFFFFF result=0x%0.8x\n", fract24_8mul_asm(0x00000010, 0xFFFFFFF0));
	  printf("0xFFFFFFF0 * 0xFFFFFFF0 = 0x00000001 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0xFFFFFFF0));
	  printf("0xFFFFFFF0 * 0x10000000 = 0xFF000000 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFFF0, 0x10000000));
	  printf("0xFFFFFF00 * 0x00000010 = 0xFFFFFFF0 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFF00, 0x00000010));
	  printf("0x00000020 * 0x00000020 = 0x00000004 result=0x%0.8x\n", fract24_8mul_asm(0x00000020, 0x00000020));
	  printf("0x00000008 * 0x00000008 = 0x00000000 result=0x%0.8x\n", fract24_8mul_asm(0x00000008, 0x00000008));
      printf("0xFFFFFF00 * 0x00000020 = 0xFFFFFFE0 result=0x%0.8x\n", fract24_8mul_asm(0xFFFFFF00, 0x00000020));
	  printf("0x00020000 * 0x00020000 = 0x04000000 result=0x%0.8x\n", fract24_8mul_asm(0x00020000, 0x00020000));
	  printf("\n\n");
	  
	  printf("Test matrix*vector multiplication of fract24_8\n");
	// 3x3 copy 3x3 matrix and vector from float32 to fract 24.8
    for(i=0;i < Dim3 ; i++ ) {
        BFrac3[i] = floattofr32(B3[i]/(pow( (float)2,(float) (31-8) ))); // 32bit
		for(j=0; j < Dim3;j++) {
		    AFrac3[i][j] = floattofr32(A3[i][j]/(pow( (float)2,(float) (31-8) )));		    
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
    PlotVector3x1Frac32(ResFrac3, 31-4); // -> 24.8
	printf("\n\n");
    
    printf("Test optimized matrix*vector multiplication of fract24_8\n");
    ResFrac3[0]=0; ResFrac3[1]=0; ResFrac3[2]=0;
#ifdef BMK 
	_GET_CYCLE_COUNT(C_Start);
#endif
    MatrixMultVec3x1Frac24_8(AFrac3, BFrac3, ResFrac3);
#ifdef BMK	
	_GET_CYCLE_COUNT(C_Stop);
	printf("3x1 Fract Opt Func multiply Cycles    : %d\n", C_Stop-C_Start);	
#endif
	printf("Fract Opt Func result\n");
    PlotVector3x1Frac32(ResFrac3, 31-4); // -> 24.8
}
