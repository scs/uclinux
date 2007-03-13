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
=   $RCSfile:  MatrixMulVecFract.c,v $
=   $Revision: 1.2 $
=   $Date: 2007/03/12 00:00:00 $
=
=   Project:    libbfdsp
=   Title:      MatrixMulVecFract.c
=   Author(s):  Matthijs Paffen
=   Revised by:
=
=   Description: Verification purposes only
=
============================================================================*/

#include "MatrixMulVec.h"
#include "math.h"
#include <stdio.h>
#include "matrix.h"

fract32 FloatToFrac24_8(float A) {

    A = A * pow((float)2,(float)8);
    return (short)A;
}

fract32 floattofr32(float A) {
    A = A * pow((float)2,(float)31);
    return (int)A;
}

double Frac24_8ToFloat(fract32 A) {
    long long B = 0;
    double C=0;
    int i;
    for(i = 0 ; i < 8 ; i++)
        C+= (float)((A>>i)&0x1)*pow((float)2,(float)(i-8));
    for(i = 8 ; i < 31 ; i++)
        B+=((A>>i)&0x1)* (1<<(i-8));
        B-= ((A>>31)&0x1) * 8388608;

    printf("%d", B);
    printf("+%0.8f ", C);
    /*
    31  -8388608    FFF8000000
    30  4194304     4000000
    29  2097152     2000000
    28  1048576     1000000
    27  524288      800000
    26  262144      400000
    25  131072      200000
    24  65536       100000
    23  32768       80000
    22  16384       40000
    21  8192        20000
    20  4096        10000
    19  2048        8000
    18  1024        4000
    17  512         2000
    16  256         1000
    15  128         800
    14  64          400
    13  32          200
    12  16          100
    11  8           80
    10  4           40
    9   2           20
    8   1           10
    7   0,5         8
    6   0,25        4
    5   0,125       2
    4   0,0625      1
    3   0,03125     0
    2   0,015625    0
    1   0,0078125   0
    0   0,00390625  0
    */

    return (double)B+C;
}

void PlotMatrix3x3Frac32(fract32 A[][3], int power) {
    int i, j;

    for( i=0 ; i < 3 ;i++ ) {
        for( j=0 ; j<3 ; j++ ) Frac24_8ToFloat(A[i][j]);
        printf("\n");
    }
}

void PlotMatrix4x4Frac32(fract32 A[][4], int power) {
    int i, j;

    for( i=0 ; i < 4 ;i++ ) {
        for( j=0 ; j<4 ; j++ ) Frac24_8ToFloat(A[i][j]);
        printf("\n");
    }
}

void PlotVector3x1Frac32(fract32 A[], int power) {
    int j;
        for( j=0 ; j<3 ; j++ ) Frac24_8ToFloat(A[j]);
        printf("\n");
}

void PlotVector4x1Frac32(fract32 A[], int power) {
    int j;
        for( j=0 ; j<4 ; j++ ) Frac24_8ToFloat(A[j]);
        printf("\n");
}

void  MatrixMultVec3x1Frac32(fract32 A[][3], fract32 B[], fract32 Res[])
{
    int i, k;
    for (i = 0 ; i < 3 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < 3 ; k++) {Res[i] +=fract24_8mul_asm(A[i][k], B[k]);
            }
        }
}

void  MatrixMultVec4x1Frac32(fract32 A[][4], fract32 B[], fract32 Res[])
{
    int i, k;
    for (i = 0 ; i < 4 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < 4 ; k++) Res[i] += fract24_8mul_asm(A[i][k], B[k]);
        }
}
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
=   $RCSfile:  MatrixMulVecFract.c,v $
=   $Revision: 1.1 $
=   $Date: 2007/03/07 00:00:00 $
=
=   Project:    libbfdsp
=   Title:      MatrixMulVecFract.c
=   Author(s):  Matthijs Paffen
=   Revised by:
=
=   Description: Verification purposes only
=
============================================================================*/

#include "MatrixMulVec.h"
#include "math.h"
#include <stdio.h>
#include "matrix.h"

int FloatToFrac24_8(float A) {

    A = A * pow((float)2,(float)8);
    return (short)A;
}

int floattofr32(float A) {
    A = A * pow((float)2,(float)31);
    return (int)A;
}

// 28.4 Range -134217728 to +134217727,9 (LSB=0,0625=1/16)
// -1 = 0xFFFFFFF0
//  1 = 0x00000010


double Frac24_8ToFloat(int A) {
    long long B = 0;
    double C=0;
    int i;
    for(i = 0 ; i < 8 ; i++)
        C+= (float)((A>>i)&0x1)*pow((float)2,(float)(i-8));
    for(i = 8 ; i < 31 ; i++)
        B+=((A>>i)&0x1)* (1<<(i-8));
        B-= ((A>>31)&0x1) * 8388608;

    printf("%d", B);
    printf("+%0.8f ", C);
    /*
	31	-8388608	FFF8000000
	30	4194304		4000000
	29	2097152		2000000
	28	1048576		1000000
	27	524288		800000
	26	262144		400000
	25	131072		200000
	24	65536		100000
	23	32768		80000
	22	16384		40000
	21	8192		20000
	20	4096		10000
	19	2048		8000
	18	1024		4000
	17	512			2000
	16	256			1000
	15	128			800
	14	64			400
	13	32			200
	12	16			100
	11	8			80
	10	4			40
	9	2			20
	8	1			10
	7	0,5			8
	6	0,25		4
	5	0,125		2
	4	0,0625		1
	3	0,03125		0
	2	0,015625	0
	1	0,0078125	0
	0	0,00390625	0
    */

    return (double)B+C;
}

void PlotMatrix3x3Frac32(long A[][Dim3], int power) {
    int i, j;

    for( i=0 ; i < Dim3 ;i++ ) {
        for( j=0 ; j<Dim3 ; j++ ) Frac24_8ToFloat(A[i][j]);
        printf("\n");
    }
}

void PlotMatrix4x4Frac32(long A[][Dim4], int power) {
    int i, j;

    for( i=0 ; i < Dim4 ;i++ ) {
        for( j=0 ; j<Dim4 ; j++ ) Frac24_8ToFloat(A[i][j]);
        printf("\n");
    }
}

void PlotVector3x1Frac32(long A[], int power) {
    int j;
        for( j=0 ; j<Dim3 ; j++ ) Frac24_8ToFloat(A[j]);
        printf("\n");
}

void PlotVector4x1Frac32(long A[], int power) {
    int j;
        for( j=0 ; j<Dim4 ; j++ ) Frac24_8ToFloat(A[j]);
        printf("\n");
}

void  MatrixMultVec3x1Frac32(long A[][Dim3], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim3 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim3 ; k++) {Res[i] +=fract24_8mul_asm(A[i][k], B[k]);
            }
        }
}

void  MatrixMultVec4x1Frac32(long A[][Dim4], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim4 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim4 ; k++) Res[i] += fract24_8mul_asm(A[i][k], B[k]);
        }
}

void  MatrixMultVec3x1Frac32Opt(long A[][Dim3], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim3 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim3 ; k++) {Res[i] +=fract24_8mul_asm(A[i][k], B[k]);
            }
        }
}

void  MatrixMultVec4x1Frac32Opt(long A[][Dim4], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim4 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim4 ; k++) Res[i] += fract24_8mul_asm(A[i][k], B[k]);
        }
}
