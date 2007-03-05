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
=   $Revision: 1.0 $
=   $Date: 2007/03/05 00:00:00 $
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
#include "fract.h"

int FloatToFrac28_4(float A) {

    A = A * pow((float)2,(float)4);
    return (short)A;
}

int floattofr32(float A) {
    A = A * pow((float)2,(float)31);
    return (int)A;
}

// 28.4 Range -134217728 to +134217727,9 (LSB=0,0625=1/16)
// -1 = 0xFFFFFFF0
//  1 = 0x00000010


double Frac28_4ToFloat(int A) {
    long long B = 0;
    double C=0;
    int i;
    for(i = 0 ; i < 4 ; i++)
        C+= (float)((A>>i)&0x1)*pow((float)2,(float)(i-4));
    for(i = 4 ; i < 31 ; i++)
        B+=((A>>i)&0x1)* (1<<(i-4));
        B-= ((A>>31)&0x1) * 134217728;
    printf("%d", (unsigned int)B);
    printf("+%0.4f ", C);
    /*
    31  -134217728  FF80000000
    30  67108864    40000000
    29  33554432    20000000
    28  16777216    10000000
    27  8388608     8000000
    26  4194304     4000000
    25  2097152     2000000
    24  1048576     1000000
    23  524288      800000
    22  262144      400000
    21  131072      200000
    20  65536       100000
    19  32768       80000
    18  16384       40000
    17  8192        20000
    16  4096        10000
    15  2048        8000
    14  1024        4000
    13  512         2000
    12  256         1000
    11  128         800
    10  64          400
    9   32          200
    8   16          100
    7   8           80
    6   4           40
    5   2           20
    4   1           10
    3   0,5         8
    2   0,25        4
    1   0,125       2
    0   0,0625      1
    */

    return (double)B+C;
}

void PlotMatrix3x3Frac32(long A[][Dim3], int power) {
    int i, j;

    for( i=0 ; i < Dim3 ;i++ ) {
        for( j=0 ; j<Dim3 ; j++ ) Frac28_4ToFloat(A[i][j]);
        printf("\n");
    }
}

void PlotMatrix4x4Frac32(long A[][Dim4], int power) {
    int i, j;

    for( i=0 ; i < Dim4 ;i++ ) {
        for( j=0 ; j<Dim4 ; j++ ) Frac28_4ToFloat(A[i][j]);
        printf("\n");
    }
}

void PlotVector3x1Frac32(long A[], int power) {
    int j;
        for( j=0 ; j<Dim3 ; j++ ) Frac28_4ToFloat(A[j]);
        printf("\n");
}

void PlotVector4x1Frac32(long A[], int power) {
    int j;
        for( j=0 ; j<Dim4 ; j++ ) Frac28_4ToFloat(A[j]);
        printf("\n");
}

void  MatrixMultVec3x1Frac32(long A[][Dim3], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim3 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim3 ; k++) {Res[i] +=fract28_4mul_asm(A[i][k], B[k]);
            }
        }
}

void  MatrixMultVec4x1Frac32(long A[][Dim4], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim4 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim4 ; k++) Res[i] += fract28_4mul_asm(A[i][k], B[k]);
        }
}

void  MatrixMultVec3x1Frac32Opt(long A[][Dim3], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim3 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim3 ; k++) {Res[i] +=fract28_4mul_asm(A[i][k], B[k]);
            }
        }
}

void  MatrixMultVec4x1Frac32Opt(long A[][Dim4], long B[], long Res[])
{
    int i, k;
    for (i = 0 ; i < Dim4 ; i++) {
            Res[i] = 0;
            for (k = 0 ; k < Dim4 ; k++) Res[i] += fract28_4mul_asm(A[i][k], B[k]);
        }
}
