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
=   $RCSfile:  MatrixMulVec.h,v $
=   $Revision: 1.0 $
=   $Date: 2007/03/05 00:00:00 $
=
=   Project:    Graphics Optimization for Navigation
=   Title:      MatrixMulVec.h
=   Author(s):  Matthijs Paffen
=   Revised by:
=
=   Description: Verification purposes only
=
============================================================================*/

#define Dim3 3                // Define the matrix Dim3ension size
#define Dim4 4                // Define the matrix Dim3ension size

int FloatToFrac28_4(float A);
int floattofr32(float A);
double Frac28_4ToFloat(int A);
void PlotMatrix3x3Frac32(long A[][3], int pow);
void PlotMatrix4x4Frac32(long A[][4], int pow);
void PlotVector3x1Frac32(long A[], int power);
void PlotVector4x1Frac32(long A[], int power);

void  MatrixMultVec4x1Frac32(long A[][Dim4], long B[], long Res[]);
void  MatrixMultVec3x1Frac32(long A[][Dim3], long B[], long Res[]);
void  MatrixMultVec4x1Frac32Opt(long A[][Dim4], long B[], long Res[]);
void  MatrixMultVec3x1Frac32Opt(long A[][Dim3], long B[], long Res[]);
