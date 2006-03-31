/*****************************************************************
    Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *****************************************************************

    File name   :   cvecdot_fr16.asm
    Module name :   Complex vector dot product
    Label name  :   __cvecdot_fr16
    Description :   This program computes the dot product of two 16 bit vectors.

    Registers used   :

    R0 - Starting address of the 16 bits input vector
    R1 - Starting address of the 16 bits input vector
    R2 - No. of elements in the vector                      (32 bits)

    Other registers used:
    R3, I0 & I1

    Note            :   The two input vectors have to be declared in two
			different data memory banks to avoid data bank
			collision.

    Cycle count     :   64 cycles   (Vector length - 25)

    Code size       :   46 bytes

 *******************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.align 2;
.global __cvecdot_fr16;
__cvecdot_fr16:

	I0 = R0;                            // Store the address of the 1st input vector
	I1 = R1;                            // Store the address of the 2nd input vector
	P0 = R2;                            // Set loop counter
	R0 = 0;                             // Return zero if vector length is zero
	CC = R2 <= 0;                       // Check if the the vector length is negative or zero
	IF CC JUMP FINISH;                  // Terminate if the vector length is zero

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		NOP;
		NOP;
		NOP;
#endif

#if defined(__WORKAROUND_BF532_ANOMALY38__)

       /* Start of BF532 Anomaly#38 Safe Code */

	A1 = A0 = 0 || R1 = [I0++];
	LSETUP(vd_start, vd_end) LC0 = P0;
vd_start:   R3 = [I1++];
	    A1+=R1.H*R3.L, A0+=R1.L*R3.L;
vd_end:     R0.H = (A1+=R1.L*R3.H), R0.L = (A0-=R1.H*R3.H) || R1 = [I0++];

#else  /* End of BF532 Anomaly#38 Safe Code */

	A1 = A0 = 0 || R1 = [I0++] || R3 = [I1++];  // Load the real and imaginary parts of the 1st and 2nd input vectors
	LSETUP(vd_start, vd_end) LC0 = P0;
vd_start:   A1+=R1.H*R3.L, A0+=R1.L*R3.L;           // (C1 + jC2) = ( A1[] +jA2[] ).( B1[] + jB2[] )
vd_end:     R0.H = (A1+=R1.L*R3.H), R0.L = (A0-=R1.H*R3.H) || R1 = [I0++] || R3 = [I1++];
						    // C1 = Sum( A1[i]*B1[i] - A2[i]*B2[i] )
#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

FINISH:
	RTS;                                // C2 = Sum( A1[i]*B2[i] + A2[i]*B1[i] )

.__cvecdot_fr16.end:
