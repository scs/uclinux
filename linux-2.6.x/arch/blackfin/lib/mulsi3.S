/* libgcc1 routines for Blackfin BF533 
 *  Copyright (c) 2003-2004 LG Soft India.
 */	

	.text
	.globl	__mulsi3
__mulsi3:

	R3 = [SP+12];
	[--SP] = ( R7:5);
	A1 = R0.L*R2.L (FU); 
        R5 = A1.W;
        R5 = R5 << 16;
        R7 = R5 >> 16;
        A1 = A1 >> 16; 
        A1 += R0.H * R2.L (FU);
        A1 += R0.L * R2.H (FU);
        R5 = A1.W;
        R5 = R5 << 16;
        A1 = A1 >> 16;
        R6 = R7 | R5;
        A1 += R3.L * R0.L (FU);
        A1 += R2.L * R1.L (FU);
        A1 += R0.H * R2.H (FU);
        R5 = A1.W;
        R5 = R5 << 16;
        R7 = R5 >> 16;
        A1 = A1 >> 16; 
        A1 += R1.H * R2.L (M,IS);
        A1 += R3.H * R0.L (M,IS);
        A1 += R1.L * R2.H (IS);
        A1 += R3.L * R0.H (IS);
        R5 = A1.W;
        R5 = R5 << 16;
        R1 = R7 | R5; 
        R0 = R6;
	( R7:5) = [SP++];
	RTS;






