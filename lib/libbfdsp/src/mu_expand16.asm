/*******************************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

********************************************************************************************
File Name      : mu_expand.asm
Function Name  : __mu_expand
Module Name    : TRANS Library
Description    : This function computes mu-law expansion of the given in put vector.
Operands       : R0- Address of input vector, R1-Address of putput vector, R2- Number of elements                
Registers Used : R3-R7,I0,I1,P0      
Cycle count    : 2,29,403 for -8192 to +8191 output data 
		 14(appx.) cycles for single output
Code Size      : 74 bytes
Modified on 27-04-2001 for removing the special case for input data (127) which is not required
**********************************************************************************************/

.text;
.global          __mu_expand;
.align 2;

__mu_expand:    [--SP]=(R7:4);     // PUSH R7-R4 ON STACK
		I0=R0;             // ADDRESS OF INPUT ARRAY
		I1=R1;             // ADDRESS OF OUTPUT ARRAY
		P0=R2;             // R2= NUMBER OF ELEMENTS
		L0=0;              // CLEAR L1 AND L0
		L1=0;
		R5.L=0xFF;       
		R7.L=0x0403;       // INITIALISE TO EXTRACT CHORD VALUE 
		R6.L=0x0F;      
		R1.L=W[I0++];      //  GET INPUT DATA
		LSETUP(EXP_START,EXP_END)LC0=P0;
EXP_START:      R1.L=R5.L-R1.L (NS);// SUBTRACT INPUT FROM 255       
		CC=BITTST(R1,7);   // CHECK FOR SIGN 
		R3=CC;             // STORE SIGN INFORMATION
		R2=EXTRACT(R1,R7.L) (Z);//GET CHORD VALUE
		R4=R1&R6;          // GET STEP VALUE
		R4=R4<<1 ||R1.L=W[I0++];//  GET INPUT DATA          
		R4+=33;            // ADD 33 TO CHORD
		R4<<=R2;           // SHIFT STEP VALUE BY CHORD TIMES 
		R4+=-33;           // SUBTRACT 33 FROM CHORD VALUE
		R0=R4;             // STORE THE RESULT IN RO
CHK_SIGN:       CC=R3==0;          // CHECK FOR SIGN 
		R2=-R0;            // NEGATE THE RESULT
		IF !CC R0=R2;
EXP_END:        W[I1++]=R0.L;      // STORE THE RESULT
		(R7:4)=[SP++];     // POP R7-R4 FROM STACK
		RTS;
.__mu_expand.end:
