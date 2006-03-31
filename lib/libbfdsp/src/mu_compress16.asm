/*******************************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

********************************************************************************************
File Name      : mu_compress.asm
Function Name  : __mu_compress
Module Name    : TRANS Library
Description    : This function computes mu-law compression of the given input vector.
Operands       : R0- Address of input vector, R1-Address of putput vector, R2- Number of elements                
Registers Used : R3-R7,I0-I2,P0-P2       
Cycle count    : 6672 for 256 output data
Code size      : 104 bytes
Modified on 27-04-2001 for removing the special case for data (8192) which is not required
********************************************************************************************/
#define CLIP 8158
#define BIAS 33

.section .rodata;
.align 8;
.chordcoef0:
.byte 0x00
.byte 0x00
.byte 0x01
.byte 0x01
.byte 0x02
.byte 0x02
.byte 0x02
.byte 0x02
.byte 0x03
.byte 0x03
.byte 0x03
.byte 0x03
.byte 0x03
.byte 0x03
.byte 0x03
.byte 0x03

.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04
.byte 0x04

.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05

.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05
.byte 0x05

.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06

.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06

.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06

.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06
.byte 0x06

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07
.byte 0x07

	  
.text;
.global          __mu_compress;
.align 2;

__mu_compress:      [--SP]=(R7:5);     // PUSH R7-R5 ON STACK
		    I0=R0;              // ADDRESS OF INPUT ARRAY
		    I1=R1;              // ADDRESS OF OUTPUT ARRAY
		    L0=0;
		    L1=0;               // CLEAR L0 AND L1 REGISTER
		    P2.L = .chordcoef0; 
		    P2.H = .chordcoef0; //POINTER TO ARRAY OF COEFFICIENT 2
		    I2=P2;              // STORE THE ADDRESS    
		    P0=R2;              // R2= NUMBER OF ELEMENTS
		    R5=0xff;            // INTIALISED TO 0X55
		    R0.L=W[I0++];       // GET INPUT DATA
		    R1=CLIP;            // GET MAXIMUM VALUE
		    LSETUP(COM_START,COM_END)LC0=P0;
COM_START:          CC=BITTST(R0,13);   // CHECK FOR SIGN
		    R3=CC;              // STORE SIGN INFORMATION
		    R2=-R0;
		    IF CC R0=R2;        // IF FALSE, BRANCH TO NO_NEGATE
		    R0.H=0;
		    CC=R0<R1;           // CHECK FOR MAX VALUE
		    IF !CC R0=R1;
		    R0+=33;              
		    R2=R0;              // DUPLICATE THE DATA
		    R2>>=5;             // SHIFT TO GET OFFSET FOR CHORD
		    P1=R2;              // STORE OFFSET VALUE
		    R1=CLIP;            // GET MAXIMUM VALUE
		    R2=0x0f;            // INITIALISED TO 0x0F
		    R3<<=7;             // TO KEEP SIGN BIT IN PROPER POSITION
		    P2=P2+P1;           // GET ADDRES OF CHORD
		    R6=B[P2](Z);            // GET CHORD VALUE
		    R7=R6;              // DUPLICATE CHORD VALUE
		    R7+=1;              // TO GET STEP VALUE
		    R0>>=R7;            
		    R0=R0&R2;           // AND WITH R6 TO GET STEP VALUE    
		    R6<<=4;             // TO KEEP CHORD IN PROPER POSITION
		    R6=R6|R3;           // OR WITH SIGN BIT
		    R0=R0|R6;           // OR WITH CHORD VALUE
		    P2=I2;              // LOAD BASE ADDRESS OF CHORD COEFFICIENT FOR NEXT ITERATION
		    R2.L=R5.L-R0.L (NS)||R0.L=W[I0++];// GET NEXT INPUT DATA, AND WITH 0x55 TO GET FINAL RESULT        
COM_END:            W[I1++]=R2.L;       // STORE THE RESULT IN OUTPUT ARRAY
		    (R7:5)=[SP++];      // POP R7-R5 FROM STACK
		    RTS;                    
.__mu_compress.end:

		    
		
