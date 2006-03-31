/******************************************************************************
  Copyright(c) 2000-2004 Analog Devices Inc. IPDC BANGALORE, India. 

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 ******************************************************************************
  File name   :  sqrt_fr16.asm 
 
  Module name : fractional square root

  Label name  : __sqrt_fr16

  Description :   This program finds squre root of fractional input no.

  Registers used :
  Operand in  R0
  R0 - fractional input no.
  Other registers used
  R1-R3,R7,P0,P1,P2,LC0
 
  Special case :
  If input value is -ve then it returns zero.

  CYCLE COUNT    : 10            N <= 0
		 : 33 + 8*X      for other N
  'N' - INPUT VALUE IN FRACTIONAL FORMAT
   X  = CEIL( LOG4 (0x2000/N) )

  CODE SIZE      : 116 BYTES
  
  DATE           : 26-02-01
**************************************************************/

.section .rodata;
 .align 2;
 .sqrtcoef0:
 .short 0x2D41
 .short 0xD2CE
 .short 0xE7E8
 .short 0xF848
 .short 0xAC7C
 .sqrtcoef1:
 .short 0x2D42
 .short 0x2D31
 .short 0xEA5D
 .short 0x1021
 .short 0xF89E


.text;
.global __sqrt_fr16;
.align 2;

__sqrt_fr16:
	    CC = R0 <= 0;                     // CHECK  FOR R0 <= 0             
	    IF CC JUMP LOOP1;                 // IF TRUE ,BRANCH TO LOOP1 
	    [--SP] = R7;                      // PUSH R7 TO STACK  
	    P1.L = .sqrtcoef0;                // POINTER TO ARRAY OF COEFFICIENT 0
	    P1.H = .sqrtcoef0;
	    P2.L = .sqrtcoef1;                // POINTER TO ARRAY OF COEFFICIENT 1 
	    P2.H = .sqrtcoef1;
	    R1 = 0X4000;
	    R2 = 1;                           
	    R3 = 0X2000;                      // INITIALISE R3 = 0X2000 
AGAIN:      CC = R0 < R3;                     // WHILE R0 < 0X2000 DO 
	    IF !CC JUMP LOOP2;                // IF R0 > 0X2000, BRANCH LOOP2 LOCATION 
	    R0 <<= 2;                         // MULTIPLY 4 
	    R2 += -1;                         // DIVIDE BY 2 LATER 
	    JUMP AGAIN;                       // JUMP TO AGAIN LOCATION

LOOP2:      R0 = R0 - R1;                     // R0 = R0 - 0X4000 
	    CC = R0 < 0;                      // IF R0 < 0
	    IF CC P2 = P1;                    // IF TRUE, USE COEFFICIENT 0
	    R3 = -R0;                         
	    IF CC R0 = R3;                    // IF TRUE, NEGATE RESULT

	    P0 = 2;                           // LOOP COUNTER
	    R3 = PACK(R0.H,R0.L) || R7 = W[P2++] (Z);           
					      // SAVE RO IN R3, FETCH FIRST COEFFICIENT
	    R7 <<= 16;                        // ARRANGE IN 32 BIT FORMAT
	    A1 = R7 || R7 = W[P2++] (Z);          // INITIALISE A1 WITH FIRST COEFFICIENT
					      // GET NEXT COEFFICIENT
	    LSETUP(START,SEND) LC0 = P0;      // SET A LOOP FOR LOOP COUNTER VALUE = 2
START:      R0.H = R0.L * R3.L;               // CALCULATES EVEN POWERS OF X AND TAKES NEXT COEFFICIENT
	    A1 += R3.L * R7.L || R7 = W[P2++] (Z);// 
	    R3.L = R0.L * R0.H;               // CALCULATES ODD POWERS OF X AND TAKES NEXT COEFFICIENT
SEND:       R1 = (A1 += R0.H * R7.L) || R7 = W[P2++] (Z);
     
	    R0 = 16;                          // INITIALISE R0 = 16 
	    R0 = R2 - R0;                     // R0 = R2 - 16 
	    R0 = ASHIFT R1 BY R0.L;           // SAVE IN FRACT16  
	    R7 = [SP++];                      // POP R7
	    RTS;

LOOP1:      R0 = 0;                           // RETURN 0 

	    RTS;    
.__sqrt_fr16.end:
