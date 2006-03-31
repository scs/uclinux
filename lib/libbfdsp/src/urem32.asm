/***************************************************************************
Copyright (c) 2000-2004 Analog Devices Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


****************************************************************************
  File name :  urem32.asm 
 
  This program computes 32 bit unsigned remainder.It calls udiv32 function 
  for quotient estimation.

  Registers used :
  Numerator/ Denominator in  R0 and  R1  respectively.
  R0      -  Returns remainder.
  R2-R7   
 
Special cases :
	    1)  If(numerator == 0) return 0 
	    2)  If(denominator ==0) return 0xFFFFFFFF
	    3)  If(numerator == denominator) return 0
	    4)  If(denominator == 1 ) return 0
	    5)  If(numerator < denominator) return numerator
	    
     BLACKFIN  hidden functions
     IPDC, Bangalore, 26 April 2000.
    
     Modified on 14th July 2000
     Modification include:
     Removed external declaration for ___udiv32 function calling.       

     Modified for new instruction set   
     and  tested using Dev13 toolset on    : 13 October 2000
     
****************************************************************************/

.text;
.align 2;

.global ___urem32;
.type ___urem32, STT_FUNC;
.extern ___udiv32;
.type ___udiv32, STT_FUNC;
___urem32 :

    CC=R0==0;
    IF CC JUMP RETURN_R0;       /* Return 0, if NR == 0 */
    CC= R1==0;
    IF CC JUMP RETURN_ZERO_VAL; /* Return 0, if DR == 0 */
    CC=R0==R1;             
    IF CC JUMP RETURN_ZERO_VAL; /* Return 0, if NR == DR */
    CC = R1 == 1;
    IF CC JUMP RETURN_ZERO_VAL; /* Return 0, if  DR == 1 */
    CC = R0<R1 (IU);
    IF CC JUMP RETURN_R0;       /* Return dividend (R0),IF NR<DR */

    [--SP] = (R7:6);        /* Push registers and */
    [--SP] = RETS;          /* Return address */
    R7 = R0;            /* Copy of R0 */   
    R6 = R1;
    SP += -12;          /* Should always provide this space */
    CALL.X ___udiv32;           /* Compute unsigned quotient using ___udiv32()*/
    SP += 12;
    R0 *= R6;           /* Quotient * divisor */
    R0 = R7 - R0;           /* Dividend - ( quotient *divisor) */
    RETS = [SP++];          /* Pop return address */
    (R7:6) = [SP++];        /* And registers */
    RTS;                /* Return remainder */
RETURN_ZERO_VAL:
    R0 = 0;
RETURN_R0:
    RTS;
.___urem32.end:
