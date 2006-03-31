/************************************************************************
 *
 * roundflti.asm : $Revision$
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

#if 0
   This program rounds given floating point number to a signed 
   integer( 32 bit).
     
   Registers used :
    R0 - Input/output parameter 
    R1 - R6 
#endif

.text;

.global __float32_to_int32;

.align 2;
__float32_to_int32:
   R1 = 0;          
   CC = R0 == R1;               // Check for zero input 
   IF CC JUMP  return_zero_int; // If true, return zero  
   [--SP] = (R7:4);             // Push registers R4-R7 

   R1 = R0<< 1;                 // Remove sign bit 
   R2 = R1>> 24;                // Bring exponent to LSB 
   R1 = 150;                    // 127 + 23 offset for float to int 1 
   R3 = R2-R1;                  // Unbiased exponent                   
   R2 = R0 << 9;                // Msb r2 will have mantissa 
   R4 = R2 >> 9;                // Position mantissa 
   R1.H = 0X0080;               // Implicit 1 for hidden bit  
   R1.L = 0;
   R5 = R4|R1;                  // Made explicit 
		
   R2.H = 0;
   R2.L = 0X10;                 // Load shift value 
   CC = R3 < 0 ;                // Check unbiased exponent 
   IF  CC  JUMP add_shift;           
   R4 = R3 - R2;                // Sub shift, if positive  
   JUMP set_frac_exp;       

add_shift:
   R4 = R3 + R2;                // Add shift, if negative 
set_frac_exp:
   R1.H = 0;                  
   R1.L = LSHIFT R0.L BY R4.L;  // Place LSW of  a number 
   R6 =  LSHIFT R5 BY R4.L;    
   R2 = R1|R6;                  // Place MSE of  a number 
   CC = BITTST(R2 ,15);         // Test 15th bit 
     
   IF CC JUMP round_num;        // if set, round the number 
				// else no rounding 
			
   R1 = 1;                      // Check for sign of input 
   R2 = R0 >>31;                // Extract sign bit  
   CC = R2 == R1;     
   IF CC JUMP put_sign;         // If negative, negate the result  
   R0 = ASHIFT R5 BY R3.L (S);  // Shift mantissa by exponent 
   JUMP COMM_RET;               // Saturate for maximum positive 
put_sign:  
   R0= ASHIFT R5 BY R3.L;       // Shift mantissa by exponent 
   R0= -R0;
   JUMP COMM_RET;

round_num:
   R1 = 1;                      // Check for sign of input 
   R2 = R0 >>31;                // Extract sign bit  
   CC = R2 == R1;    
   IF CC JUMP sign1;            // If negative, negate the result  
   R0 = ASHIFT R5 BY R3.L (S);  // Shift mantissa by exponent 
   R0 = R0 +|+ R1 (S);          // round the number    
   JUMP COMM_RET;               // Saturate for maximum positive 

sign1: 
   R0 =ASHIFT R5 BY R3.L;       // Shift mantissa by exponent 
   R3 = R0 +|+ R1 (S);          // Saturate for maximum negative  
   R0 = -R3;                    // Negate the number  
   JUMP COMM_RET;

COMM_RET:
   (R7:4) = [SP++];             // Pop registers R4-R7 

return_zero_int:                // If we jump here R0==0
   RTS;   

   .__float32_to_int32.end:

// end of file
