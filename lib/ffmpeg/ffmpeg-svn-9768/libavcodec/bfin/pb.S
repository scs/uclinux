
#include "config_bfin.h"

//#define mL1 mL3
DEFUN (put_bits, mL1, (PutBitContext *s, int n, unsigned int value)):
	P1 = R0;
	[--sp] = ( r7:6 );

	R6 = [P1+4];   // bit_left
	cc =R6<=R1;
	R3 = [P1];     // bit_buf
	if cc jump 0f;

//        bit_buf = (bit_buf<<n) | value;
//        bit_left-=n;

	r3 = lshift r3 by r1.l;
	R2 = R2 | R3;
	R0 = R6 - R1 (NS) ||	[P1] = R2;  // bit_buf = expr
	[P1+4] = R0;                        // bit_left

	( r7:6 ) = [sp++];
	rts;

0:

//        bit_buf<<=bit_left;
//        bit_buf |= value >> (n - bit_left);

	R0 = R6 - R1 (NS) || P2 = [P1+12];  // R0 = R1 - R6, p2 = buf_ptr
	R7 = lshift r2 by R0.l;
	R3 = lshift r3 by r6.l;
	R3 = R3 | R7;


//            s->buf_ptr[0] = bit_buf >> 24;
//            s->buf_ptr[1] = bit_buf >> 16;
//            s->buf_ptr[2] = bit_buf >>  8;
//            s->buf_ptr[3] = bit_buf      ;


// recognize that we are advancing the pointer
	R0 = R3 >> 24 ||        [P1] = R2; // bit_buf = value
	R0 = R3 >> 16 || 	B [P2++] = R0;
	R0 = R3 >> 8  ||  	B [P2++] = R0;
 	B [P2++] = R0;
 	

//        s->buf_ptr+=4;
//        bit_left+=32 - n;
//        bit_buf = value;

	R0 = R6 - R1 (NS) || B [P2++] = R3;
	R0 += 32;

//    s->bit_buf = bit_buf;
//    s->bit_left = bit_left;

	[P1+12] = P2;
	[P1+4]  = R0;
	( r7:6 ) = [sp++];

	rts;
DEFUN_END(put_bits)

