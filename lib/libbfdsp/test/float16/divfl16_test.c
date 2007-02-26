
/* Test the all_fl16() function.
 * Copyrigt 2007 (C) Analog Devices.
 * 
 * float16 is a 32-bit type. Exponent is low-half.
 * Mantissa is high half:
 * s mmm mmmm mmmm mmmm s eee eeee eeee eeee
 * Exponent is unbiased, and there is no hidden bit;
 * numbers are normalised to 0.x, not 1.x
 */

#include <stdio.h>
#include "float16.h"

int main(){
	fract16 a = 0x1, /* 2^(-15)*/ 
		b = 0x2; /* 2^(-14)*/

	float16 a16 = 0,b16 = 0,c16 = 0;
	
	printf("fract16 a: 0x%x, b: 0x%x\n", a, b);	
	
	/* Normalize */
	a16 = fr16_to_fl16(a);
	b16 = fr16_to_fl16(b);
	c16 = div_fl16(a16,b16);

	printf("float16 a16: 0x%lx / %f, b16: 0x%lx / %f\n", 
			a16, fl16_to_fl(a16), b16, fl16_to_fl(b16));	
	printf("\ndiv_fl16(a16, b16): Result is 0x%lx / %f\n",c16, fl16_to_fl(c16));
	
	return 0;
}
