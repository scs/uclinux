
#include <stdio.h>
#include "math.h"

int main()
{
	float f;
	fract16 fr16 = 0x0;

	f = atanf(1.0);
	printf("atanf(1.0): %f\n",f);
	
	fr16 = atan_fr16(0.1);
	printf("atan_fr16(0.1): 0x%hx\n", fr16);

	f = floorf(1.5);
	printf("floorf(1.5): %f\n", f);
		
	f = fabsf(-5.1);
	printf("fabsf(-5.1): %f\n", f);

	printf("Finished\n");
	return 0;
}

