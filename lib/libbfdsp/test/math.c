
#include <stdio.h>
#include "math_bf.h"

int main()
{
	fract16 fr16 = 0x0;
	
	fr16 = atan_fr16(0.1);
	printf("atan_fr16(0.1): 0x%hx\n", fr16);

	printf("Finished\n");
	return 0;
}

