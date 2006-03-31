
#include <stdio.h>
#include "stats.h"

int main()
{
	float in_f[6] = {-2, -1, 0, 1, 2, 3}, f;

	fract16 in_fr16[6] = {-0.2, -0.1, 0, 0.1, 0.2, 0.3}, fr16;

	printf("rmsf:");
	f = rmsf(in_f, 6);
	printf("%f\n", f);
	
	printf("rms_fr16\n");
	fr16 = rms_fr16(in_fr16, 6);
		
	
	printf("meanf:");
	f = meanf(in_f, 6);
	printf("%f\n", f);
	
	printf("mean_fr16\n");
	fr16 = mean_fr16(in_fr16, 6);

	printf("Finished\n");
	return 0;
}

