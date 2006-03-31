
#include <stdio.h>
#include "filter.h"

int convolve_fr16_tst()
{
	fract16 cin1[] = {-0.1, 0, 0.1, 0.2};
	int clen1 = 4;
	fract16 cin2[] = {-0.2, 0, 0.2};
	int clen2 = 3;
	fract16 cout[6]; /* clen1 + clen2 - 1 */
	
	printf("convolve_fr16\n");
	convolve_fr16(cin1, clen1, cin2, clen2, cout);

	return 0;	
}

int main()
{
	convolve_fr16_tst();

	printf("Finished\n");
	return 0;
}

