/* generate a sampled sine wave for testing */

#include <math.h>
#include <stdio.h>

#define AMP    2048
#define PERIOD 6

int main() {
	int i;
	float sam;
	float pi = 4*atan(1.0);

	printf("pi = %f\n", pi);
	for(i=0; i<2*PERIOD; i++) {
		sam = AMP*cos(2.0*pi*(float)i/(float)PERIOD);
		printf("%d, ", (int)sam);
	}
	printf("\n");

	return 0;
}
