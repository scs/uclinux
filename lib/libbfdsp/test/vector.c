
#include <stdio.h>
#include "vector.h"

int main()
{
	complex_float a[] = {{0.1, 0.2}, {0.3, 0.4}};
	complex_float b[] = {{0.5, 0.6}, {0.7, 0.8}};
	int n = 2;

	float a_f[] = {0, 0.5, 1.5, 2.0};
	float b_f[] = {2.0, 1.5, 0.5, 0};
	float c_f[4];
	int n_f = 4;
	
	
	printf("cvecdotf\n");
	cvecdotf(a, b, n);

	// cvecdotd - not supported

	printf("vecvaddf\n");
	vecvaddf(a_f, b_f, c_f, n_f);
	
	printf("vecvsubf\n");
	vecvsubf(a_f, b_f, c_f, n_f);
	
	printf("vecvmltf\n");
	vecvmltf(a_f, b_f, c_f, n_f);
	
	printf("Finished\n");
	return 0;
}

