/*	test_cfft.c
 *
 *	Example of the FFT routine from the Blackfin DSP library.
 *
 *	Compare results in the output buffer "out" to the
 * 	desired output (files "out_re.ans" and out_im.ans")
 *
 *	See the documentation for more info on the DSP routines
 *
 */

#include <fract.h>
#include <complex.h>
#include <filter.h>
#include <stdio.h>

#define VEC_SIZE 8192	// length of the input vector

// input
complex_fract16 in[VEC_SIZE] = 
{
	#include "in.dat"
};  

// temp storage
complex_fract16 t[VEC_SIZE];  

// output
complex_fract16 out[VEC_SIZE];

// twiddle factors
#define TWIDDLE_SIZE VEC_SIZE/2

complex_fract16 w[TWIDDLE_SIZE] =
{
	#include "twiddles.dat"
};

int main(void) {
	int i = 0;
	FILE * outf = NULL;
	
	outf = fopen("./cfft_out.dat", "w");
	if (outf == NULL)
	{
		perror("fopen() error");
		exit(-1);
	}
	
	// call to the DSP library
	cfft_fr16(in, t, out, w, 2*TWIDDLE_SIZE/VEC_SIZE, VEC_SIZE, 1, 2);
	
	for (i = 0; i < VEC_SIZE; i++)
		fprintf(outf, "0x%hx\n0x%hx\n", out[i].re, out[i].im );
	fclose(outf);
	printf("Finished\n");
	
	return 0;
}
