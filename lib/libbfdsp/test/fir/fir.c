/*	fir.c
 *
 *	Example of the FIR routine from the Blackfin DSP library.
 *
 *  The default input data file is a sum of two sinusoids
 *  The default coefficients implement a LPF that filters out one of the sine terms
 *
 *	See the documentation for more info on the DSP routines
 *
 *	Load the workspace found in file "fir_533.vdw" or "fir_535.vdw" to see the input and output 
 *	of this FIR test.
 */
#include <stdio.h>
#include <fract.h>
#include <filter.h>

#define VEC_SIZE 256	// length of the input vector
#define NUM_TAPS 8	// number of filter coefficients

fract16 in[VEC_SIZE] = {
#include "in.dat"
};

fract16 coefs[NUM_TAPS] = {
#include "coefs.dat"
};

fract16 delay[NUM_TAPS];

fract16 out[VEC_SIZE + NUM_TAPS - 1];

fir_state_fr16 state;	// declare filter state

int main()
{
	int i = 0;
	FILE * outf = NULL;

	outf = fopen("fir_out.dat", "w");
	if (outf == NULL)
	{
		perror("fopen() error");
		exit(-1);
	}	

	fir_init(state, coefs, delay, NUM_TAPS, 1);	// initialize filter state  
	fir_fr16(in, out, VEC_SIZE, &state);	// apply the filter to the data
 
	for (i = 0; i < (VEC_SIZE + NUM_TAPS -1); i++)
		fprintf(outf, "0x%hx\n", out[i]);
	printf("Finished\n");
        return 0;
}
