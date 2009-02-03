/**************************************************************
 * C Benchmark code based on EDN June 5 1997                  *
 * for details look at:                                       *
 * http://www.edn.com/archives/1997/060597/12df_02.htm        *
 *                                                            *
 **************************************************************/

#include "edn.h"

/******************************************************
 *	Simple vector multiply                        *
 ******************************************************/

void vec_mpy1(short y[], const short x[], short scaler)
{
	int i;

	for (i = 0; i < 150; i++)
		y[i] += ((scaler * x[i]) >> 15);
}


/******************************************************
 *	Dot Product                                   *
 ******************************************************/
int mac(const short *a, const short *b, long int sqr, long int *sum)
{
	int i;
	int dotp = *sum;

	for (i = 0; i < 150; i++) {
		dotp += b[i] * a[i];
		sqr += b[i] * b[i];
	}

	*sum = dotp;
	return sqr;
}


/*****************************************************
*		FIR Filter		     *
*****************************************************/
void fir(const short array1[], const short coeff[], short output[])
{
	int i, j, sum;

	for (i = 0; i < N - ORDER; i++) {
		sum = 0;
		for (j = 0; j < ORDER; j++) {
			sum += array1[i + j] * coeff[j];
		}
		output[i] = sum >> 15;
	}
}

/***************************************************************
 *      FIR Filter with Redundant Load Elimination              *
 * By doing two outer loops simultaneously, you can potentially *
 * reuse data (depending on the DSP architecture). x and h only *
 * need to be loaded once, therefore reducing redundant loads.  *
 * This reduces memory bandwidth and power.                     *
 ***************************************************************/
void fir_no_red_ld(const short x[], const short h[], short y[])
{
	int i, j;
	long sum0, sum1;
	short x0, x1, h0, h1;

	for (j = 0; j < 100; j += 2) {
		sum0 = 0;
		sum1 = 0;
		x0 = x[j];
		for (i = 0; i < 32; i += 2) {
			x1 = x[j + i + 1];
			h0 = h[i];
			sum0 += x0 * h0;
			sum1 += x1 * h0;
			x0 = x[j + i + 2];
			h1 = h[i + 1];
			sum0 += x1 * h1;
			sum1 += x0 * h1;
		}
		y[j] = sum0 >> 15;
		y[j + 1] = sum1 >> 15;
	}
}

/***************************************************************
 *      Lattice Synthesis                                      *
 *                                                             *
 * This function doesn't follow the typical DSP multiply two   *
 * vector operation, but it will point out the compiler's      *
 * flexibility                                                 *
 ***************************************************************/
int latsynth(short b[], const short k[], long int n, long int f)
{
	int i;

	f -= b[n - 1] * k[n - 1];
	for (i = n - 2; i >= 0; i--) {
		f -= b[i] * k[i];
		b[i + 1] = b[i] + ((k[i] * (f >> 16)) >> 16);
	}
	b[0] = f >> 16;
	return f;
}

/*****************************************************
 *			IIR Filter		     *
 *****************************************************/
void iir1(const short *coefs, const short *input, short *optr,
	short *state)
{
	short x;
	short t;
	int n;

	x = input[0];
	for (n = 0; n < 50; n++) {
		t = x + ((coefs[2] * state[0] +
			coefs[3] * state[1]) >> 15);
		x = t + ((coefs[0] * state[0] +
			coefs[1] * state[1]) >> 15);

		state[1] = state[0];
		state[0] = t;
		coefs += 4;	/* point to next filter coefs  */
		state += 2;	/* point to next filter states */
	}
	*optr++ = x;
}

/*****************************************************
 *	Vocoder Codebook Search 	     *
 *****************************************************/
int codebook(int mask, int bitchanged, int numbasis, int codeword,
		int g, const short *d, short ddim, short theta)
{
	int j;
	int tmpMask;

	tmpMask = mask << 1;
	for (j = bitchanged + 1; j <= numbasis; j++) {
		if (theta == !(!(codeword & tmpMask)))
			g += *(d + bitchanged * ddim + j);
		else
			g -= *(d + bitchanged * ddim + j);
		tmpMask <<= 1;
	}

	return g;
}


/*****************************************************
 *	JPEG Discrete Cosine Transform 		     *
 *****************************************************/
void
jpegdct(short *d, const short *r)
{
	int t[12];
	int i, j, k, m, n, p;

	for (k = 1, m = 0, n = 13, p = 8;
		k <= 8;
		k += 7, m += 3, n += 3, p -= 7, d -= 64) {
		for (i = 0; i < 8; i++, d += p) {
			for (j = 0; j < 4; j++) {
				t[j] = d[k * j] + d[k * (7 - j)];
				t[7 - j] = d[k * j] - d[k * (7 - j)];
			}
			t[8] = t[0] + t[3];
			t[9] = t[0] - t[3];
			t[10] = t[1] + t[2];
			t[11] = t[1] - t[2];
			d[0] = (t[8] + t[10]) >> m;
			d[4 * k] = (t[8] - t[10]) >> m;
			t[8] = (short) (t[11] + t[9]) * r[10];
			d[2 * k] = t[8] + (short) ((t[9] * r[9]) >> n);
			d[6 * k] = t[8] + (short) ((t[11] * r[11]) >> n);
			t[0] = (short) (t[4] + t[7]) * r[2];
			t[1] = (short) (t[5] + t[6]) * r[0];
			t[2] = t[4] + t[6];
			t[3] = t[5] + t[7];
			t[8] = (short) (t[2] + t[3]) * r[8];
			t[2] = (short) t[2] * r[1] + t[8];
			t[3] = (short) t[3] * r[3] + t[8];
			d[7 * k] = (short) (t[4] * r[4] + t[0] + t[2]) >> n;
			d[5 * k] = (short) (t[5] * r[6] + t[1] + t[3]) >> n;
			d[3 * k] = (short) (t[6] * r[5] + t[1] + t[2]) >> n;
			d[1 * k] = (short) (t[7] * r[7] + t[0] + t[3]) >> n;
		}
	}
}
