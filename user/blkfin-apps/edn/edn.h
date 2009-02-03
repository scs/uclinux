#define N 100
#define ORDER 50

void vec_mpy1(short y[], const short x[], short scaler);
int mac(const short *a, const short *b, long int sqr, long int *sum);
void fir(const short array1[], const short coeff[], short output[]);
void fir_no_red_ld(const short x[], const short h[], short y[]);
int latsynth(short b[], const short k[], long int n, long int f);
void iir1(const short *coefs, const short *input, short *optr, short *state);
int codebook(int mask, int bitchanged, int numbasis, int codeword, int g, const short *d, short ddim, short theta);
void jpegdct(short *d, const short *r);
