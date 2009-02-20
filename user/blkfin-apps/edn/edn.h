#define N 100
#define ORDER 50

#ifdef INLINE
static __inline__ void vec_mpy1(short y[], const short x[], short scaler) __attribute__((always_inline));
static __inline__ int mac(const short *a, const short *b, int sqr, int *sum) __attribute__((always_inline));
static __inline__ void fir(const short array1[], const short coeff[], short output[]) __attribute__((always_inline));
static __inline__ void fir_no_red_ld(const short x[], const short h[], short y[]) __attribute__((always_inline));
static __inline__ int latsynth(short b[], const short k[], long int n, long int f) __attribute__((always_inline));
static __inline__ void iir1(const short *coefs, const short *input, short *optr, short *state) __attribute__((always_inline));
static __inline__ int codebook(int mask, int bitchanged, int numbasis, int codeword, int g, const short *d, short ddim, short theta) __attribute__((always_inline));
static __inline__ void jpegdct(short *d, const short *r) __attribute__((always_inline));
#else
void vec_mpy1(short y[], const short x[], short scaler);
int mac(const short *a, const short *b, int sqr, int *sum);
void fir(const short array1[], const short coeff[], short output[]);
void fir_no_red_ld(const short x[], const short h[], short y[]);
int latsynth(short b[], const short k[], long int n, long int f);
void iir1(const short *coefs, const short *input, short *optr, short *state);
int codebook(int mask, int bitchanged, int numbasis, int codeword, int g, const short *d, short ddim, short theta);
void jpegdct(short *d, const short *r);
#endif
