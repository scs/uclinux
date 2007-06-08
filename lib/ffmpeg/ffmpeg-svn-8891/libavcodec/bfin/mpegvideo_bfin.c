#include "dsputil.h"
#include "mpegvideo.h"
#include "avcodec.h"

#ifdef PROFILE
#define clock()      ({ int _t; asm volatile ("%0=cycles;" : "=d" (_t)); _t; })

static double Telem[16];
static char  *TelemNames[16];
static int    TelemCnt;

#define PROF(lab,e) { int __e = e; char*__lab = lab;unsigned _t0 = clock();
#define EPROF()       _t0 = clock()-_t0; Telem[__e] = Telem[__e] + _t0; TelemNames[__e] = __lab; }

static void prof_report (void)
{
    int i;
    double s = 0;
    for (i=0;i<16;i++) {
        double v;
        if (TelemNames[i]) {
            v = Telem[i]/TelemCnt;
            av_log (0,0,"%-20s: %12.4f\t%12.4f\n", TelemNames[i],v,v/64);
            s = s + Telem[i];
        }
    }
    av_log (0,0,"%-20s: %12.4f\t%12.4f\n%20.4f\t%d\n", "total",s/TelemCnt,s/TelemCnt/64,s,TelemCnt);
}

static void bfprof (void)
{
    static int init;
    if (!init) atexit (prof_report);
    init=1;
    TelemCnt++;
}

#else
#define PROF(a,b)
#define EPROF()
#define bfprof()
#endif

#define abs(x) (((x)<0)?-(x):(x))

#define L1CODE __attribute__ ((l1_text))

extern void ff_bfin_fdct (DCTELEM *block) L1CODE;

static int dct_quantize_bfin (MpegEncContext *s,
			      DCTELEM *block, int n,
			      int qscale, int *overflow)
{
    int i, j, level, last_non_zero, q, start_i;
    const short *qmat;
    const uint8_t *scantable= s->intra_scantable.scantable;
    short *bias;
    short dc;
    short sign,x;
    int   max=0;

    PROF("fdct",0);
    ff_bfin_fdct (block);
    //    s->dsp.fdct (block);
    EPROF();

    PROF("denoise",1);
    if(s->dct_error_sum)
        s->denoise_dct(s, block);
    EPROF();

    PROF("quant-init",2);
    if (s->mb_intra) {
        if (!s->h263_aic) {
            if (n < 4)
                q = s->y_dc_scale;
            else
                q = s->c_dc_scale;
            q = q << 3;
        } else
            /* For AIC we skip quant/dequant of INTRADC */
            q = 1 << 3;

        /* note: block[0] is assumed to be positive */
        dc = block[0] = (block[0] + (q >> 1)) / q;
        start_i = 1;
        last_non_zero = 0;
        bias = s->q_intra_matrix16[qscale][1];
        qmat = s->q_intra_matrix16[qscale][0];

    } else {
        start_i = 0;
        last_non_zero = -1;
        bias = s->q_inter_matrix16[qscale][1];
        qmat = s->q_inter_matrix16[qscale][0];

    }
    EPROF();


    PROF("quantize",4);

    /*  for(i=start_i; i<64; i++) {                         */
    /*      sign     = (block[i]>>15)|1;                    */
    /*      level    = ((long)abs(block[i]) * qmat[i])>>16; */
    /*      max     |= level;                               */
    /*      level    = level * sign;                        */
    /*      block[i] = level;                               */
    /*  } */

    asm volatile (
                  "i2=%1;\n\t"
                  "r1=[%1++];                                                         \n\t"
                  "r0=r1>>>15 (v);                                                    \n\t"
                  "lsetup (0f,1f) lc0=%3;                                             \n\t"
                  "0:   r0=r0|%4;                                                     \n\t"
                  "     r1=abs r1 (v)                                    || r2=[%2++];\n\t"
                  "     r1.h=(a1 =r1.h*r2.h), r1.l=(a0 =r1.l*r2.l) (tfu);             \n\t"
                  "     %0=%0|r1;                                                     \n\t"
                  "     r0.h=(a1 =r1.h*r0.h), r0.l=(a0 =r1.l*r0.l) (is)  || r1=[%1++];\n\t"
                  "1:   r0=r1>>>15 (v)                                   || [i2++]=r0;\n\t"
                  "r1=%0>>16;                                                         \n\t"
                  "%0=%0|r1;                                                          \n\t"
                  "%0.h=0;                                                            \n\t"
                  : "=&d" (max)
                  : "b" (block), "b" (qmat), "a" (32), "d" (0x00010001), "a" (start_i)
                  : "R0","R1","R2", "I2","I3");
    if (start_i == 1) block[0] = dc;
    EPROF();

    PROF("zzscan",5);

    asm ("r0=b[%1--] (x);         \n\t"
         "lsetup (0f,1f) lc0=%3;  \n\t"     /*    for(i=63; i>=start_i; i--) { */
         "0: p0=r0;               \n\t"     /*        j = scantable[i];        */
         "   p0=%2+(p0<<1);       \n\t"     /*        if (block[j]) {          */
         "   r0=w[p0];            \n\t"     /*           last_non_zero = i;    */
         "   cc=r0==0;            \n\t"     /*           break;                */
         "   if !cc jump 2f;      \n\t"     /*        }                        */
         "1: r0=b[%1--] (x);      \n\t"     /*    }                            */
         "   %0=%4;               \n\t"
         "   jump 3f;             \n\t"
         "2: %0=lc0;              \n\t"
         "3:\n\t"

         : "=d" (last_non_zero)
         : "a" (scantable+63), "a" (block), "a" (63), "d" (last_non_zero)
         : "P0","R0");

    EPROF();

    *overflow= s->max_qcoeff < max; //overflow might have happened

    bfprof();
    return last_non_zero;
}


void MPV_common_init_bfin (MpegEncContext *s)
{
    //    if (mm_flags & MM_BFIN) {
    const int dct_algo = s->avctx->dct_algo;
    s->dct_quantize= dct_quantize_bfin;
    //    }
}

