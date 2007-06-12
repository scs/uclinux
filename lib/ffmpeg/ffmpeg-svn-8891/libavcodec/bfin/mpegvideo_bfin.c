/*
 * BlackFin MPEGVIDEO OPTIMIZATIONS
 *
 * Copyright (C) 2007 Marc Hoffman <mmh@pleasantst.com>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../dsputil.h"
#include "../mpegvideo.h"
#include "../avcodec.h"


#ifdef PROFILE

static double Telem[16];
static char  *TelemNames[16];
static int    TelemCnt;

#define PROF(lab,e) { int __e = e; char*__lab = lab; uint64_t _t0 = read_time();
#define EPROF()       _t0 = read_time()-_t0; Telem[__e] = Telem[__e] + _t0; TelemNames[__e] = __lab; }

static void prof_report (void)
{
    int i;
    double s = 0;
    for (i=0;i<16;i++) {
        double v;
        if (TelemNames[i]) {
            v = Telem[i]/TelemCnt;
            av_log (NULL,AV_LOG_DEBUG,"%-20s: %12.4f\t%12.4f\n", TelemNames[i],v,v/64);
            s = s + Telem[i];
        }
    }
    av_log (NULL,AV_LOG_DEBUG,"%-20s: %12.4f\t%12.4f\n%20.4f\t%d\n",
	    "total",s/TelemCnt,s/TelemCnt/64,s,TelemCnt);
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

    asm volatile
      (
       "i2=%1;\n\t"
       "r1=[%1++];                           \n\t"
       "r0=r1>>>15 (v);                      \n\t"
       "lsetup (0f,1f) lc0=%3;               \n\t"  /*  for(i=start_i; i<64; i++) {         */
       "0:   r0=r0|%4;                       \n\t"  /*      sign     = (block[i]>>15)|1;    */
       "     r1=abs r1 (v)                       "
       "         || r2=[%2++];               \n\t"
       "     r1=r1+|+%5;                     \n\t"  /*      level=abs(block[i])+bias;       */
       "     r1=max(r1,%6) (v);              \n\t"  /*      if (level < 0) level = 0;       */
       "     r1.h=(a1 =r1.h*r2.h),               "  /*      level    = (lavel*qmat[i])>>16; */
       "         r1.l=(a0 =r1.l*r2.l) (tfu); \n\t"
       "     %0=%0|r1;                       \n\t"  /*      max     |= level;               */
       "     r0.h=(a1 =r1.h*r0.h),               "  /*      level    = level * sign;        */
       "         r0.l=(a0 =r1.l*r0.l) (is)       "
       "              || r1=[%1++];          \n\t"
       "1:   r0=r1>>>15 (v)                      "
       "         || [i2++]=r0;               \n\t"  /*      block[i] = level;               */

       "r1=%0>>16;                           \n\t"  /*      max = (uint16_t)((max>>16) | max) */
       "%0=%0|r1;                            \n\t"
       "%0.h=0;                              \n\t"
       : "=&d" (max)
       : "b" (block), "b" (qmat), "a" (32), "d" (0x00010001), "d" (bias[0]*0x10001), "d" (0)
       : "R0","R1","R2", "I2");
    if (start_i == 1) block[0] = dc;
#if 0
    /*  for(i=start_i; i<64; i++) {                           */
    /*      sign     = (block[i]>>15)|1;                      */
    /*      level    = ((abs(block[i])+bias[0])*qmat[i])>>16; */
    /*      if (level < 0) level = 0;                         */
    /*      max     |= level;                                 */
    /*      level    = level * sign;                          */
    /*      block[i] = level;                                 */
    /*  } */

    asm volatile
	(
	 "i2=%1;\n\t"
	 "r1=[%1++];                                                         \n\t"
	 "r0=r1>>>15 (v);                                                    \n\t"
	 "lsetup (0f,1f) lc0=%3;                                             \n\t"
	 "0:   r0=r0|%4;                                                     \n\t"
	 "     r1=abs r1 (v)                                    || r2=[%2++];\n\t"
	 "     r1=r1+|+%5;                                                   \n\t"
	 "     r1=max(r1,%6) (v);                                            \n\t"
	 "     r1.h=(a1 =r1.h*r2.h), r1.l=(a0 =r1.l*r2.l) (tfu);             \n\t"
	 "     %0=%0|r1;                                                     \n\t"
	 "     r0.h=(a1 =r1.h*r0.h), r0.l=(a0 =r1.l*r0.l) (is)  || r1=[%1++];\n\t"
	 "1:   r0=r1>>>15 (v)                                   || [i2++]=r0;\n\t"
	 "r1=%0>>16;                                                         \n\t"
	 "%0=%0|r1;                                                          \n\t"
	 "%0.h=0;                                                            \n\t"
	 : "=&d" (max)
	 : "b" (block), "b" (qmat), "a" (32), "d" (0x00010001), "d" (bias[0]*0x10001), "d" (0)
	 : "R0","R1","R2", "I2");
    if (start_i == 1) block[0] = dc;
#endif
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

    /* we need this permutation so that we correct the IDCT, we only permute the !=0 elements */
    if (s->dsp.idct_permutation_type != FF_NO_IDCT_PERM)
        ff_block_permute(block, s->dsp.idct_permutation, scantable, last_non_zero);

    return last_non_zero;
}

#if 0
static void pblk (char *lab, int no, DCTELEM *block)
{
    int i;
    av_log (NULL,0, "%s: %d\n", lab, no);
    for (i=0;i<64;i++) {
        if (i>0 && (i&7)==0) av_log (NULL,0,"\n");
        av_log (NULL,0, "%5d, ", block[i]);
    }
    av_log (NULL,0,"\n");
}

static void pblkl (char *lab, int no, int *block)
{
    int i;
    av_log (NULL,0, "%s: %d\n", lab, no);
    for (i=0;i<64;i++) {
        if (i>0 && (i&7)==0) av_log (NULL,0,"\n");
        av_log (NULL,0, "%5d, ", block[i]);
    }
    av_log (NULL,0,"\n");
}

static DCTELEM tmp[64];
static DCTELEM orig[64];

static int dct_quantize_ref (MpegEncContext *s,
                             DCTELEM *block, int n,
                             int qscale, int *overflow)
{
    int i, j, level, last_non_zero, q, start_i;
    const int *qmat;
    const uint8_t *scantable= s->intra_scantable.scantable;
    int bias;
    int max=0;
    unsigned int threshold1, threshold2;

    const short *Q,*B;
    int max2=0;
    short dc,sign,x;

    s->dsp.fdct (block);

    if(s->dct_error_sum)
        s->denoise_dct(s, block);

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
        block[0] = (block[0] + (q >> 1)) / q;
        start_i = 1;
        last_non_zero = 0;
        qmat = s->q_intra_matrix[qscale];
        bias= s->intra_quant_bias<<(QMAT_SHIFT - QUANT_BIAS_SHIFT);
        B = s->q_intra_matrix16[qscale][1];
        Q = s->q_intra_matrix16[qscale][0];
    } else {
        start_i = 0;
        last_non_zero = -1;
        qmat = s->q_inter_matrix[qscale];
        bias= s->inter_quant_bias<<(QMAT_SHIFT - QUANT_BIAS_SHIFT);
        B = s->q_inter_matrix16[qscale][1];
        Q = s->q_inter_matrix16[qscale][0];
    }

    memcpy (orig,block,128);
    tmp[0] = block[0];
    for(i=start_i; i<64; i++) {
        sign     = (block[i]>>15)|1;
        level    = ((FFABS(block[i])+B[0])*Q[i])>>16;
        if (level < 0) level = 0;
        max2    |= level;
        level    = level * sign;
        tmp[i] = level;
    }

    asm volatile (
                  "i2=%7;\n\t"
                  "r1=[%1++];                                                         \n\t"
                  "r0=r1>>>15 (v);                                                    \n\t"
                  "lsetup (0f,1f) lc0=%3;                                             \n\t"
                  "0:   r0=r0|%4;                                                     \n\t"
                  "     r1=abs r1 (v)                                    || r2=[%2++];\n\t"
                  "     r1=r1+|+%5;                                                   \n\t"
                  "     r1=max(r1,%6) (v);                                            \n\t"
                  "     r1.h=(a1 =r1.h*r2.h), r1.l=(a0 =r1.l*r2.l) (tfu);             \n\t"
                  "     %0=%0|r1;                                                     \n\t"
                  "     r0.h=(a1 =r1.h*r0.h), r0.l=(a0 =r1.l*r0.l) (is)  || r1=[%1++];\n\t"
                  "1:   r0=r1>>>15 (v)                                   || [i2++]=r0;\n\t"
                  "r1=%0>>16;                                                         \n\t"
                  "%0=%0|r1;                                                          \n\t"
                  "%0.h=0;                                                            \n\t"
                  : "=&d" (max2)
                  : "b" (block), "b" (Q), "a" (32), "d" (0x00010001), "d" (B[0]*0x10001), "d" (0),
                  "d" (tmp)
                  : "R0","R1","R2", "I2");
    if (start_i == 1) block[0] = dc;


    threshold1= (1<<QMAT_SHIFT) - bias - 1;
    threshold2= (threshold1<<1);

    for(i=63;i>=start_i;i--) {
        j = scantable[i];
        level = block[j] * qmat[j];

        if(((unsigned)(level+threshold1))>threshold2){
            last_non_zero = i;
            break;
        }else{
            block[j]=0;
        }
    }



    for(i=start_i; i<=last_non_zero; i++) {
        j = scantable[i];
        level = block[j] * qmat[j];

        //        if(   bias+level >= (1<<QMAT_SHIFT)
        //           || bias-level >= (1<<QMAT_SHIFT)){
        if(((unsigned)(level+threshold1))>threshold2){
            if(level>0){
                level= (bias + level)>>QMAT_SHIFT;
                block[j]= level;
            }else{
                level= (bias - level)>>QMAT_SHIFT;
                block[j]= -level;
            }
            max |=level;
        }else{
            block[j]=0;
        }
    }


    {
        static mbno = 0;
        if (memcmp (tmp, block, 128) != 0) {
            int err = 0;
            for (i=0;i<64;i++) {
                err += FFABS (tmp[i]-block[i]);
            }
            if (err < 64) {
                av_log (NULL,0,"mbno %d has err %d\n", mbno, err);
            }
            else {
                av_log (NULL,0, "%s\n", s->mb_intra?"intra":"non-intra");
                pblk ("in", mbno, orig);
                pblk ("ref", mbno, block);
                av_log (NULL,0,
			"threshold1 = %d, threshold2 = %d, QMAT_SHIFT = %d, bias = %d, qbias_sh = %d\n",
                        threshold1, threshold2, QMAT_SHIFT,
                        bias, QUANT_BIAS_SHIFT);
                pblkl ("qmat", mbno, qmat);

                for (i=0;i<64;i++) {
                    if (tmp[i] != block[i])
                        av_log (NULL,0,
				"%5d: %d %d %d != %d (%04x)\n", mbno, n, i, tmp[i],block[i],B[i]*Q[i]);
                }

                pblk ("tmp",mbno, tmp);
                pblk ("Q",0,Q);
                pblk ("B",0,B);
                abort ();
            }
        }
        mbno ++;
    }

    *overflow= s->max_qcoeff < max; //overflow might have happened

    /* we need this permutation so that we correct the IDCT, we only permute the !=0 elements */
    if (s->dsp.idct_permutation_type != FF_NO_IDCT_PERM)
        ff_block_permute(block, s->dsp.idct_permutation, scantable, last_non_zero);

    return last_non_zero;
}
#endif

void MPV_common_init_bfin (MpegEncContext *s)
{
//    if (mm_flags & MM_BFIN) {
    const int dct_algo = s->avctx->dct_algo;
    s->dct_quantize= dct_quantize_bfin;
//    }
}

