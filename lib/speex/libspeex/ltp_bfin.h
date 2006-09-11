/* Copyright (C) 2005 Analog Devices */
/**
   @file ltp_bfin.h
   @author Jean-Marc Valin
   @brief Long-Term Prediction functions (Blackfin version)
*/
/*
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   
   - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
   
   - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
   
   - Neither the name of the Xiph.org Foundation nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.
   
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define OVERRIDE_INNER_PROD
spx_word32_t inner_prod(const spx_word16_t *x, const spx_word16_t *y, int len)
{
   spx_word32_t sum=0;
   __asm__ __volatile__ (
      "P0 = %3;\n\t"
      "P1 = %1;\n\t"
      "P2 = %2;\n\t"
      "I0 = P1;\n\t"
      "I1 = P2;\n\t"
      "L0 = 0;\n\t"
      "L1 = 0;\n\t"
      "A0 = 0;\n\t"
      "R0.L = W[I0++] || R1.L = W[I1++];\n\t"
      "LOOP inner%= LC0 = P0;\n\t"
      "LOOP_BEGIN inner%=;\n\t"
         "A0 += R0.L*R1.L (IS) || R0.L = W[I0++] || R1.L = W[I1++];\n\t"
      "LOOP_END inner%=;\n\t"
      "A0 += R0.L*R1.L (IS);\n\t"
      "A0 = A0 >>> 6;\n\t"
      "R0 = A0;\n\t"
      "%0 = R0;\n\t"
   : "=m" (sum)
   : "m" (x), "m" (y), "d" (len-1)
   : "P0", "P1", "P2", "R0", "R1", "A0", "I0", "I1", "L0", "L1", "R3"
   );
   return sum;
}

#define OVERRIDE_PITCH_XCORR
void pitch_xcorr(const spx_word16_t *_x, const spx_word16_t *_y, spx_word32_t *corr, int len, int nb_pitch, char *stack)
{
   corr += nb_pitch - 1;
   __asm__ __volatile__ (
      "P2 = %0;\n\t"
      "I0 = P2;\n\t" /* x in I0 */
      "B0 = P2;\n\t" /* x in B0 */
      "R0 = %3;\n\t" /* len in R0 */
      "P3 = %3;\n\t"
      "P3 += -2;\n\t" /* len in R0 */
      "P4 = %4;\n\t" /* nb_pitch in R0 */
      "R1 = R0 << 1;\n\t" /* number of bytes in x */
      "L0 = R1;\n\t"
      "P0 = %1;\n\t"

      "P1 = %2;\n\t"
      "B1 = P1;\n\t"
      "L1 = 0;\n\t" /*Disable looping on I1*/

      "r0 = [I0++];\n\t"
      "LOOP pitch%= LC0 = P4 >> 1;\n\t"
      "LOOP_BEGIN pitch%=;\n\t"
         "I1 = P0;\n\t"
         "A1 = A0 = 0;\n\t"
         "R1 = [I1++];\n\t"
         "LOOP inner_prod%= LC1 = P3 >> 1;\n\t"
         "LOOP_BEGIN inner_prod%=;\n\t"
            "A1 += R0.L*R1.H, A0 += R0.L*R1.L (IS) || R1.L = W[I1++];\n\t"
            "A1 += R0.H*R1.L, A0 += R0.H*R1.H (IS) || R1.H = W[I1++] || R0 = [I0++];\n\t"
         "LOOP_END inner_prod%=;\n\t"
         "A1 += R0.L*R1.H, A0 += R0.L*R1.L (IS) || R1.L = W[I1++];\n\t"
         "A1 += R0.H*R1.L, A0 += R0.H*R1.H (IS) || R0 = [I0++];\n\t"
         "A0 = A0 >>> 6;\n\t"
         "A1 = A1 >>> 6;\n\t"
         "R2 = A0, R3 = A1;\n\t"
         "[P1--] = r2;\n\t"
         "[P1--] = r3;\n\t"
         "P0 += 4;\n\t"
      "LOOP_END pitch%=;\n\t"
      "L0 = 0;\n\t"
   : : "m" (_x), "m" (_y), "m" (corr), "m" (len), "m" (nb_pitch)
   : "A0", "A1", "P0", "P1", "P2", "P3", "P4", "R0", "R1", "R2", "R3", "I0", "I1", "L0", "L1", "B0", "B1", "memory"
   );
}

#define OVERRIDE_COMPUTE_PITCH_ERROR
static inline spx_word32_t compute_pitch_error(spx_word16_t *C, spx_word16_t *g, spx_word16_t pitch_control)
{
   spx_word32_t sum;
   __asm__ __volatile__
         (
         "A0 = 0;\n\t"
         
         "R0 = W[%1++];\n\t"
         "R1.L = %2.L*%5.L (IS);\n\t"
         "A0 += R1.L*R0.L (IS) || R0 = W[%1++];\n\t"
         
         "R1.L = %3.L*%5.L (IS);\n\t"
         "A0 += R1.L*R0.L (IS) || R0 = W[%1++];\n\t"
         
         "R1.L = %4.L*%5.L (IS);\n\t"
         "A0 += R1.L*R0.L (IS) || R0 = W[%1++];\n\t"
         
         "R1.L = %2.L*%3.L (IS);\n\t"
         "A0 -= R1.L*R0.L (IS) || R0 = W[%1++];\n\t"

         "R1.L = %4.L*%3.L (IS);\n\t"
         "A0 -= R1.L*R0.L (IS) || R0 = W[%1++];\n\t"
         
         "R1.L = %4.L*%2.L (IS);\n\t"
         "A0 -= R1.L*R0.L (IS) || R0 = W[%1++];\n\t"
         
         "R1.L = %2.L*%2.L (IS);\n\t"
         "A0 -= R1.L*R0.L (IS) || R0 = W[%1++];\n\t"

         "R1.L = %3.L*%3.L (IS);\n\t"
         "A0 -= R1.L*R0.L (IS) || R0 = W[%1++];\n\t"
         
         "R1.L = %4.L*%4.L (IS);\n\t"
         "A0 -= R1.L*R0.L (IS);\n\t"
         
         "%0 = A0;\n\t"
   : "=&D" (sum), "=a" (C)
   : "d" (g[0]), "d" (g[1]), "d" (g[2]), "d" (pitch_control), "1" (C)
   : "R0", "R1", "R2", "A0"
         );
   return sum;
}

#define OVERRIDE_OPEN_LOOP_NBEST_PITCH
#ifdef OVERRIDE_OPEN_LOOP_NBEST_PITCH
void open_loop_nbest_pitch(spx_word16_t *sw, int start, int end, int len, int *pitch, spx_word16_t *gain, int N, char *stack)
{
   int i,j,k;
   VARDECL(spx_word32_t *best_score);
   VARDECL(spx_word32_t *best_ener);
   spx_word32_t e0;
   VARDECL(spx_word32_t *corr);
   VARDECL(spx_word32_t *energy);

   ALLOC(best_score, N, spx_word32_t);
   ALLOC(best_ener, N, spx_word32_t);
   ALLOC(corr, end-start+1, spx_word32_t);
   ALLOC(energy, end-start+2, spx_word32_t);

   for (i=0;i<N;i++)
   {
        best_score[i]=-1;
        best_ener[i]=0;
        pitch[i]=start;
   }

   energy[0]=inner_prod(sw-start, sw-start, len);
   e0=inner_prod(sw, sw, len);

   /* energy update -------------------------------------*/

      __asm__ __volatile__
      (
"        P0 = %0;\n\t"
"        I1 = %1;\n\t"
"        L1 = 0;\n\t"
"        I2 = %2;\n\t"
"        L2 = 0;\n\t"
"        R2 = [P0++];\n\t"
"        R3 = 0;\n\t"
"        LSETUP (eu1, eu2) LC1 = %3;\n\t"
"eu1:      R1.L = W [I1--] || R0.L = W [I2--] ;\n\t"
"          R1 = R1.L * R1.L (IS);\n\t"
"          R0 = R0.L * R0.L (IS);\n\t"
"          R1 >>>= 6;\n\t"
"          R1 = R1 + R2;\n\t"
"          R0 >>>= 6;\n\t"
"          R1 = R1 - R0;\n\t"
"          R2 = MAX(R1,R3);\n\t"
"eu2:      [P0++] = R2;\n\t"
       : : "d" (energy), "d" (&sw[-start-1]), "d" (&sw[-start+len-1]),
           "a" (end-start)  
       : "P0", "I1", "I2", "R0", "R1", "R2", "R3"
#if (__GNUC__ == 4)
         , "LC1"
#endif
       );

   pitch_xcorr(sw, sw-end, corr, len, end-start+1, stack);

   /* FIXME: Fixed-point and floating-point code should be merged */
#ifdef FIXED_POINT
   {
      VARDECL(spx_word16_t *corr16);
      VARDECL(spx_word16_t *ener16);
      ALLOC(corr16, end-start+1, spx_word16_t);
      ALLOC(ener16, end-start+1, spx_word16_t);
      /* Normalize to 180 so we can square it and it still fits in 16 bits */
      normalize16(corr, corr16, 180, end-start+1);
      normalize16(energy, ener16, 180, end-start+1);

      if (N == 1) {
	/* optimised asm to handle N==1 case */
      __asm__ __volatile__
      (
"        I0 = %1;\n\t"                     /* I0: corr16[]    */
"        L0 = 0;\n\t"
"        I1 = %2;\n\t"                     /* I1: energy      */
"        L1 = 0;\n\t"
"        R2 = -1;\n\t"                     /* R2: best score  */
"        R3 = 0;\n\t"                      /* R3: best energy */
"        P0 = %4;\n\t"                     /* P0: best pitch  */
"        P1 = %4;\n\t"                     /* P1: counter     */
"        LSETUP (sl1, sl2) LC1 = %3;\n\t"
"sl1:      R0.L = W [I0++] || R1.L = W [I1++];\n\t"         
"          R0 = R0.L * R0.L (IS);\n\t"
"          R1   += 1;\n\t"
"          R4   = R0.L * R3.L;\n\t"
"          R5   = R2.L * R1.L;\n\t"
"          cc   = R5 < R4;\n\t"
"          if cc R2 = R0;\n\t"
"          if cc R3 = R1;\n\t"
"          if cc P0 = P1;\n\t"
"sl2:      P1 += 1;\n\t"
"        %0 = P0;\n\t"
       : "=&d" (pitch[0])
       : "a" (corr16), "a" (ener16), "a" (end+1-start), "d" (start) 
       : "P0", "P1", "I0", "I1", "R0", "R1", "R2", "R3", "R4", "R5"
#if (__GNUC__ == 4)
         , "LC1"
#endif
       );

      }
      else {
	for (i=start;i<=end;i++)
	  {
	    spx_word16_t tmp = MULT16_16_16(corr16[i-start],corr16[i-start]);
	    /* Instead of dividing the tmp by the energy, we multiply on the other side */
	    if (MULT16_16(tmp,best_ener[N-1])>MULT16_16(best_score[N-1],ADD16(1,ener16[i-start])))
	      {
		/* We can safely put it last and then check */
		best_score[N-1]=tmp;
		best_ener[N-1]=ener16[i-start]+1;
		pitch[N-1]=i;
		/* Check if it comes in front of others */
		for (j=0;j<N-1;j++)
		  {
		    if (MULT16_16(tmp,best_ener[j])>MULT16_16(best_score[j],ADD16(1,ener16[i-start])))
		      {
			for (k=N-1;k>j;k--)
			  {
			    best_score[k]=best_score[k-1];
			    best_ener[k]=best_ener[k-1];
			    pitch[k]=pitch[k-1];
			  }
			best_score[j]=tmp;
			best_ener[j]=ener16[i-start]+1;
			pitch[j]=i;
			break;
		      }
		  }
	      }
	  }
      }
   }
#else
   for (i=start;i<=end;i++)
   {
      float tmp = corr[i-start]*corr[i-start];
      if (tmp*best_ener[N-1]>best_score[N-1]*(1+energy[i-start]))
      {
         for (j=0;j<N;j++)
         {
            if (tmp*best_ener[j]>best_score[j]*(1+energy[i-start]))
            {
               for (k=N-1;k>j;k--)
               {
                  best_score[k]=best_score[k-1];
                  best_ener[k]=best_ener[k-1];
                  pitch[k]=pitch[k-1];
               }
               best_score[j]=tmp;
               best_ener[j]=energy[i-start]+1;
               pitch[j]=i;
               break;
            }
         }
      }
   }
#endif

   /* Compute open-loop gain */
   if (gain)
   {
       for (j=0;j<N;j++)
       {
          spx_word16_t g;
          i=pitch[j];
          g = DIV32(corr[i-start], 10+SHR32(MULT16_16(spx_sqrt(e0),spx_sqrt(energy[i-start])),6));
          /* FIXME: g = max(g,corr/energy) */
                   if (g<0)
                   g = 0;
             gain[j]=g;
       }
   }
}
#endif

#define OVERRIDE_PITCH_GAIN_SEARCH_3TAP
#ifdef OVERRIDE_PITCH_GAIN_SEARCH_3TAP

/** Finds the best quantized 3-tap pitch predictor by analysis by synthesis */
static spx_word32_t pitch_gain_search_3tap(
const spx_word16_t target[],       /* Target vector */
const spx_coef_t ak[],          /* LPCs for this subframe */
const spx_coef_t awk1[],        /* Weighted LPCs #1 for this subframe */
const spx_coef_t awk2[],        /* Weighted LPCs #2 for this subframe */
spx_sig_t exc[],                /* Excitation */
const void *par,
int   pitch,                    /* Pitch value */
int   p,                        /* Number of LPC coeffs */
int   nsf,                      /* Number of samples in subframe */
SpeexBits *bits,
char *stack,
const spx_word16_t *exc2,
const spx_word16_t *r,
spx_word16_t *new_target,
int  *cdbk_index,
int cdbk_offset,
int plc_tuning
)
{
   int i,j;
   VARDECL(spx_word16_t *tmp1);
   VARDECL(spx_word16_t *e);
   spx_word16_t *x[3];
   spx_word32_t corr[3];
   spx_word32_t A[3][3];
   int   gain_cdbk_size;
   const signed char *gain_cdbk;
   spx_word16_t gain[3];
   spx_word32_t err;

   const ltp_params *params;
   params = (const ltp_params*) par;
   gain_cdbk_size = 1<<params->gain_bits;
   gain_cdbk = params->gain_cdbk + 3*gain_cdbk_size*cdbk_offset;
   ALLOC(tmp1, 3*nsf, spx_word16_t);
   ALLOC(e, nsf, spx_word16_t);

   x[0]=tmp1;
   x[1]=tmp1+nsf;
   x[2]=tmp1+2*nsf;
   
   {
      VARDECL(spx_mem_t *mm);
      int pp=pitch-1;
      ALLOC(mm, p, spx_mem_t);
      for (j=0;j<nsf;j++)
      {
         if (j-pp<0)
            e[j]=exc2[j-pp];
         else if (j-pp-pitch<0)
            e[j]=exc2[j-pp-pitch];
         else
            e[j]=0;
      }
      for (j=0;j<p;j++)
         mm[j] = 0;
      iir_mem16(e, ak, e, nsf, p, mm, stack);
      for (j=0;j<p;j++)
         mm[j] = 0;
      filter_mem16(e, awk1, awk2, e, nsf, p, mm, stack);
      for (j=0;j<nsf;j++)
         x[2][j] = e[j];
   }
   for (i=1;i>=0;i--)
   {
      spx_word16_t e0=exc2[-pitch-1+i];
      x[i][0]=MULT16_16_Q14(r[0], e0);
      for (j=0;j<nsf-1;j++)
         x[i][j+1]=ADD32(x[i+1][j],MULT16_16_P14(r[j+1], e0));
   }

   for (i=0;i<3;i++)
      corr[i]=inner_prod(x[i],target,nsf);
   for (i=0;i<3;i++)
      for (j=0;j<=i;j++)
         A[i][j]=A[j][i]=inner_prod(x[i],x[j],nsf);

   {
      spx_word32_t C[9];
      const signed char *ptr=gain_cdbk;
      int best_cdbk=0;
      spx_word32_t best_sum=0;
#ifdef FIXED_POINT
      spx_word16_t C16[9];
#else
      spx_word16_t *C16=C;
#endif      
      C[0]=corr[2];
      C[1]=corr[1];
      C[2]=corr[0];
      C[3]=A[1][2];
      C[4]=A[0][1];
      C[5]=A[0][2];      
      C[6]=A[2][2];
      C[7]=A[1][1];
      C[8]=A[0][0];
      
      /*plc_tuning *= 2;*/
      if (plc_tuning<2)
         plc_tuning=2;
      if (plc_tuning>30)
         plc_tuning=30;
#ifdef FIXED_POINT
      C[0] = SHL32(C[0],1);
      C[1] = SHL32(C[1],1);
      C[2] = SHL32(C[2],1);
      C[3] = SHL32(C[3],1);
      C[4] = SHL32(C[4],1);
      C[5] = SHL32(C[5],1);
      C[6] = MAC16_32_Q15(C[6],MULT16_16_16(plc_tuning,655),C[6]);
      C[7] = MAC16_32_Q15(C[7],MULT16_16_16(plc_tuning,655),C[7]);
      C[8] = MAC16_32_Q15(C[8],MULT16_16_16(plc_tuning,655),C[8]);
      normalize16(C, C16, 32767, 9);
#else
      C[6]*=.5*(1+.02*plc_tuning);
      C[7]*=.5*(1+.02*plc_tuning);
      C[8]*=.5*(1+.02*plc_tuning);
#endif

      /* fast asm version of VQ codebook search */

      __asm__ __volatile__
      (

"        P0 = %2;\n\t"                     /* P0: ptr to gain_cdbk */
"        L1 = 0;\n\t"                      /* no circ addr for L1  */
"        %0 = 0;\n\t"                      /* %0: best_sum         */
"        %1 = 0;\n\t"                      /* %1: best_cbdk        */
"        P1 = 0;\n\t"                      /* P1: loop counter     */

"        LSETUP (pgs1, pgs2) LC1 = %4;\n\t"
"pgs1:     R2  = B [P0++] (X);\n\t"        /* R2: g[0]             */
"          R3  = B [P0++] (X);\n\t"        /* R3: g[1]             */
"          R4  = B [P0++] (X);\n\t"        /* R4: g[2]             */
"          R2 += 32;\n\t"
"          R3 += 32;\n\t"
"          R4 += 32;\n\t"

"          R0  = ABS R2;\n\t"              /* determine gain_sum   */
"          R1  = ABS R3;\n\t"
"          R0  = R0 + R1;\n\t"
"          R1  = ABS R4;\n\t"
"          R0  = R0 + R1;\n\t"

"          R0 += -60;\n\t"
"          R1  = 0;\n\t"
"          R0  = MAX(R0,R1);\n\t"

"          R0 += 4;\n\t"
"          R0 >>>= 3;\n\t"
"          R5 = 64;\n\t"
"          R5 = R5 - R0;\n\t"              /* R5: pitch control    */

           /* compute_pitch_error() -------------------------------*/

"          I1 = %3;\n\t"                   /* I1: ptr to C         */
"          A0 = 0;\n\t"
         
"          R0.L = W[I1++];\n\t"
"          R1.L = R2.L*R5.L (IS);\n\t"
"          A0 += R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"
         
"          R1.L = R3.L*R5.L (IS);\n\t"
"          A0 += R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"
         
"          R1.L = R4.L*R5.L (IS);\n\t"
"          A0 += R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"
         
"          R1.L = R2.L*R3.L (IS);\n\t"
"          A0 -= R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"

"          R1.L = R4.L*R3.L (IS);\n\t"
"          A0 -= R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"
         
"          R1.L = R4.L*R2.L (IS);\n\t"
"          A0 -= R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"
         
"          R1.L = R2.L*R2.L (IS);\n\t"
"          A0 -= R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"

"          R1.L = R3.L*R3.L (IS);\n\t"
"          A0 -= R1.L*R0.L (IS) || R0.L = W[I1++];\n\t"
         
"          R1.L = R4.L*R4.L (IS);\n\t"
"          R0 = (A0 -= R1.L*R0.L) (IS);\n\t"

"          cc = %0 < R0;\n\t"
"          if cc %0 = R0;\n\t"
"          if cc %1 = P1;\n\t"

"pgs2:     P1 += 1;\n\t"
   
       : "=&d" (best_sum), "=&d" (best_cdbk) 
       : "a" (gain_cdbk), "a" (C16), "a" (gain_cdbk_size) 
       : "R0", "R1", "R2", "R3", "R4", "R5", "P0", 
         "P1", "I1", "L1", "A0"
#if (__GNUC__ == 4)
         , "LC1"
#endif
       );

#ifdef FIXED_POINT
      gain[0] = ADD16(32,(spx_word16_t)gain_cdbk[best_cdbk*3]);
      gain[1] = ADD16(32,(spx_word16_t)gain_cdbk[best_cdbk*3+1]);
      gain[2] = ADD16(32,(spx_word16_t)gain_cdbk[best_cdbk*3+2]);
      /*printf ("%d %d %d %d\n",gain[0],gain[1],gain[2], best_cdbk);*/
#else
      gain[0] = 0.015625*gain_cdbk[best_cdbk*3]  + .5;
      gain[1] = 0.015625*gain_cdbk[best_cdbk*3+1]+ .5;
      gain[2] = 0.015625*gain_cdbk[best_cdbk*3+2]+ .5;
#endif
      *cdbk_index=best_cdbk;
   }


   for (i=0;i<nsf;i++)
      exc[i]=0;
   for (i=0;i<3;i++)
   {
      int j;
      int tmp1, tmp3;
      int pp=pitch+1-i;
      tmp1=nsf;
      if (tmp1>pp)
         tmp1=pp;
      for (j=0;j<tmp1;j++)
         exc[j]=MAC16_16(exc[j],SHL16(gain[2-i],7),exc2[j-pp]);
      tmp3=nsf;
      if (tmp3>pp+pitch)
         tmp3=pp+pitch;
      for (j=tmp1;j<tmp3;j++)
         exc[j]=MAC16_16(exc[j],SHL16(gain[2-i],7),exc2[j-pp-pitch]);
   }
   err=0;
#ifdef FIXED_POINT
   for (i=0;i<nsf;i++)
   {
      spx_word16_t perr2;
      spx_word32_t tmp = ADD32(ADD32(MULT16_16(gain[0],x[2][i]),MULT16_16(gain[1],x[1][i])),
                            MULT16_16(gain[2],x[0][i]));
      new_target[i] = SUB16(target[i], EXTRACT16(PSHR32(tmp,6)));
   }
   err = inner_prod(new_target, new_target, nsf);
#else
   for (i=0;i<nsf;i++)
   {
      spx_sig_t tmp = gain[2]*x[0][i]+gain[1]*x[1][i]+gain[0]*x[2][i];
      new_target[i] = target[i] - tmp;
      err+=new_target[i]*new_target[i];
   }
#endif

   return err;
}
#endif
