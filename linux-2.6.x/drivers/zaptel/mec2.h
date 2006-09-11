/*
 * Mark's Second Echo Canceller
 * 
 * Copyright (C) 2002, Digium, Inc.
 *
 * This program is free software and may be used and
 * distributed according to the terms of the GNU
 * General Public License, incorporated herein by
 * reference.
 *
 */
#ifndef _MARK2_ECHO_H
#define _MARK2_ECHO_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/slab.h>
#define MALLOC(a) kmalloc((a), GFP_KERNEL)
#define FREE(a) kfree(a)
#else
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#define MALLOC(a) malloc(a)
#define FREE(a) free(a)
#endif

/* Get optimized routines for math */
#include "arith.h"

#ifndef NULL
#define NULL 0
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

#include "mec2_const.h"

/* Circular buffer definition */
typedef struct {
  int idx_d;
  int size_d;
  short *buf_d;	/* Twice as large as we need */
} echo_can_cb_s;

// class definition
//
typedef struct  {
  /* Echo canceller definition */

  /* absolute time */
  int i_d;
  
  /* pre-computed constants */

  int N_d;
  int beta2_i;

  // declare accumulators for power computations
  //
  int Ly_i;
  int Lu_i;

  // declare an accumulator for the near-end signal detector
  //
  int s_tilde_i;
  int HCNTR_d;

  // circular buffers and coefficients
  //
  int *a_i;
  short *a_s;
  echo_can_cb_s y_s;
  echo_can_cb_s s_s;
  echo_can_cb_s u_s;
  echo_can_cb_s y_tilde_s;
  int y_tilde_i;

  /* Max memory */
  short max_y_tilde;
  int max_y_tilde_pos;

} echo_can_state_t;

static inline void init_cb_s(echo_can_cb_s *cb, int len, void *where)
{
	cb->buf_d = (short *)where;
	cb->idx_d = 0;
	cb->size_d = len;
}

static inline void add_cc_s(echo_can_cb_s *cb, short newval)
{
    /* Can't use modulus because N+M isn't a power of two (generally) */
    cb->idx_d--;
    if (cb->idx_d < (int)0)
     {cb->idx_d += cb->size_d;}
	/* Load two copies into memory */
	cb->buf_d[cb->idx_d] = newval;
	cb->buf_d[cb->idx_d + cb->size_d] = newval;
}

static inline short get_cc_s(echo_can_cb_s *cb, int pos)
{
	/* Load two copies into memory */
	return cb->buf_d[cb->idx_d + pos];
}

static inline void init_cc(echo_can_state_t *ec, int N, int maxy, int maxu) {

  void *ptr = ec;
  unsigned long tmp;
  /* double-word align past end of state */
  ptr += sizeof(echo_can_state_t);
  tmp = (unsigned long)ptr;
  tmp += 3;
  tmp &= ~3L;
  ptr = (void *)tmp;
  
  // reset parameters
  //
  ec->N_d = N;
  ec->beta2_i = DEFAULT_BETA1_I;
  
  // allocate coefficient memory
  //
  ec->a_i = ptr;
  ptr += (sizeof(int) * ec->N_d);
  ec->a_s = ptr;
  ptr += (sizeof(short) * ec->N_d);

  /* Reset Y circular buffer (short version) */
  init_cb_s(&ec->y_s, maxy, ptr);
  ptr += (sizeof(short) * (maxy) * 2);
  
  /* Reset Sig circular buffer (short version for FIR filter) */
  init_cb_s(&ec->s_s, (1 << DEFAULT_ALPHA_ST_I), ptr);
  ptr += (sizeof(short) * (1 << DEFAULT_ALPHA_ST_I) * 2);

  init_cb_s(&ec->u_s, maxu, ptr);
  ptr += (sizeof(short) * maxu * 2);

  // allocate a buffer for the reference signal power computation
  //
  init_cb_s(&ec->y_tilde_s, ec->N_d, ptr);


  // reset absolute time
  //
  ec->i_d = (int)0;
  
  // reset the power computations (for y and u)
  //
  ec->Ly_i = DEFAULT_CUTOFF_I;

  // reset the near-end speech detector
  //
  ec->s_tilde_i = 0;
  ec->HCNTR_d = (int)0;

  // exit gracefully
  //
}

static inline void echo_can_free(echo_can_state_t *ec)
{
	FREE(ec);
}

static inline short echo_can_update(echo_can_state_t *ec, short iref, short isig) {

  /* declare local variables that are used more than once
  */
  int k;
  int rs;
  short u;
  int Py_i;
  int two_beta_i;
  
  /***************************************************************************
  //
  // flow A on pg. 428
  //
   ***************************************************************************/

  /* eq. (16): high-pass filter the input to generate the next value;
  //           push the current value into the circular buffer
  //
  // sdc_im1_d = sdc_d;
  // sdc_d = sig;
  //  s_i_d = sdc_d;
  //  s_d = s_i_d;
  //  s_i_d = (float)(1.0 - gamma_d) * s_i_d
     + (float)(0.5 * (1.0 - gamma_d)) * (sdc_d - sdc_im1_d); */
  
  
  /* Delete last sample from power estimate */
  ec->y_tilde_i -= abs(get_cc_s(&ec->y_s, (1 << DEFAULT_ALPHA_YT_I) - 1 )) >> DEFAULT_ALPHA_YT_I;
  /* push the reference data onto the circular buffer */
  add_cc_s(&ec->y_s, iref);
 
  /* eq. (2): compute r in fixed-point */
  rs = CONVOLVE2(ec->a_s, ec->y_s.buf_d + ec->y_s.idx_d, ec->N_d);
  rs >>= 15;

  /* eq. (3): compute the output value (see figure 3) and the error
  // note: the error is the same as the output signal when near-end
  // speech is not present
  */
  u = isig - rs;  
  
  add_cc_s(&ec->u_s, u);
  


  /* Delete oldest part of received s_tilde */
  ec->s_tilde_i -= abs(get_cc_s(&ec->s_s, (1 << DEFAULT_ALPHA_ST_I) - 1 ));

  /* push the signal on the circular buffer, too */
  add_cc_s(&ec->s_s, isig);
  ec->s_tilde_i += abs(isig);
  ec->y_tilde_i += abs(iref) >> DEFAULT_ALPHA_ST_I;

  /* Add to our list of recent y_tilde's */
  add_cc_s(&ec->y_tilde_s, ec->y_tilde_i);		

  /****************************************************************************
  //
  // flow B on pg. 428
  // 
   ****************************************************************************/
  
  /* compute the new convergence factor
  */
  Py_i = (ec->Ly_i >> DEFAULT_SIGMA_LY_I) * (ec->Ly_i >> DEFAULT_SIGMA_LY_I);
  Py_i >>= 15;
  if (ec->HCNTR_d > 0) {
  	Py_i = (1 << 15);
  }
  
#if 0
  printf("Py: %e, Py_i: %e\n", Py, Py_i * AMPL_SCALE_1);
#endif  

  /* Vary rate of adaptation depending on position in the file
  // Do not do this for the first (DEFAULT_UPDATE_TIME) secs after speech
  // has begun of the file to allow the echo cancellor to estimate the
  // channel accurately
  */
#if 0
  if (ec->start_speech_d != 0 ){
    if ( ec->i_d > (DEFAULT_T0 + ec->start_speech_d)*(SAMPLE_FREQ) ){
      ec->beta2_d = max_cc_float(MIN_BETA,
		       DEFAULT_BETA1 * exp((-1/DEFAULT_TAU)*((ec->i_d/(float)SAMPLE_FREQ) -
						 DEFAULT_T0 -
						 ec->start_speech_d)));
    }
  }
  else {ec->beta2_d = DEFAULT_BETA1;}
#endif
  
  ec->beta2_i = DEFAULT_BETA1_I;	/* Fixed point, inverted */
  
  two_beta_i = (ec->beta2_i * Py_i) >> 15;	/* Fixed point version, inverted */
  if (!two_beta_i)
  	two_beta_i++;

  /* Update Lu_i (Suppressed power estimate) */
  ec->Lu_i -= abs(get_cc_s(&ec->u_s, (1 << DEFAULT_SIGMA_LU_I) - 1 )) ;
  ec->Lu_i += abs(u);

  /* eq. (10): update power estimate of the reference
  */
  ec->Ly_i -= abs(get_cc_s(&ec->y_s, (1 << DEFAULT_SIGMA_LY_I) - 1)) ;
  ec->Ly_i += abs(iref);

  if (ec->Ly_i < DEFAULT_CUTOFF_I)
  	ec->Ly_i = DEFAULT_CUTOFF_I;

#if 0
  printf("Float: %e, Int: %e\n", ec->Ly_d, (ec->Ly_i >> DEFAULT_SIGMA_LY_I) * AMPL_SCALE_1);
#endif
  
  if (ec->y_tilde_i > ec->max_y_tilde) {
  	/* New highest y_tilde with full life */
	ec->max_y_tilde = ec->y_tilde_i;
	ec->max_y_tilde_pos = ec->N_d - 1;
  } else if (--ec->max_y_tilde_pos < 0) {
    /* Time to find new max y tilde... */
	ec->max_y_tilde = MAX16(ec->y_tilde_s.buf_d + ec->y_tilde_s.idx_d, ec->N_d, &ec->max_y_tilde_pos);
  }

  if ((ec->s_tilde_i >> (DEFAULT_ALPHA_ST_I - 1)) > ec->max_y_tilde)
    {
      ec->HCNTR_d = DEFAULT_HANGT;
    }
  else if (ec->HCNTR_d > (int)0)
    {
      ec->HCNTR_d--;
    }

  /* update coefficients if no near-end speech and we have enough signal
   * to bother trying to update.
  */
  if (!ec->HCNTR_d && !(ec->i_d % DEFAULT_M) && 
      (ec->Lu_i > MIN_UPDATE_THRESH_I)) {
	    // loop over all filter coefficients
	    //
	    for (k=0; k<ec->N_d; k++) {
	      
	      // eq. (7): compute an expectation over M_d samples 
	      //
		  int grad2;
	      grad2 = CONVOLVE2(ec->u_s.buf_d + ec->u_s.idx_d,
		  					ec->y_s.buf_d + ec->y_s.idx_d + k, DEFAULT_M);
	      // eq. (7): update the coefficient
	      //
	      ec->a_i[k] += grad2 / two_beta_i;
		  ec->a_s[k] = ec->a_i[k] >> 16;
	    }
  }

  /* paragraph below eq. (15): if no near-end speech,
  // check for residual error suppression
  */
#ifndef NO_ECHO_SUPPRESSOR
#ifdef AGGRESSIVE_SUPPRESSOR
  if ((ec->HCNTR_d < AGGRESSIVE_HCNTR) && (ec->Ly_i > (ec->Lu_i << 1))) {
 	u = u * (ec->Lu_i >> DEFAULT_SIGMA_LU_I) / ((ec->Ly_i >> (DEFAULT_SIGMA_LY_I)) + 1);
 	u = u * (ec->Lu_i >> DEFAULT_SIGMA_LU_I) / ((ec->Ly_i >> (DEFAULT_SIGMA_LY_I)) + 1);
  }
#else	
  if ((ec->HCNTR_d == 0) && ((ec->Ly_i/(ec->Lu_i + 1)) > DEFAULT_SUPPR_I)) {
  	u = u * (ec->Lu_i >> DEFAULT_SIGMA_LU_I) / ((ec->Ly_i >> (DEFAULT_SIGMA_LY_I + 2)) + 1);
  }
#endif	
#endif  

#if 0
  if ((ec->HCNTR_d == 0) && ((ec->Lu_d/ec->Ly_d) < DEFAULT_SUPPR) &&
      (ec->Lu_d/ec->Ly_d > EC_MIN_DB_VALUE)) { 
    suppr_factor = (10/(float)(SUPPR_FLOOR-SUPPR_CEIL))*log(ec->Lu_d/ec->Ly_d)
      - SUPPR_CEIL/(float)(SUPPR_FLOOR - SUPPR_CEIL);

    u_suppr = pow(10.0,(suppr_factor)*RES_SUPR_FACTOR/10.0)*u_suppr;
    
  }
#endif  
  ec->i_d++;
  return u;
}

static inline echo_can_state_t *echo_can_create(int len, int adaption_mode)
{
	echo_can_state_t *ec;
	int maxy;
	int maxu;
	maxy = len + DEFAULT_M;
	maxu = DEFAULT_M;
	if (maxy < (1 << DEFAULT_ALPHA_YT_I))
		maxy = (1 << DEFAULT_ALPHA_YT_I);
	if (maxy < (1 << DEFAULT_SIGMA_LY_I))
		maxy = (1 << DEFAULT_SIGMA_LY_I);
	if (maxu < (1 << DEFAULT_SIGMA_LU_I))
		maxu = (1 << DEFAULT_SIGMA_LU_I);
	ec = (echo_can_state_t *)MALLOC(sizeof(echo_can_state_t) +
									4 + 						/* align */
									sizeof(int) * len +			/* a_i */
									sizeof(short) * len + 		/* a_s */
									2 * sizeof(short) * (maxy) +	/* y_s */
									2 * sizeof(short) * (1 << DEFAULT_ALPHA_ST_I) + /* s_s */
									2 * sizeof(short) * (maxu) +		/* u_s */
									2 * sizeof(short) * len);			/* y_tilde_s */
	if (ec) {
		memset(ec, 0, sizeof(echo_can_state_t) +
									4 + 						/* align */
									sizeof(int) * len +			/* a_i */
									sizeof(short) * len + 		/* a_s */
									2 * sizeof(short) * (maxy) +	/* y_s */
									2 * sizeof(short) * (1 << DEFAULT_ALPHA_ST_I) + /* s_s */
									2 * sizeof(short) * (maxu) +		/* u_s */
									2 * sizeof(short) * len);			/* y_tilde_s */
	  init_cc(ec, len, maxy, maxu);
	}
	return ec;
}

static inline int echo_can_traintap(echo_can_state_t *ec, int pos, short val)
{
	/* Reset hang counter to avoid adjustments after
	   initial forced training */
	ec->HCNTR_d = ec->N_d << 1;
	if (pos >= ec->N_d)
		return 1;
	ec->a_i[pos] = val << 17;
	ec->a_s[pos] = val << 1;
	if (++pos >= ec->N_d)
		return 1;
	return 0;
}

#endif
