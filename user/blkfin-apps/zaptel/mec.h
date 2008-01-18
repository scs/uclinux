/*
 * Mark's Echo Canceller
 *
 * Mark Spencer <markster@linux-support.net>
 *
 * Simple, LMS Echo Canceller with double talk detection.  
 * Partly based on the TI App note:
 *     "Digital Voice Echo Canceller with a TMS 32020"
 *
 * Special additional thanks to:
 * 		Jim Dixon 	  (Lambda Telecommunications)
 *		Iman Ghobrial (Adtran, Inc.)
 *
 * Copyright (C) 2001, Linux Support Services, Inc.
 *
 * This program is free software and may be used and
 * distributed according to the terms of the GNU
 * General Public License, incorporated herein by
 * reference.
 *
 */

#ifndef _MEC_H
#define _MEC_H 

/* You have to express the size of the echo canceller in taps as
   a power of 2 (6 = 64 taps, 7 = 128 taps, 8 = 256 taps) */
#define	NUM_TAPS_POW2	6	/* Size of echo canceller in power of 2 (taps) */
#define NUM_TAPS (1 << NUM_TAPS_POW2) /* Actual number of taps */
#define TAP_MASK (NUM_TAPS-1)


#define SIGMA_LU_POW NUM_TAPS_POW2
#define SIGMA_LY_POW NUM_TAPS_POW2
#define SIGMA_YT_POW (NUM_TAPS_POW2 - 1)
#define SIGMA_ST_POW (NUM_TAPS_POW2 - 1)

#define BETA_POW	  8

#define CUTOFF_S 4

/* The higher you make this, the better the quality, but the more CPU time required */
#define MIN_QUALITY 100

/* This optimization saves a lot of processor but may degrade quality */
#define OPTIMIZEDIV

#if 0
/* This converges much more slowly but saves processor */
#define MIN_UPDATE 256
#define MIN_SKIP   8
#endif

#define HANG_T	600					/* 600 samples, or 75ms */

typedef struct mark_ec {
	/* Circular position */
	int cpos;
	short y[NUM_TAPS];		/* Last N samples (relative to cpos) transmitted */
	short y_abs[NUM_TAPS];		/* Last N samples (relative to cpos) transmitted (abs value) */
	short s[NUM_TAPS];		/* Last N samples (relative to cpos) received */
	short s_abs[NUM_TAPS];		/* Last N samples (relative to cpos) received (abs value) */
	short u[NUM_TAPS];		/* Last N samples (relative to cpos) with echo removed */
	short u_abs[NUM_TAPS];		/* Last N samples (relative to cpos) with echo removed */
	
	int Ly;				/* tx power */
	int Lu;				/* Power of echo-cancelled output */

	int Ty[NUM_TAPS];		/* Short term power estimate of transmit */
	int Ts;				/* Short term power estimate of received signal */

	int a[NUM_TAPS];		/* Tap weight coefficients (not relative) */
	
	short sdc[NUM_TAPS];		/* Near end signal before High Pass Filter */

	int samples;			/* Sample count */
	int pass;				/* Number of passes we've made */

	int hangt;

	int lastmax;			/* Optimize maximum search */
	int maxTy;			/* Maximum Ty */
} echo_can_state_t;

#define INLINE inline

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/slab.h>
#define MALLOC(a) kmalloc((a), GFP_KERNEL)
#define FREE(a) kfree((a))
#else
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#define MALLOC(a) malloc(a)
#define FREE(a) free(a)
#endif

static INLINE echo_can_state_t *echo_can_create(int len, int adaption_mode)
{
	echo_can_state_t *ec;
	/* Uhm, we're only one length, sorry.  */
	ec = MALLOC(sizeof(echo_can_state_t));
	if (ec)
		memset(ec, 0, sizeof(*ec));
	return ec;
}

#define PASSPOS 32000
#undef PASSPOS

static INLINE void echo_can_free(echo_can_state_t *ec)
{
	FREE(ec);
}

static INLINE int16_t echo_can_update(echo_can_state_t *ec, int16_t tx, int16_t rx)
{
	/* Process a sample, where tx is the near end and rx is the far end + echo */

	int suppr;
	int nsuppr;
	short rxabs, txabs;
	register int Lu;
	register int x;
	register int pos;
	register int r_hat;		/* Estimated echo */
	int oldrxabs;
	int oldtxabs;
	int oldsupprabs;
	int supprabs;
#ifdef MIN_UPDATE
	int totalupd;
#endif

	txabs = abs(tx);
	rxabs = abs(rx);

	ec->pass++;

	r_hat = 0;

	/* Load next value */
	ec->y[ec->cpos] = tx;

	/* Load next abs value */
	oldtxabs = ec->y_abs[ec->cpos];
	ec->y_abs[ec->cpos] = txabs;

	/* Bring in receive value (near-end signal) */
	ec->sdc[ec->cpos] = rx;
	
	/* Bring in receive value absolute value */
	oldrxabs = ec->s_abs[ec->cpos];
	ec->s_abs[ec->cpos] = rxabs;

	Lu = ec->Lu | 1;

#if 0
	/* Apply first order high pass filter (3 dB @ 160 Hz) */
	tx = ec->s[ec->cpos] = (1.0-DEFGAMMA) * ec->s[(ec->cpos - 1) & TAP_MASK] +
							0.5 * (1.0-DEFGAMMA) * ( ec->sdc[(ec->cpos - 1) & TAP_MASK] - ec->sdc[(ec->cpos - 2) & TAP_MASK]);
#endif

	/* Estimate echo */
	pos = ec->cpos;
	for (x=0;x<NUM_TAPS;x++) {
		r_hat += ec->a[x] * ec->y[pos];
		/* Go backwards in time and loop around circular buffer */
		pos = (pos - 1) & TAP_MASK;
	}
	
	r_hat >>= 16;
	
	if (ec->hangt > 0)
		ec->hangt--;

	/* printf("rx: %F, rhat: %F\n", rx, r_hat); */
	/* Calculate suppressed amount */
	suppr = rx - r_hat;

	if (ec->pass > NUM_TAPS) {
		/* Have to have enough taps to start with */
		if (ec->maxTy > ec->Ts) {
			/* There is no near-end speech detected */
			if (!ec->hangt) {
				/* We're not in the hang-time from the end of near-end speech */
				if ((ec->Ly > 1024) && ((ec->Ly / Lu) < MIN_QUALITY)) {
#ifdef OPTIMIZEDIV
					/* We both have enough signal on the transmit   */
					nsuppr = (suppr << 18) / ec->Ly;
				
					if (nsuppr > 32767)
						nsuppr = 32767;
					if (nsuppr < -32768)
						nsuppr =  -32768;
			
					nsuppr /= ec->Ly;
#else					
					/* We both have enough signal on the transmit   */
					nsuppr = (suppr << 16) / ec->Ly;
				
					if (nsuppr > 32767)
						nsuppr = 32767;
					if (nsuppr < -32768)
						nsuppr =  -32768;
			
#endif					
			
					/* Update coefficients */
					pos = ec->cpos;
#ifdef MIN_UPDATE
					totalupd =0;
#endif					
					for (x=0;x<NUM_TAPS;x++) {
						register int adj;
						adj = ec->y[pos] * nsuppr;
#ifndef OPTIMIZEDIV
						adj /= ec->Ly;
						adj >>= BETA_POW;
#else						
						adj >>= BETA_POW + 2;
#endif						
#ifdef PASSPOS
						if (ec->pass > PASSPOS)
							printf("tx: %d, old %d: %d, adj %d, nsuppr: %d, power: %d\n", tx, x, ec->a[x], adj, nsuppr, ec->Ly);
#endif							
						ec->a[x] += adj;
#ifdef MIN_UPDATE
						totalupd += abs(adj);
#endif						
						/* Go backwards in time and loop around circular buffer */
						pos = (pos - 1) & TAP_MASK;
					}
#ifdef MIN_UPDATE
					/* If we didn't update at least this much, delay for many more taps */
					if (totalupd < MIN_UPDATE) {
						ec->hangt += MIN_SKIP;
					}
#endif						
				} 
					
			}
		} else
			/* Near end speech detected */
			ec->hangt = HANG_T;
	} 

	/* Save supression and absolute values */
	supprabs = abs(suppr);
	oldsupprabs = ec->u_abs[ec->cpos];
	ec->u[ec->cpos] = suppr;
	ec->u_abs[ec->cpos] = supprabs;

	/* Update tx power */
	ec->Ly += (txabs >> SIGMA_LY_POW) - (oldtxabs >> SIGMA_LY_POW);

	/* Update rx power */
	ec->Lu += (supprabs  >> SIGMA_LU_POW) - (oldsupprabs >> SIGMA_LU_POW);

	/* Short term power of tx */
	ec->Ty[ec->cpos] = ec->Ty[(ec->cpos - 1) & TAP_MASK] + 
		((txabs >> SIGMA_YT_POW ) - (oldtxabs >> SIGMA_YT_POW));
	
	/* Keep track of highest */
	if (ec->lastmax == ec->cpos) {
		register int maxTy = 0;
		/* Have to loop through and find the new highest since our old highest expired */
		/* Estimate echo */
		pos = ec->cpos;
		for (x=0;x<NUM_TAPS;x++) {
			if (ec->Ty[pos] > maxTy)
				maxTy = ec->Ty[pos];
			/* Go backwards in time and loop around circular buffer */
			pos = (pos - 1) & TAP_MASK;
		}
		ec->maxTy = maxTy;
	} else {
		/* Just keep the highest */
		if (ec->Ty[ec->cpos] > ec->maxTy) {
			ec->maxTy = ec->Ty[ec->cpos];
			ec->lastmax = ec->cpos;
		}
	}
	ec->Ts += (rxabs >> SIGMA_ST_POW) - (oldrxabs >> SIGMA_ST_POW) ;

	/* Increment position memory */
	ec->cpos = (ec->cpos + 1 ) & TAP_MASK;
	
	return suppr;
}

static inline int echo_can_traintap(echo_can_state_t *ec, int pos, short val)
{
	/* Reset hang counter to avoid adjustments after
	   initial forced training */
	ec->hangt = NUM_TAPS << 1;
	if (pos >= NUM_TAPS)
		return 1;
	ec->a[pos] = val << 17;
	if (++pos >= NUM_TAPS)
		return 1;
	return 0;
}

#endif
