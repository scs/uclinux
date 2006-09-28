/*
 * ########################################################################
 *
 *  This program is free software; you can distribute it and/or modify it
 *  under the terms of the GNU General Public License (Version 2) as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * ########################################################################
*/

/*
** drivers/char/bf5xx_timers.c - derived from bf53x_timers.c
**  This file contains General Purpose Timer functions for BF5xx
**
**  Copyright (C) 2005 John DeHority
**  Copyright (C) 2006 Hella Aglaia GmbH (awe@aglaia-gmbh.de)
**
*/

#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/io.h>
#include <asm/blackfin.h>
#include <asm/bf5xx_timers.h>

#undef assert
#ifndef BFIN_TIMER_DEBUG
#define assert(expr) do {} while(0)
#else
#define assert(expr)                        \
	if (!(expr)) {                      \
		printk("Assertion failed! %s, %s, %s, line=%d \n",  \
			#expr, __FILE__,__FUNCTION__,__LINE__);     \
	}
#endif

#define BFIN_TIMER_NUM_GROUP  (BFIN_TIMER_OCTET(MAX_BLACKFIN_GPTIMERS - 1) + 1)

typedef struct {
	short config;
	short pad;
	int   counter;
	int   period;
	int   width;
} GPTIMER_timer_regs;

typedef struct {
	short enable;
	short pad0;
	short disable;
	short pad1;
	long  status;
} GPTIMER_group_regs;

static volatile GPTIMER_timer_regs *const timer_regs[MAX_BLACKFIN_GPTIMERS] = {
	(GPTIMER_timer_regs*)TIMER0_CONFIG,
	(GPTIMER_timer_regs*)TIMER1_CONFIG,
	(GPTIMER_timer_regs*)TIMER2_CONFIG,
#if (MAX_BLACKFIN_GPTIMERS > 3)
	(GPTIMER_timer_regs*)TIMER3_CONFIG,
	(GPTIMER_timer_regs*)TIMER4_CONFIG,
	(GPTIMER_timer_regs*)TIMER5_CONFIG,
	(GPTIMER_timer_regs*)TIMER6_CONFIG,
	(GPTIMER_timer_regs*)TIMER7_CONFIG,
#endif
#if (MAX_BLACKFIN_GPTIMERS > 8)
	(GPTIMER_timer_regs*)TIMER8_CONFIG,
	(GPTIMER_timer_regs*)TIMER9_CONFIG,
	(GPTIMER_timer_regs*)TIMER10_CONFIG,
	(GPTIMER_timer_regs*)TIMER11_CONFIG,
#endif
};

static volatile GPTIMER_group_regs *const group_regs[BFIN_TIMER_NUM_GROUP] = {
	(GPTIMER_group_regs*)TIMER0_GROUP_REG,
#if (MAX_BLACKFIN_GPTIMERS > 8)
	(GPTIMER_group_regs*)TIMER8_GROUP_REG,
#endif
};

static int const dis_mask[MAX_BLACKFIN_GPTIMERS] = {
	TIMER_STATUS_TRUN0,
	TIMER_STATUS_TRUN1,
	TIMER_STATUS_TRUN2,
#if (MAX_BLACKFIN_GPTIMERS > 3)
	TIMER_STATUS_TRUN3,
	TIMER_STATUS_TRUN4,
	TIMER_STATUS_TRUN5,
	TIMER_STATUS_TRUN6,
	TIMER_STATUS_TRUN7,
#endif
#if (MAX_BLACKFIN_GPTIMERS > 8)
	TIMER_STATUS_TRUN8,
	TIMER_STATUS_TRUN9,
	TIMER_STATUS_TRUN10,
	TIMER_STATUS_TRUN11,
#endif
};

static int const irq_mask[MAX_BLACKFIN_GPTIMERS] = {
	TIMER_STATUS_TIMIL0,
	TIMER_STATUS_TIMIL1,
	TIMER_STATUS_TIMIL2,
#if (MAX_BLACKFIN_GPTIMERS > 3)
	TIMER_STATUS_TIMIL3,
	TIMER_STATUS_TIMIL4,
	TIMER_STATUS_TIMIL5,
	TIMER_STATUS_TIMIL6,
	TIMER_STATUS_TIMIL7,
#endif
#if (MAX_BLACKFIN_GPTIMERS > 8)
	TIMER_STATUS_TIMIL8,
	TIMER_STATUS_TIMIL9,
	TIMER_STATUS_TIMIL10,
	TIMER_STATUS_TIMIL11,
#endif
};

#define AUTHOR "Axel Weiss (awe@aglaia-gmbh.de)"
#define DESCRIPTION "bf5xx-gptimers api, implemented as a standalone kernel component"
#define LICENSE "GPL"

MODULE_AUTHOR     (AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_LICENSE    (LICENSE);


/*******************************************************************************
*	GP_TIMER API's
*******************************************************************************/

void set_gptimer_pwidth(int timer_id, int value){
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	timer_regs[timer_id]->width = value;
	__builtin_bfin_ssync();
}

int get_gptimer_pwidth(int timer_id){
	int	value;
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	value = timer_regs[timer_id]->width;
	return value;
}

void set_gptimer_period(int timer_id, int period){
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	timer_regs[timer_id]->period = period;
	__builtin_bfin_ssync();
}

int get_gptimer_period(int timer_id){
	int	value;
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	value = timer_regs[timer_id]->period;
	return value;
}

int get_gptimer_count(int timer_id){
	int	value;
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	value = timer_regs[timer_id]->counter;
	return value;
}

int get_gptimer_status(int octet){
	assert(octet < BFIN_TIMER_NUM_GROUP);
	return group_regs[octet]->status;
}

void set_gptimer_status(int octet, int value){
	assert(octet < BFIN_TIMER_NUM_GROUP);
	group_regs[octet]->status = value;
	__builtin_bfin_ssync();
}

short get_gptimer_intr(int timer_id){
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	return (group_regs[BFIN_TIMER_OCTET(timer_id)]->status & irq_mask[timer_id]) ? 1 : 0;
}


void set_gptimer_config(int timer_id, short config){
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	timer_regs[timer_id]->config = config;
	__builtin_bfin_ssync();
}

short get_gptimer_config(int timer_id){
	int value;
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	value = timer_regs[timer_id]->config;
	return value;
}

void enable_gptimers(short mask){
	int i;
	assert( (mask & ~BLACKFIN_GPTIMER_IDMASK) == 0);
	for (i=0; i<BFIN_TIMER_NUM_GROUP; ++i){
		group_regs[i]->enable = mask & 0xFF;
		mask >>= 8;
	}
	__builtin_bfin_ssync();
}

void disable_gptimers(short mask){
	int i;
	short m = mask;
	assert( (mask & ~BLACKFIN_GPTIMER_IDMASK) == 0);
	for (i=0; i<BFIN_TIMER_NUM_GROUP; ++i){
		group_regs[i]->disable = m & 0xFF;
		m >>= 8;
	}
	for (i=0; i<MAX_BLACKFIN_GPTIMERS; ++i){
		if (mask & (1 << i)){
			group_regs[BFIN_TIMER_OCTET(i)]->status |= dis_mask[i];
		}
	}
	__builtin_bfin_ssync();
}

void set_gptimer_pulse_hi(int timer_id){
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	timer_regs[timer_id]->config |= TIMER_PULSE_HI;
	__builtin_bfin_ssync();
}

void clear_gptimer_pulse_hi(int timer_id){
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	timer_regs[timer_id]->config &= ~TIMER_PULSE_HI;
	__builtin_bfin_ssync();
}

short get_enabled_timers(void){
	int i;
	short result = 0;
	for (i=0; i<BFIN_TIMER_NUM_GROUP; ++i){
		result |= group_regs[i]->enable << (i << 3);
	}
	return result;
}

EXPORT_SYMBOL(set_gptimer_pwidth);
EXPORT_SYMBOL(get_gptimer_pwidth);
EXPORT_SYMBOL(set_gptimer_period);
EXPORT_SYMBOL(get_gptimer_period);
EXPORT_SYMBOL(get_gptimer_count);
EXPORT_SYMBOL(get_gptimer_intr);
EXPORT_SYMBOL(set_gptimer_config);
EXPORT_SYMBOL(get_gptimer_config);
EXPORT_SYMBOL(set_gptimer_pulse_hi);
EXPORT_SYMBOL(clear_gptimer_pulse_hi);
EXPORT_SYMBOL(enable_gptimers);
EXPORT_SYMBOL(disable_gptimers);
EXPORT_SYMBOL(get_enabled_timers);
EXPORT_SYMBOL(get_gptimer_status);
EXPORT_SYMBOL(set_gptimer_status);

