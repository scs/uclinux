/*
 * File:         drivers/char/bfin_bf53x_timers.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:  This file contains General Purpose Timer functions
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2005 John DeHority
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/kernel.h>
#include <asm/io.h>

#include <asm/blackfin.h>
#include <asm/bf53x_timers.h>

#define SSYNC() __builtin_bfin_ssync()

#ifndef BFIN_TIMER_DEBUG
# define ASSERT(expr) do {} while (0)
#else
# define ASSERT(expr) \
	do { \
		if (!(expr)) \
			printk(KERN_DEBUG "%s:%s():%d: assertion failed: %s\n", \
			       __FILE__, __FUNCTION__, __LINE__, #expr); \
	} while (0)
#endif

static GPTIMER_registers *gptimers = (GPTIMER_registers *)TIMER0_CONFIG;

/*******************************************************************************
*	GP_TIMER API's 
*******************************************************************************/

void set_gptimer_pwidth(int timer_id, int value)
{
	short mask;

	mask = 1 << timer_id;

	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	gptimers->a_timer[timer_id].width = value;
	SSYNC();
}

int get_gptimer_pwidth(int timer_id)
{
	int value;

	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	value = gptimers->a_timer[timer_id].width;

	return value;
}

void set_gptimer_period(int timer_id, int period)
{
	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	gptimers->a_timer[timer_id].period = period;
	SSYNC();
}


int get_gptimer_period(int timer_id)
{
	int value;

	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	value = gptimers->a_timer[timer_id].period;
	return value;
}

int get_gptimer_count(int timer_id)
{
	int value;

	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	value = gptimers->a_timer[timer_id].counter;
	return value;
}

/*
** get_gptimer_status()
** 
** return:  status
*/

int get_gptimer_status(void)
{
	int value;

	value = (int) gptimers->status;
	return value;
}


/*
** get_gptimer_intr()
** 
** return:  0 - timer clear (no interrupt)
**          1 - timer interrupted
*/

short get_gptimer_intr(int timer_id)
{
	short mask = 0;
	short cur_status;

	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	mask = 1 << timer_id;
	cur_status = gptimers->status;
	return ((cur_status & mask) ? 1 : 0);
}

void set_gptimer_config(int timer_id, short config)
{
	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	gptimers->a_timer[timer_id].config = config;
	SSYNC();
}


short get_gptimer_config(int timer_id)
{
	int value;

	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	value = gptimers->a_timer[timer_id].config;
	return value;
}


void enable_gptimers(short mask)
{
	unsigned short regdata;

	//printk(KERN_DEBUG "enable timers write 0x%04hX at 0x%08X\n", mask, &gptimers->enable);
	regdata = gptimers->enable;
	regdata |= mask;
	gptimers->enable = regdata;
	SSYNC();
}

void disable_gptimers(short mask)
{
	unsigned short regdata;

	regdata = gptimers->enable;
	regdata |= mask;
	gptimers->disable = regdata;
	SSYNC();
}

void set_gptimer_pulse_hi(int timer_id)
{
	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	gptimers->a_timer[timer_id].config |= TIMER_PULSE_HI;
	SSYNC();
}

void clear_gptimer_pulse_hi(int timer_id)
{
	ASSERT(timer_id < MAX_BLACKFIN_GPTIMERS);

	gptimers->a_timer[timer_id].config &= ~TIMER_PULSE_HI;
	SSYNC();
}


/*
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
*/
