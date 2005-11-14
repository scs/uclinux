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
** drivers/char/bf533_timers.c
**  This file contains General Purpose Timer functions for BF533
**
**  Copyright (C) 2005 John DeHority
**
*/

#include <asm/bf533_timers.h>
#include <asm/blackfin.h>

static GPTIMER_registers *gptimers = (GPTIMER_registers *)TIMER0_CONFIG;

/*******************************************************************************
*	GP_TIMER API's 
*******************************************************************************/

void 	
set_gptimer_pwidth		(int timer_id, int width)
{
	short	mask = 0;

	mask  = 1 << timer_id;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	
	gptimers->a_timer[timer_id].width = width;
	SSYNC();
}


int	
get_gptimer_pwidth		(int timer_id)
{
	int	value;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	value = gptimers->a_timer[timer_id].width;
	return value;
}

void 	
set_gptimer_period		(int timer_id, int period)
{
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );
	
	gptimers->a_timer[timer_id].period = period;
	SSYNC();
}


int	
get_gptimer_period		(int timer_id)
{
	int	value;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	value = gptimers->a_timer[timer_id].period;
	return value;
}

int	
get_gptimer_count(int timer_id)
{
	int	value;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	value = gptimers->a_timer[timer_id].counter;
	return value;
}

/*
** get_gptimer_running()
** 
** return:  0 - timer stopped
**          1 - timer running
*/

short	
get_gptimer_running(int	timer_id)
{
	short mask = 0;
	short cur_status;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	mask = TIMER_STATUS_TRUN0 << timer_id;
	cur_status = gptimers->status;
	return ( cur_status & mask ) ? 1 : 0;
}

	
/*
** get_gptimer_intr()
** 
** return:  0 - timer clear (no interrupt)
**          1 - timer interrupted
*/

short	
get_gptimer_intr(int	timer_id)
{
	short mask = 0;
	short cur_status;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	mask = 1 << timer_id;
	cur_status = gptimers->status;
	return ( cur_status & mask ) ? 1 : 0;
}

	
void	
set_gptimer_config	(int timer_id, short config)
{
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	gptimers->a_timer[timer_id].config = config;
	SSYNC();
}


short	
get_gptimer_config(int timer_id)
{
	int	value;

	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	value = gptimers->a_timer[timer_id].config;
	return value;
}


void	
enable_gptimers(short mask)
{
	gptimers->enable = mask;
	SSYNC();
}


void	
disable_gptimers(short mask)
{
	gptimers->disable = mask;
	SSYNC();
}

void    
set_gptimer_pulse_hi(int timer_id)
{
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	gptimers->a_timer[timer_id].config |= TIMER_PULSE_HI;
	SSYNC();
}

void    
clear_gptimer_pulse_hi  (int timer_id)
{
	assert( timer_id < MAX_BLACKFIN_GPTIMERS );

	gptimers->a_timer[timer_id].config &= ~TIMER_PULSE_HI;
	SSYNC();
}


/**********
	EXPORT_SYMBOL(set_gptimer_pwidth);
	EXPORT_SYMBOL(get_gptimer_pwidth);
	EXPORT_SYMBOL(set_gptimer_period);
	EXPORT_SYMBOL(get_gptimer_period);
	EXPORT_SYMBOL(get_gptimer_count);
	EXPORT_SYMBOL(get_gptimer_running);
	EXPORT_SYMBOL(get_gptimer_intr);
	EXPORT_SYMBOL(set_gptimer_config);
	EXPORT_SYMBOL(get_gptimer_config);
	EXPORT_SYMBOL(set_gptimer_pulse_hi);
	EXPORT_SYMBOL(clear_gptimer_pulse_hi);
	EXPORT_SYMBOL(enable_gptimers);
	EXPORT_SYMBOL(disable_gptimers);
***********/

