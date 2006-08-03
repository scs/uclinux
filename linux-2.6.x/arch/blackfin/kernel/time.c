/*
 * File:         arch/blackfin/kernel/time.c
 * Based on:     none - original work
 * Author:
 *
 * Created:
 * Description:  This file contains the bfin-specific time handling details.
 *               Most of the stuff is located in the machine specific files.
 *
 * Rev:          $Id$
 *
 * Modified:
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

#include <linux/module.h>
#include <linux/profile.h>
#include <linux/interrupt.h>
#include <linux/time.h>

#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/bf5xx_rtc.h>

/* This is an NTP setting */
#define	TICK_SIZE (tick_nsec / 1000)

static void time_sched_init(irqreturn_t (*timer_routine)
		      (int, void *, struct pt_regs *));
static unsigned long gettimeoffset(void);
extern int setup_irq(unsigned int, struct irqaction *);
inline static void do_leds(void);

#if (defined(CONFIG_BFIN_ALIVE_LED) || defined(CONFIG_BFIN_IDLE_LED))
void __init init_leds(void)
{
	unsigned int tmp = 0;

#if defined(CONFIG_BFIN_ALIVE_LED)
	/* config pins as output. */
	tmp = bfin_read_CONFIG_BFIN_ALIVE_LED_DPORT();
	__builtin_bfin_ssync();
	bfin_write_CONFIG_BFIN_ALIVE_LED_DPORT(tmp | CONFIG_BFIN_ALIVE_LED_PIN);
	__builtin_bfin_ssync();

	/*      First set led be off */
	tmp = bfin_read_CONFIG_BFIN_ALIVE_LED_PORT();
	__builtin_bfin_ssync();
	bfin_write_CONFIG_BFIN_ALIVE_LED_PORT(tmp | CONFIG_BFIN_ALIVE_LED_PIN);	/* light off */
	__builtin_bfin_ssync();
#endif

#if defined(CONFIG_BFIN_IDLE_LED)
	/* config pins as output. */
	tmp = bfin_read_CONFIG_BFIN_IDLE_LED_DPORT();
	__builtin_bfin_ssync();
	bfin_write_CONFIG_BFIN_IDLE_LED_DPORT(tmp | CONFIG_BFIN_IDLE_LED_PIN);
	__builtin_bfin_ssync();

	/*      First set led be off */
	tmp = bfin_read_CONFIG_BFIN_IDLE_LED_PORT();
	__builtin_bfin_ssync();
	bfin_write_CONFIG_BFIN_IDLE_LED_PORT(tmp | CONFIG_BFIN_IDLE_LED_PIN);	/* light off */
	__builtin_bfin_ssync();
#endif

}
#else
inline void __init init_leds(void)
{
}
#endif

#if defined(CONFIG_BFIN_ALIVE_LED)
inline static void do_leds(void)
{
	static unsigned int count = 50;
	static int flag = 0;
	unsigned short tmp = 0;

	if (--count == 0) {
		count = 50;
		flag = ~flag;
	}
	tmp = bfin_read_CONFIG_BFIN_ALIVE_LED_PORT();
	__builtin_bfin_ssync();

	if (flag)
		tmp &= ~CONFIG_BFIN_ALIVE_LED_PIN;	/* light on */
	else
		tmp |= CONFIG_BFIN_ALIVE_LED_PIN;	/* light off */

	bfin_write_CONFIG_BFIN_ALIVE_LED_PORT(tmp);
	__builtin_bfin_ssync();

}
#else
inline static void do_leds(void)
{
}
#endif

static struct irqaction bfin_timer_irq = {
	.name = "BFIN Timer Tick",
	.flags = SA_INTERRUPT
};

/*
 * The way that the Blackfin core timer works is:
 *  - CCLK is divided by a programmable 8-bit pre-scaler (TSCALE)
 *  - Every time TSCALE ticks, a 32bit is counted down (TCOUNT)
 * 
 * If you take the fastest clock (1ns, or 1GHz to make the math work easier)
 *    10ms is 10,000,000 clock ticks, which fits easy into a 32-bit counter
 *    (32 bit counter is 4,294,967,296ns or 4.2 seconds) so, we don't need 
 *    to use TSCALE, and program it to zero (which is pass CCLK through).
 *    If you feel like using it, try to keep HZ * TIMESCALE to some
 *    value that divides easy (like power of 2).
 */

#define TIME_SCALE 1

static void
time_sched_init(irqreturn_t(*timer_routine) (int, void *, struct pt_regs *))
{
	u32 tcount;

	/* power up the timer, but don't enable it just yet */
	bfin_write_TCNTL(1);
	__builtin_bfin_csync();

	/*
	 * the TSCALE prescaler counter.
	 */
	bfin_write_TSCALE((TIME_SCALE - 1));

	tcount = ((get_cclk() / (HZ * TIME_SCALE)) - 1);
	bfin_write_TPERIOD(tcount);
	bfin_write_TCOUNT(tcount);

	/* now enable the timer */
	__builtin_bfin_csync();

	bfin_write_TCNTL(7);

	bfin_timer_irq.handler = timer_routine;
	/* call setup_irq instead of request_irq because request_irq calls kmalloc which has not been initialized yet */
	setup_irq(IRQ_CORETMR, &bfin_timer_irq);
}

/*
 * Should return useconds since last timer tick
 */
static unsigned long gettimeoffset(void)
{
	unsigned long offset;
	unsigned long clocks_per_jiffy ;

	clocks_per_jiffy =  bfin_read_TPERIOD() ;
	offset =  (clocks_per_jiffy - bfin_read_TCOUNT())  / (( (clocks_per_jiffy + 1) *  HZ * TIME_SCALE) /  USEC_PER_SEC ) ;

	/* Check if we just wrapped the counters and maybe missed a tick */
	if ((bfin_read_ILAT() & (1 << IRQ_CORETMR)) && (offset < (100000 / HZ / 2)))
		offset += ( USEC_PER_SEC / HZ);


	return offset;
}

static inline int set_rtc_mmss(unsigned long nowtime)
{
	return 0;
}

/*
 * timer_interrupt() needs to keep up the real-time clock,
 * as well as call the "do_timer()" routine every clocktick
 */
irqreturn_t timer_interrupt(int irq, void *dummy, struct pt_regs *regs)
{
	/* last time the cmos clock got updated */
	static long last_rtc_update = 0;

	write_seqlock(&xtime_lock);

	do_timer(regs);
	do_leds();

#ifndef CONFIG_SMP
	update_process_times(user_mode(regs));
#endif
	profile_tick(CPU_PROFILING, regs);

	/*
	 * If we have an externally synchronized Linux clock, then update
	 * CMOS clock accordingly every ~11 minutes. Set_rtc_mmss() has to be
	 * called as close as possible to 500 ms before the new second starts.
	 */

	if (ntp_synced() &&
	    xtime.tv_sec > last_rtc_update + 660 &&
	    (xtime.tv_nsec /  NSEC_PER_USEC ) >= 500000 - ((unsigned)TICK_SIZE) / 2 &&
	    (xtime.tv_nsec /  NSEC_PER_USEC ) <= 500000 + ((unsigned)TICK_SIZE) / 2) {
		if (set_rtc_mmss(xtime.tv_sec) == 0)
			last_rtc_update = xtime.tv_sec;
		else
			/* Do it again in 60s. */
			last_rtc_update = xtime.tv_sec - 600;
	}
	write_sequnlock(&xtime_lock);
	return IRQ_HANDLED;
}

void time_init(void)
{
#ifdef CONFIG_BFIN_HAVE_RTC
	time_t secs_since_1970 = 0;

	/* Initialize the RTC sub-system */
	rtc_init();
	/* Retrieve calendar time (secs since Jan 1970) */
	rtc_get(&secs_since_1970);
#else
	time_t secs_since_1970 = (365 * 35 + 9) * 24 * 3600;	/* 1 Jan 2005 */
#endif
	/* Initialize xtime. From now on, xtime is updated with timer interrupts */
	xtime.tv_sec = secs_since_1970;
	xtime.tv_nsec = 0;

	wall_to_monotonic.tv_sec = -xtime.tv_sec;

	time_sched_init(timer_interrupt);
}

void do_gettimeofday(struct timeval *tv)
{
	unsigned long flags;
	unsigned long lost, seq;
	unsigned long usec, sec;

	do {
		seq = read_seqbegin_irqsave(&xtime_lock, flags);
		usec = gettimeoffset();
		lost = jiffies - wall_jiffies;
		if (unlikely(lost))
			usec += lost * ( USEC_PER_SEC / HZ); 
		sec = xtime.tv_sec;
		usec += (xtime.tv_nsec /  NSEC_PER_USEC );
	}
	while (read_seqretry_irqrestore(&xtime_lock, seq, flags));

	while (usec >=  USEC_PER_SEC) {
		usec -=  USEC_PER_SEC;
		sec++;
	}

	tv->tv_sec = sec;
	tv->tv_usec = usec;
}

EXPORT_SYMBOL(do_gettimeofday);

int do_settimeofday(struct timespec *tv)
{
	time_t wtm_sec, sec = tv->tv_sec;
	long wtm_nsec, nsec = tv->tv_nsec;

	if ((unsigned long)tv->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	write_seqlock_irq(&xtime_lock);
	/*
	 * This is revolting. We need to set the xtime.tv_usec
	 * correctly. However, the value in this location is
	 * is value at the last tick.
	 * Discover what correction gettimeofday
	 * would have done, and then undo it!
	 */
	nsec -= (gettimeoffset() *  NSEC_PER_USEC );

	wtm_sec = wall_to_monotonic.tv_sec + (xtime.tv_sec - sec);
	wtm_nsec = wall_to_monotonic.tv_nsec + (xtime.tv_nsec - nsec);

	set_normalized_timespec(&xtime, sec, nsec);
	set_normalized_timespec(&wall_to_monotonic, wtm_sec, wtm_nsec);

	ntp_clear();

	write_sequnlock_irq(&xtime_lock);
	clock_was_set();

	/*
	 *  rtc_set() busy-waits up to a second (the next tick of the RTC)
	 *  for completion of the write.
	 *  We release xtime_lock before updating the RTC so as not to
	 *  lock out the timer_interrupt() routine which also acquires
	 *  xtime_lock.  Locking out timer_interrupt() loses ticks!
	 */
#ifdef CONFIG_BFIN_HAVE_RTC
	rtc_set(sec);
#endif

	return 0;
}

/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	return (unsigned long long)jiffies *(NSEC_PER_SEC / HZ);
}

EXPORT_SYMBOL(do_settimeofday);
