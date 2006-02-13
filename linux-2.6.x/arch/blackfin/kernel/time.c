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
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http:    //blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/module.h>
#include <linux/profile.h>

#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/bf5xx_rtc.h>

#define	TICK_SIZE (tick_nsec / 1000)

u64 jiffies_64 = INITIAL_JIFFIES;

EXPORT_SYMBOL(jiffies_64);

static void time_sched_init(irqreturn_t(*timer_routine)
		      (int, void *, struct pt_regs *));
static unsigned long gettimeoffset(void);
extern unsigned long wall_jiffies;
extern int setup_irq(unsigned int, struct irqaction *);
inline static void do_leds(void);

extern u_long get_cclk(void);

#define TIME_SCALE 100
#define CLOCKS_PER_JIFFY (get_cclk() / HZ / TIME_SCALE)

#if (defined(CONFIG_BFIN_ALIVE_LED) || defined(CONFIG_BFIN_IDLE_LED))
void __init init_leds(void)
{
	unsigned int tmp = 0;

#if defined(CONFIG_BFIN_ALIVE_LED)
	/* config pins as output. */
	tmp = *(volatile unsigned short *)CONFIG_BFIN_ALIVE_LED_DPORT;
	__builtin_bfin_ssync();
	*(volatile unsigned short *)CONFIG_BFIN_ALIVE_LED_DPORT =
	    tmp | CONFIG_BFIN_ALIVE_LED_PIN;
	__builtin_bfin_ssync();

	/*      First set led be off */
	tmp = *(volatile unsigned short *)CONFIG_BFIN_ALIVE_LED_PORT;
	__builtin_bfin_ssync();
	*(volatile unsigned short *)CONFIG_BFIN_ALIVE_LED_PORT = tmp | CONFIG_BFIN_ALIVE_LED_PIN;	/* light off */
	__builtin_bfin_ssync();
#endif

#if defined(CONFIG_BFIN_IDLE_LED)
	/* config pins as output. */
	tmp = *(volatile unsigned short *)CONFIG_BFIN_IDLE_LED_DPORT;
	__builtin_bfin_ssync();
	*(volatile unsigned short *)CONFIG_BFIN_IDLE_LED_DPORT =
	    tmp | CONFIG_BFIN_IDLE_LED_PIN;
	__builtin_bfin_ssync();

	/*      First set led be off */
	tmp = *(volatile unsigned short *)CONFIG_BFIN_IDLE_LED_PORT;
	__builtin_bfin_ssync();
	*(volatile unsigned short *)CONFIG_BFIN_IDLE_LED_PORT = tmp | CONFIG_BFIN_IDLE_LED_PIN;	/* light off */
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
	tmp = *(volatile unsigned short *)CONFIG_BFIN_ALIVE_LED_PORT;
	__builtin_bfin_ssync();

	if (flag)
		tmp &= ~CONFIG_BFIN_ALIVE_LED_PIN;	/* light on */
	else
		tmp |= CONFIG_BFIN_ALIVE_LED_PIN;	/* light off */

	*(volatile unsigned short *)CONFIG_BFIN_ALIVE_LED_PORT = tmp;
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

static void
time_sched_init(irqreturn_t(*timer_routine) (int, void *, struct pt_regs *))
{
	/* power up the timer, but don't enable it just yet */
	*pTCNTL = 1;
	__builtin_bfin_csync();

	/*
	 * the TSCALE prescaler counter.
	 */
	*pTSCALE = (TIME_SCALE - 1);

	*pTCOUNT = *pTPERIOD = (CLOCKS_PER_JIFFY - 1);

	/* now enable the timer */
	__builtin_bfin_csync();

	*pTCNTL = 7;

	bfin_timer_irq.handler = timer_routine;
	/* call setup_irq instead of request_irq because request_irq calls kmalloc which has not been initialized yet */
	setup_irq(IRQ_CORETMR, &bfin_timer_irq);
}

static unsigned long gettimeoffset(void)
{
	unsigned long offset;
	unsigned long clocks_per_jiffy = CLOCKS_PER_JIFFY;	/* call get_cclk() only once */

	offset =
	    tick_usec * (clocks_per_jiffy - (*pTCOUNT + 1)) / clocks_per_jiffy;

	/* Check if we just wrapped the counters and maybe missed a tick */
	if ((*pILAT & (1 << IRQ_CORETMR)) && (offset < (100000 / HZ / 2)))
		offset += (1000000 / HZ);

	return offset;
}

static inline int set_rtc_mmss(unsigned long nowtime)
{
	return 0;
}

static inline void do_profile(struct pt_regs *regs)
{
/*
 * temperary remove code to do profile, because the arch change of the profile in the kernel 2.6.12
 */
#if 0
	unsigned long pc;

	pc = regs->pc;

	profile_hook(regs);

	if (prof_buffer && current->pid) {
		extern int _stext;
		pc -= (unsigned long)&_stext;
		pc >>= prof_shift;
		if (pc < prof_len)
			++prof_buffer[pc];
		else
			/*
			 * Don't ignore out-of-bounds PC values silently,
			 * put them into the last histogram slot, so if
			 * present, they will show up as a sharp peak.
			 */
			++prof_buffer[prof_len - 1];
	}
#endif
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

	if ((time_status & STA_UNSYNC) == 0 &&
	    xtime.tv_sec > last_rtc_update + 660 &&
	    (xtime.tv_nsec / 1000) >= 500000 - ((unsigned)TICK_SIZE) / 2 &&
	    (xtime.tv_nsec / 1000) <= 500000 + ((unsigned)TICK_SIZE) / 2) {
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
		if (lost)
			usec += lost * (1000000 / HZ);
		sec = xtime.tv_sec;
		usec += (xtime.tv_nsec / 1000);
	}
	while (read_seqretry_irqrestore(&xtime_lock, seq, flags));

	while (usec >= 1000000) {
		usec -= 1000000;
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
	nsec -= (gettimeoffset() * 1000);

	wtm_sec = wall_to_monotonic.tv_sec + (xtime.tv_sec - sec);
	wtm_nsec = wall_to_monotonic.tv_nsec + (xtime.tv_nsec - nsec);

	set_normalized_timespec(&xtime, sec, nsec);
	set_normalized_timespec(&wall_to_monotonic, wtm_sec, wtm_nsec);

	time_adjust = 0;	/* stop active adjtime() */
	time_status |= STA_UNSYNC;
	time_maxerror = NTP_PHASE_LIMIT;
	time_esterror = NTP_PHASE_LIMIT;

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
	return (unsigned long long)jiffies *(1000000000 / HZ);
}

EXPORT_SYMBOL(do_settimeofday);
