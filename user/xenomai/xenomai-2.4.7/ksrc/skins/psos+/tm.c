/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <nucleus/registry.h>
#include <psos+/task.h>
#include <psos+/tm.h>

static const u_long tm_secbyday = 24 * 60 * 60;

static const u_long tm_secbyhour = 60 * 60;

static const u_long tm_secbymin = 60;

void psostm_init(void)
{
}

void psostm_cleanup(void)
{
}

void tm_destroy_internal(psostm_t *tm)
{
	spl_t s;

	/* Internal timers are automatically removed by exiting tasks,
	 * so we don't need any resource cleanup handling here. */

	xnlock_get_irqsave(&nklock, s);
	removegq(&tm->owner->alarmq, tm);
	xntimer_destroy(&tm->timerbase);
#ifdef CONFIG_XENO_OPT_REGISTRY
	if (tm->handle)
		xnregistry_remove(tm->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
	psos_mark_deleted(tm);
	xnlock_put_irqrestore(&nklock, s);

	xnfree(tm);
}

static void tm_evpost_handler(xntimer_t *timer)
{
	psostm_t *tm = container_of(timer, psostm_t, timerbase);

	ev_send((u_long)tm->owner, tm->data);

	if (xntimer_interval(&tm->timerbase) == XN_INFINITE)
		tm_destroy_internal(tm);
}

static u_long tm_start_event_timer(u_long ticks,
				   u_long interval, u_long events, u_long *tmid)
{
	psostm_t *tm;
	spl_t s;

	tm = (psostm_t *)xnmalloc(sizeof(*tm));

	if (!tm)
		return ERR_NOSEG;

	inith(&tm->link);
	tm->data = events;
	tm->owner = psos_current_task();
	*tmid = (u_long)tm;

	xntimer_init(&tm->timerbase, psos_tbase, tm_evpost_handler);
	tm->magic = PSOS_TM_MAGIC;

	xnlock_get_irqsave(&nklock, s);
	appendgq(&tm->owner->alarmq, tm);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		static unsigned long tm_ids;
		u_long err;

		sprintf(tm->name, "anon_evtm%lu", tm_ids++);

		err = xnregistry_enter(tm->name, tm, &tm->handle, 0);

		if (err) {
			tm->handle = XN_NO_HANDLE;
			tm_cancel((u_long)tm);
			return err;
		}
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xnlock_get_irqsave(&nklock, s);
	xntimer_start(&tm->timerbase, ticks, interval, XN_RELATIVE);
	xnlock_put_irqrestore(&nklock, s);

	return SUCCESS;
}

#ifdef CONFIG_XENO_OPT_PERVASIVE

static void tm_sigpost_handler(xntimer_t *timer)
{
	psostm_t *tm = container_of(timer, psostm_t, timerbase);

	xnshadow_send_sig(&tm->owner->threadbase, tm->data, 1);

	if (xntimer_interval(&tm->timerbase) == XN_INFINITE)
		tm_destroy_internal(tm);
}

u_long tm_start_signal_timer(u_long ticks,
			     u_long interval, int signo, u_long *tmid)
{
	static unsigned long tm_ids;
	psostm_t *tm;
	u_long err;
	spl_t s;

	tm = (psostm_t *)xnmalloc(sizeof(*tm));

	if (!tm)
		return ERR_NOSEG;

	inith(&tm->link);
	tm->data = signo;
	tm->owner = psos_current_task();
	*tmid = (u_long)tm;

	xntimer_init(&tm->timerbase, psos_tbase, tm_sigpost_handler);
	tm->magic = PSOS_TM_MAGIC;

	xnlock_get_irqsave(&nklock, s);
	appendgq(&tm->owner->alarmq, tm);
	xnlock_put_irqrestore(&nklock, s);

	sprintf(tm->name, "anon_sigtm%lu", tm_ids++);

	err = xnregistry_enter(tm->name, tm, &tm->handle, 0);

	if (err) {
		tm->handle = XN_NO_HANDLE;
		tm_cancel((u_long)tm);
		return err;
	}

	xnlock_get_irqsave(&nklock, s);
	xntimer_start(&tm->timerbase, ticks, interval, XN_RELATIVE);
	xnlock_put_irqrestore(&nklock, s);

	return SUCCESS;
}

#endif /* CONFIG_XENO_OPT_PERVASIVE */

static const int tm_month_sizes[] = {
	31, 28, 31, 30, 31, 30,
	31, 31, 30, 31, 30, 31
};

static u_long tm_date_to_ticks(u_long date,
			       u_long time, u_long ticks, xnticks_t *count)
{
	u_long year, month, day, hour, min, sec;
	int n;

	*count = 0;

	year = date >> 16;
	month = (date >> 8) & 0xff;
	day = (date & 0xff);
	hour = time >> 16;
	min = (time >> 8) & 0xff;
	sec = (time & 0xff);

	if (month < 1 || month > 12 || day < 1 || day > 31)
		return ERR_ILLDATE;

	if (hour > 23 || min > 59 || sec > 59)
		return ERR_ILLTIME;

	if (ticks >= xntbase_get_ticks2sec(psos_tbase))
		return ERR_ILLTICKS;

	for (n = 0; n < year; n++)
		*count += ((n % 4) ? 365 : 366);

	if (!(year % 4) && month >= 3)
		/* Add one day for leap year after February. */
		*count += 1;

	for (n = month - 1; n > 0; n--)
		*count += tm_month_sizes[n - 1];

	*count += day - 1;
	*count *= 24;
	*count += hour;
	*count *= 60;
	*count += min;
	*count *= 60;
	*count += sec;
	*count *= xntbase_get_ticks2sec(psos_tbase);
	*count += ticks;

	return SUCCESS;
}

static void tm_ticks_to_date(u_long *date,
			     u_long *time, u_long *ticks, xnticks_t count)
{
	u_long year, month, day, hour, min, sec, rem;
	xnticks_t allsecs;

	allsecs = xnarch_ulldiv(count, xntbase_get_ticks2sec(psos_tbase), &rem);

	year = 0;

	for (;;) {
		u_long ysecs = ((year % 4) ? 365 : 366) * tm_secbyday;

		if (ysecs > allsecs)
			break;

		allsecs -= ysecs;
		year++;
	}

	month = 0;

	for (;;) {
		u_long msecs = tm_month_sizes[month] * tm_secbyday;

		if (month == 1 && (year % 4) == 0)
			/* Account for leap year on February. */
			msecs += tm_secbyday;

		if (msecs > allsecs) {
			month++;
			break;
		}

		allsecs -= msecs;
		month++;
	}

	sec = allsecs;
	day = sec / tm_secbyday;
	sec -= (day * tm_secbyday);
	day++;			/* Days are 1-based. */
	hour = (sec / tm_secbyhour);
	sec -= (hour * tm_secbyhour);
	min = (sec / tm_secbymin);
	sec -= (min * tm_secbymin);

	*date = (year << 16) | (month << 8) | day;
	*time = (hour << 16) | (min << 8) | sec;
	*ticks = xnarch_ullmod(count, xntbase_get_ticks2sec(psos_tbase), &rem);
}

u_long tm_wkafter(u_long ticks)
{
	if (xnpod_unblockable_p())
		return -EPERM;

	if (ticks > 0) {
		xnpod_delay(ticks);
		if (xnthread_test_info(&psos_current_task()->threadbase, XNBREAK))
			return -EINTR;
	}
	else
		xnpod_yield();	/* Perform manual round-robin */

	return SUCCESS;
}

u_long tm_evafter(u_long ticks, u_long events, u_long *tmid)
{
	if (!xnpod_primary_p())
		return -EPERM;

	return tm_start_event_timer(ticks, XN_INFINITE, events, tmid);
}

u_long tm_evevery(u_long ticks, u_long events, u_long *tmid)
{
	if (!xnpod_primary_p())
		return -EPERM;

	return tm_start_event_timer(ticks, ticks, events, tmid);
}

u_long tm_cancel(u_long tmid)
{
	u_long err = SUCCESS;
	psostm_t *tm;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	tm = psos_h2obj_active(tmid, PSOS_TM_MAGIC, psostm_t);

	if (!tm) {
		err = psos_handle_error(tmid, PSOS_TM_MAGIC, psostm_t);
		goto unlock_and_exit;
	}

	tm_destroy_internal(tm);

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

u_long tm_tick(void)
{
	xntbase_tick(psos_tbase);
	return SUCCESS;
}

u_long tm_evwhen(u_long date,
		 u_long time, u_long ticks, u_long events, u_long *tmid)
{
	xnticks_t when, now;
	u_long err;

	if (!xnpod_primary_p())
		return -EPERM;

	if (!xntbase_timeset_p(psos_tbase))
		return ERR_NOTIME;	/* Must call tm_set() first. */

	err = tm_date_to_ticks(date, time, ticks, &when);

	if (err != SUCCESS)
		return err;

	now = xntbase_get_time(psos_tbase);

	if (when <= now)
		return ERR_TOOLATE;

	return tm_start_event_timer(when - now, XN_INFINITE, events, tmid);
}

u_long tm_wkwhen(u_long date, u_long time, u_long ticks)
{
	xnticks_t when, now;
	u_long err;

	if (xnpod_unblockable_p())
		return -EPERM;

	if (!xntbase_timeset_p(psos_tbase))
		return ERR_NOTIME;	/* Must call tm_set() first. */

	err = tm_date_to_ticks(date, time, ticks, &when);

	if (err != SUCCESS)
		return err;

	now = xntbase_get_time(psos_tbase);

	if (when <= now)
		return ERR_TOOLATE;

	xnpod_delay(when - now);

	if (xnthread_test_info(&psos_current_task()->threadbase, XNBREAK))
		return -EINTR;

	return SUCCESS;
}

u_long tm_get(u_long *date, u_long *time, u_long *ticks)
{
	if (!xntbase_timeset_p(psos_tbase))
		return ERR_NOTIME;	/* Must call tm_set() first. */

	tm_ticks_to_date(date, time, ticks, xntbase_get_time(psos_tbase));

	return SUCCESS;
}

u_long tm_set(u_long date, u_long time, u_long ticks)
{
	xnticks_t when;
	u_long err;
	spl_t s;

	err = tm_date_to_ticks(date, time, ticks, &when);

	if (err != SUCCESS)
		return err;

	xnlock_get_irqsave(&nklock, s);
	xntbase_adjust_time(psos_tbase, when - xntbase_get_time(psos_tbase));
	xnlock_put_irqrestore(&nklock, s);

	return SUCCESS;
}

/*
 * IMPLEMENTATION NOTES:
 *
 * - Daylight saving time is not handled in date-to-ticks
 * conversion.
 */
