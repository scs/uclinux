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

#include <psos+/task.h>
#include <psos+/asr.h>
#ifdef CONFIG_XENO_OPT_PERVASIVE
#include <asm/signal.h>
#endif

void psosasr_init(void)
{
}

void psosasr_cleanup(void)
{
}

u_long as_catch(void (*routine) (void), u_long mode)
{
	psostask_t *task;
	spl_t s;

	if (xnpod_unblockable_p())
		return -EPERM;

	task = psos_current_task();
	xnlock_get_irqsave(&nklock, s);
	task->threadbase.asr = (xnasr_t) routine;
	task->threadbase.asrmode = psos_mode_to_xeno(mode);
	task->threadbase.asrimask = ((mode >> 8) & 0x7);
	xnlock_put_irqrestore(&nklock, s);

	/* The rescheduling procedure checks for pending signals. */
	xnpod_schedule();

	return SUCCESS;
}

u_long as_send(u_long tid, u_long signals)
{
	u_long err = SUCCESS;
	psostask_t *task;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	task = psos_h2obj_active(tid, PSOS_TASK_MAGIC, psostask_t);

	if (!task) {
		err = psos_handle_error(tid, PSOS_TASK_MAGIC, psostask_t);
		goto unlock_and_exit;
	}

	if (task->threadbase.asr == XNTHREAD_INVALID_ASR) {
		err = ERR_NOASR;
		goto unlock_and_exit;
	}

	if (signals > 0) {
#ifdef CONFIG_XENO_OPT_PERVASIVE
		/* In case of a user-space receiver, we try to deliver
		 * a Linux signal instead of arming the signal bits in
		 * the TCB. The least significant bit from the signal
		 * mask is used to determine the value of the Linux
		 * signal to send, which will be within the [SIGRTMIN
		 * .. SIGRTMAX - 1] range. Any failure doing so only
		 * results in falling back to the normal procedure. */
		if (xnthread_user_task(&task->threadbase) != NULL) {
			int signo = SIGRTMIN + ffnz(signals);
			if (signo < SIGRTMAX) {
				xnshadow_send_sig(&task->threadbase, signo, 1);
				goto unlock_and_exit;
			}
		}
#endif
		task->threadbase.signals |= signals;

		if (xnpod_current_thread() == &task->threadbase)
			xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}
