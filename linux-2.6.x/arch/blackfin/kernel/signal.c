/*
 * File:         arch/blackfin/kernel/signal.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:
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

/*
 * ++roman (07/09/96): implemented signal stacks (specially for tosemu on
 * Atari :-) Current limitation: Only one sigstack can be active at one time.
 * If a second signal with SA_ONSTACK set arrives while working on a sigstack,
 * SA_ONSTACK is ignored. This behaviour avoids lots of trouble with nested
 * signal handlers!
 */

#include <linux/signal.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <linux/tty.h>
#include <linux/personality.h>
#include <linux/binfmts.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/ucontext.h>

#define _BLOCKABLE (~(sigmask(SIGKILL) | sigmask(SIGSTOP)))

asmlinkage int do_signal(sigset_t * oldset, struct pt_regs *regs);

struct sigframe {
	char *pretcode;
	int sig;
	int code;
	struct sigcontext *psc;
	char retcode[8];
	unsigned long extramask[_NSIG_WORDS - 1];
	struct sigcontext sc;
};

struct rt_sigframe {
	char *pretcode;
	int sig;
	struct siginfo *pinfo;
	void *puc;
	char retcode[8];
	struct siginfo info;
	struct ucontext uc;
};

/*
 * Atomically swap in the new signal mask, and wait for a signal.
 *
 */
asmlinkage int do_sigsuspend(struct pt_regs *regs)
{
	old_sigset_t mask = regs->r0;
	sigset_t saveset;

	mask &= _BLOCKABLE;
	spin_lock_irq(&current->sighand->siglock);
	saveset = current->blocked;
	siginitset(&current->blocked, mask);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	regs->r0 = -EINTR;
	while (1) {
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		if (do_signal(&saveset, regs))
			return regs->r0;
	}
}

asmlinkage int do_rt_sigsuspend(struct pt_regs *regs)
{
	sigset_t *unewset = (sigset_t *) regs->r0;
	size_t sigsetsize = (size_t) regs->r1;
	sigset_t saveset, newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&newset, unewset, sizeof(newset)))
		return -EFAULT;
	sigdelsetmask(&newset, ~_BLOCKABLE);

	spin_lock_irq(&current->sighand->siglock);
	saveset = current->blocked;
	current->blocked = newset;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	regs->r0 = -EINTR;
	while (1) {
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		if (do_signal(&saveset, regs))
			return regs->r0;
	}
}

asmlinkage int
sys_sigaction(int sig, const struct old_sigaction *act,
	      struct old_sigaction *oact)
{
	struct k_sigaction new_ka, old_ka;
	int ret;

	if (act) {
		old_sigset_t mask;
		if (!access_ok(VERIFY_READ, act, sizeof(*act)) ||
		    __get_user(new_ka.sa.sa_handler, &act->sa_handler) ||
		    __get_user(new_ka.sa.sa_restorer, &act->sa_restorer))
			return -EFAULT;
		__get_user(new_ka.sa.sa_flags, &act->sa_flags);
		__get_user(mask, &act->sa_mask);
		siginitset(&new_ka.sa.sa_mask, mask);
	}

	ret = do_sigaction(sig, act ? &new_ka : NULL, oact ? &old_ka : NULL);

	if (!ret && oact) {
		if (!access_ok(VERIFY_WRITE, oact, sizeof(*oact)) ||
		    __put_user(old_ka.sa.sa_handler, &oact->sa_handler) ||
		    __put_user(old_ka.sa.sa_restorer, &oact->sa_restorer))
			return -EFAULT;
		__put_user(old_ka.sa.sa_flags, &oact->sa_flags);
		__put_user(old_ka.sa.sa_mask.sig[0], &oact->sa_mask);
	}

	return ret;
}

asmlinkage int sys_sigaltstack(const stack_t * uss, stack_t * uoss)
{
	return do_sigaltstack(uss, uoss, rdusp());
}

/*
 * Do a signal return; undo the signal stack.
 *
 * Keep the return code on the stack quadword aligned!
 * That makes the cache flush below easier.
 */
static inline int
restore_sigcontext(struct pt_regs *regs, struct sigcontext *usc, int *pr0)
{
	struct sigcontext context;
	int err = 0;

	/* get previous context */
	if (copy_from_user(&context, usc, sizeof(context)))
		goto badframe;
	if (context.sc_pc == 0)
		goto badframe;
	/* restore passed registers */
	regs->r0 = context.sc_r0;
	regs->r1 = context.sc_r1;
	regs->r2 = context.sc_r2;
	regs->r3 = context.sc_r3;
	regs->r4 = context.sc_r4;
	regs->p0 = context.sc_p0;
	regs->p1 = context.sc_p1;
	regs->l0 = context.sc_l0;
	regs->l1 = context.sc_l1;
	regs->l2 = context.sc_l2;
	regs->l3 = context.sc_l3;
	regs->seqstat = context.sc_seqstat;
	regs->pc = context.sc_pc;
	regs->retx = context.sc_retx;
	regs->pc = context.sc_retx;
	regs->rets = context.sc_rets;
	regs->orig_p0 = -1;	/* disable syscall checks */
	wrusp(context.sc_usp);

	*pr0 = context.sc_r0;
	return err;

      badframe:
	return 1;
}

static inline int
rt_restore_ucontext(struct pt_regs *regs, struct ucontext *uc, int *pr0)
{
	int temp;
	greg_t *gregs = uc->uc_mcontext.gregs;
	unsigned long usp;
	int err;

	err = __get_user(temp, &uc->uc_mcontext.version);
	if (temp != MCONTEXT_VERSION)
		goto badframe;
	/* restore passed registers */
	err |= __get_user(regs->r0, &gregs[0]);
	err |= __get_user(regs->r1, &gregs[1]);
	err |= __get_user(regs->r2, &gregs[2]);
	err |= __get_user(regs->r3, &gregs[3]);
	err |= __get_user(regs->r4, &gregs[4]);
	err |= __get_user(regs->r5, &gregs[5]);
	err |= __get_user(regs->r6, &gregs[6]);
	err |= __get_user(regs->r7, &gregs[7]);
	err |= __get_user(regs->p0, &gregs[8]);
	err |= __get_user(regs->p1, &gregs[9]);
	err |= __get_user(regs->p2, &gregs[10]);
	err |= __get_user(regs->p3, &gregs[11]);
	err |= __get_user(regs->p4, &gregs[12]);
	err |= __get_user(regs->p5, &gregs[13]);
	err |= __get_user(usp, &gregs[14]);
	wrusp(usp);
	err |= __get_user(regs->a0w, &gregs[15]);
	err |= __get_user(regs->a1w, &gregs[16]);
	err |= __get_user(regs->a0x, &gregs[17]);
	err |= __get_user(regs->a1x, &gregs[18]);
	err |= __get_user(regs->astat, &gregs[19]);
	err |= __get_user(regs->rets, &gregs[20]);
	err |= __get_user(regs->pc, &gregs[21]);
	err |= __get_user(regs->retx, &gregs[22]);

	err |= __get_user(regs->fp, &gregs[23]);
	err |= __get_user(regs->i0, &gregs[24]);
	err |= __get_user(regs->i1, &gregs[25]);
	err |= __get_user(regs->i2, &gregs[26]);
	err |= __get_user(regs->i3, &gregs[27]);
	err |= __get_user(regs->m0, &gregs[28]);
	err |= __get_user(regs->m1, &gregs[29]);
	err |= __get_user(regs->m2, &gregs[30]);
	err |= __get_user(regs->m3, &gregs[31]);
	err |= __get_user(regs->l0, &gregs[32]);
	err |= __get_user(regs->l1, &gregs[33]);
	err |= __get_user(regs->l2, &gregs[34]);
	err |= __get_user(regs->l3, &gregs[35]);
	err |= __get_user(regs->b0, &gregs[36]);
	err |= __get_user(regs->b1, &gregs[37]);
	err |= __get_user(regs->b2, &gregs[38]);
	err |= __get_user(regs->b3, &gregs[39]);
	err |= __get_user(regs->lc0, &gregs[40]);
	err |= __get_user(regs->lc1, &gregs[41]);
	err |= __get_user(regs->lt0, &gregs[42]);
	err |= __get_user(regs->lt1, &gregs[43]);
	err |= __get_user(regs->lb0, &gregs[44]);
	err |= __get_user(regs->lb1, &gregs[45]);
	err |= __get_user(regs->seqstat, &gregs[46]);

	regs->orig_p0 = -1;	/* disable syscall checks */

	if (do_sigaltstack(&uc->uc_stack, NULL, usp) == -EFAULT)
		goto badframe;

	*pr0 = regs->r0;
	return err;

      badframe:
	return 1;
}

asmlinkage int do_sigreturn(unsigned long __unused)
{
	struct pt_regs *regs = (struct pt_regs *)__unused;
	unsigned long usp = rdusp();
	struct sigframe *frame = (struct sigframe *)(usp);
	sigset_t set;
	int r0;

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__get_user(set.sig[0], &frame->sc.sc_mask) ||
	    (_NSIG_WORDS > 1 &&
	     __copy_from_user(&set.sig[1], &frame->extramask,
			      sizeof(frame->extramask))))

		goto badframe;

	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	if (restore_sigcontext(regs, &frame->sc, &r0))
		goto badframe;
	return r0;

      badframe:
	force_sig(SIGSEGV, current);
	return 0;
}

asmlinkage int do_rt_sigreturn(unsigned long __unused)
{
	struct pt_regs *regs = (struct pt_regs *)__unused;
	unsigned long usp = rdusp();
	struct rt_sigframe *frame = (struct rt_sigframe *)(usp);
	sigset_t set;
	int r0;

	if (!access_ok(VERIFY_READ, frame, sizeof(*frame)))
		goto badframe;
	if (__copy_from_user(&set, &frame->uc.uc_sigmask, sizeof(set)))
		goto badframe;

	sigdelsetmask(&set, ~_BLOCKABLE);
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = set;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	if (rt_restore_ucontext(regs, &frame->uc, &r0))
		goto badframe;
	return r0;

      badframe:
	force_sig(SIGSEGV, current);
	return 0;
}

static void
setup_sigcontext(struct sigcontext *sc, struct pt_regs *regs,
		 unsigned long mask)
{
	sc->sc_mask = mask;
	sc->sc_usp = rdusp();
	sc->sc_r0 = regs->r0;
	sc->sc_r1 = regs->r1;
	sc->sc_r2 = regs->r2;
	sc->sc_r3 = regs->r3;
	sc->sc_r4 = regs->r4;
	sc->sc_p0 = regs->p0;
	sc->sc_p1 = regs->p1;
	sc->sc_l0 = regs->l0;
	sc->sc_l1 = regs->l1;
	sc->sc_l2 = regs->l2;
	sc->sc_l3 = regs->l3;
	sc->sc_seqstat = regs->seqstat;
	sc->sc_pc = regs->pc;
	sc->sc_rets = regs->rets;

	if (regs->seqstat)
		sc->sc_retx = regs->retx;
	else
		sc->sc_retx = regs->pc;

}

static inline int rt_setup_ucontext(struct ucontext *uc, struct pt_regs *regs)
{
	greg_t *gregs = uc->uc_mcontext.gregs;
	int err = 0;

	err |= __put_user(MCONTEXT_VERSION, &uc->uc_mcontext.version);
	err |= __put_user(regs->r0, &gregs[0]);
	err |= __put_user(regs->r1, &gregs[1]);
	err |= __put_user(regs->r2, &gregs[2]);
	err |= __put_user(regs->r3, &gregs[3]);
	err |= __put_user(regs->r4, &gregs[4]);
	err |= __put_user(regs->r5, &gregs[5]);
	err |= __put_user(regs->r6, &gregs[6]);
	err |= __put_user(regs->r7, &gregs[7]);
	err |= __put_user(regs->p0, &gregs[8]);
	err |= __put_user(regs->p1, &gregs[9]);
	err |= __put_user(regs->p2, &gregs[10]);
	err |= __put_user(regs->p3, &gregs[11]);
	err |= __put_user(regs->p4, &gregs[12]);
	err |= __put_user(regs->p5, &gregs[13]);
	err |= __put_user(rdusp(), &gregs[14]);
	err |= __put_user(regs->a0w, &gregs[15]);
	err |= __put_user(regs->a1w, &gregs[16]);
	err |= __put_user(regs->a0x, &gregs[17]);
	err |= __put_user(regs->a1x, &gregs[18]);
	err |= __put_user(regs->astat, &gregs[19]);
	err |= __put_user(regs->rets, &gregs[20]);
	err |= __put_user(regs->pc, &gregs[21]);
	err |= __put_user(regs->retx, &gregs[22]);

	err |= __put_user(regs->fp, &gregs[23]);
	err |= __put_user(regs->i0, &gregs[24]);
	err |= __put_user(regs->i1, &gregs[25]);
	err |= __put_user(regs->i2, &gregs[26]);
	err |= __put_user(regs->i3, &gregs[27]);
	err |= __put_user(regs->m0, &gregs[28]);
	err |= __put_user(regs->m1, &gregs[29]);
	err |= __put_user(regs->m2, &gregs[30]);
	err |= __put_user(regs->m3, &gregs[31]);
	err |= __put_user(regs->l0, &gregs[32]);
	err |= __put_user(regs->l1, &gregs[33]);
	err |= __put_user(regs->l2, &gregs[34]);
	err |= __put_user(regs->l3, &gregs[35]);
	err |= __put_user(regs->b0, &gregs[36]);
	err |= __put_user(regs->b1, &gregs[37]);
	err |= __put_user(regs->b2, &gregs[38]);
	err |= __put_user(regs->b3, &gregs[39]);
	err |= __put_user(regs->lc0, &gregs[40]);
	err |= __put_user(regs->lc1, &gregs[41]);
	err |= __put_user(regs->lt0, &gregs[42]);
	err |= __put_user(regs->lt1, &gregs[43]);
	err |= __put_user(regs->lb0, &gregs[44]);
	err |= __put_user(regs->lb1, &gregs[45]);
	err |= __put_user(regs->seqstat, &gregs[46]);
	return err;
}

static inline void push_cache(unsigned long vaddr, unsigned int len)
{
	flush_icache_range(vaddr, vaddr + len);
}

static inline void *get_sigframe(struct k_sigaction *ka, struct pt_regs *regs,
				 size_t frame_size)
{
	unsigned long usp;

	/* Default to using normal stack.  */
	usp = rdusp();

	/* This is the X/Open sanctioned signal stack switching.  */
	if (ka->sa.sa_flags & SA_ONSTACK) {
		if (!on_sig_stack(usp))
			usp = current->sas_ss_sp + current->sas_ss_size;
	}
	return (void *)((usp - frame_size) & -8UL);
}

static void
setup_frame(int sig, struct k_sigaction *ka,
	    sigset_t * set, struct pt_regs *regs)
{
	struct sigframe *frame;
	struct sigcontext context;
	int err = 0;

	frame = get_sigframe(ka, regs, sizeof(*frame));

	err |= __put_user((current_thread_info()->exec_domain
			   && current_thread_info()->exec_domain->signal_invmap
			   && sig < 32
			   ? current_thread_info()->exec_domain->
			   signal_invmap[sig] : sig), &frame->sig);

	err |= __put_user(&frame->sc, &frame->psc);

	if (_NSIG_WORDS > 1)
		err |= copy_to_user(frame->extramask, &set->sig[1],
				    sizeof(frame->extramask));

	setup_sigcontext(&context, regs, set->sig[0]);
	err |= copy_to_user(&frame->sc, &context, sizeof(context));

	/* Set up to return from userspace.  */
	err |= __put_user(frame->retcode, &frame->pretcode);
	err |= __put_user(0x28, &(frame->retcode[0]));
	err |= __put_user(0xe1, &(frame->retcode[1]));
	err |= __put_user(0x77, &(frame->retcode[2]));
	err |= __put_user(0x00, &(frame->retcode[3]));
	err |= __put_user(0xa0, &(frame->retcode[4]));
	err |= __put_user(0x00, &(frame->retcode[5]));

	if (err)
		goto give_sigsegv;

	push_cache((unsigned long)&frame->retcode, sizeof(frame->retcode));

	/* Set up registers for signal handler */
	wrusp((unsigned long)frame);
	regs->pc = (unsigned long)ka->sa.sa_handler;
	regs->rets = (unsigned long)(frame->retcode);
	regs->r0 = frame->sig;
	regs->l0 = regs->l1 = regs->l2 = regs->l3 = 0;

	if (regs->seqstat)
		regs->retx = (unsigned long)ka->sa.sa_handler;

	return;

      give_sigsegv:
	if (sig == SIGSEGV)
		ka->sa.sa_handler = SIG_DFL;
	force_sig(SIGSEGV, current);
	return;
}

static void
setup_rt_frame(int sig, struct k_sigaction *ka, siginfo_t * info,
	       sigset_t * set, struct pt_regs *regs)
{
	struct rt_sigframe *frame;
	int err = 0;

	frame = get_sigframe(ka, regs, sizeof(*frame));

	err |= __put_user((current_thread_info()->exec_domain
			   && current_thread_info()->exec_domain->signal_invmap
			   && sig < 32
			   ? current_thread_info()->exec_domain->
			   signal_invmap[sig] : sig), &frame->sig);

	err |= __put_user(&frame->info, &frame->pinfo);

	err |= __put_user(&frame->info, &frame->pinfo);
	err |= __put_user(&frame->uc, &frame->puc);
	err |= copy_siginfo_to_user(&frame->info, info);

	/* Create the ucontext.  */
	err |= __put_user(0, &frame->uc.uc_flags);
	err |= __put_user(0, &frame->uc.uc_link);
	err |=
	    __put_user((void *)current->sas_ss_sp, &frame->uc.uc_stack.ss_sp);
	err |= __put_user(sas_ss_flags(rdusp()), &frame->uc.uc_stack.ss_flags);
	err |= __put_user(current->sas_ss_size, &frame->uc.uc_stack.ss_size);
	err |= rt_setup_ucontext(&frame->uc, regs);
	err |= copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set));

	/* Set up to return from userspace.  */
	err |= __put_user(frame->retcode, &frame->pretcode);
	err |= __put_user(0x28, &(frame->retcode[0]));
	err |= __put_user(0xe1, &(frame->retcode[1]));
	err |= __put_user(0xad, &(frame->retcode[2]));
	err |= __put_user(0x00, &(frame->retcode[3]));
	err |= __put_user(0xa0, &(frame->retcode[4]));
	err |= __put_user(0x00, &(frame->retcode[5]));

	if (err)
		goto give_sigsegv;

	push_cache((unsigned long)&frame->retcode, sizeof(frame->retcode));

	/* Set up registers for signal handler */
	wrusp((unsigned long)frame);
	regs->pc = (unsigned long)ka->sa.sa_handler;
	regs->rets = (unsigned long)(frame->retcode);

	regs->r0 = frame->sig;
	regs->r1 = (unsigned long)(&frame->info);
	regs->r2 = (unsigned long)(&frame->uc);

	if (regs->seqstat)
		regs->retx = (unsigned long)ka->sa.sa_handler;

	return;

      give_sigsegv:
	if (sig == SIGSEGV)
		ka->sa.sa_handler = SIG_DFL;
	force_sig(SIGSEGV, current);
	return;
}

static inline void
handle_restart(struct pt_regs *regs, struct k_sigaction *ka, int has_handler)
{
	switch (regs->r0) {
	case -ERESTARTNOHAND:
		if (!has_handler)
			goto do_restart;
		regs->r0 = -EINTR;
		break;

	case -ERESTARTSYS:
		if (has_handler && !(ka->sa.sa_flags & SA_RESTART)) {
			regs->r0 = -EINTR;
			break;
		}
		/* fallthrough */
	case -ERESTARTNOINTR:
	      do_restart:
		regs->p0 = regs->orig_p0;
		regs->r0 = regs->orig_r0;
		regs->pc -= 2;
		break;
	}
}

/*
 * OK, we're invoking a handler
 */
static void
handle_signal(int sig, struct k_sigaction *ka, siginfo_t * info,
	      sigset_t * oldset, struct pt_regs *regs)
{
	/* are we from a system call? to see pt_regs->orig_p0 */
	if (regs->orig_p0 >= 0)
		/* If so, check system call restarting.. */
		handle_restart(regs, ka, 1);

	/* set up the stack frame */
	if (ka->sa.sa_flags & SA_SIGINFO)
		setup_rt_frame(sig, ka, info, oldset, regs);
	else
		setup_frame(sig, ka, oldset, regs);

	if (ka->sa.sa_flags & SA_ONESHOT)
		ka->sa.sa_handler = SIG_DFL;

	if (!(ka->sa.sa_flags & SA_NODEFER)) {
		spin_lock_irq(&current->sighand->siglock);
		sigaddset(&current->blocked, sig);
		sigorsets(&current->blocked, &current->blocked,
			  &ka->sa.sa_mask);
		recalc_sigpending();
		spin_unlock_irq(&current->sighand->siglock);
	}
}

/*
 * Note that 'init' is a special process: it doesn't get signals it doesn't
 * want to handle. Thus you cannot kill init even with a SIGKILL even by
 * mistake.
 *
 * Note that we go through the signals twice: once to check the signals
 * that the kernel can handle, and then we build all the user-level signal
 * handling stack-frames in one go after that.
 */
asmlinkage int do_signal(sigset_t * oldset, struct pt_regs *regs)
{
	siginfo_t info;
	struct k_sigaction ka;
	int signr;

	current->thread.esp0 = (unsigned long)regs;

	if (!oldset)
		oldset = &current->blocked;

	signr = get_signal_to_deliver(&info, &ka, regs, NULL);
	if (signr > 0) {
		/* Whee!  Actually deliver the signal.  */
		handle_signal(signr, &ka, &info, oldset, regs);
		return 1;
	}

	/* Did we come from a system call? */
	if (regs->orig_p0 >= 0)
		/* Restart the system call - no handlers present */
		handle_restart(regs, NULL, 0);

	return 0;
}
