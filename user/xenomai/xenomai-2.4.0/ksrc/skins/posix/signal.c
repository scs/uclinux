/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/**
 * @ingroup posix
 * @defgroup posix_signal Signals services.
 *
 * Signals management services.
 *
 * Signals are asynchronous notifications delivered to a process or thread. Such
 * notifications occur as the result of an exceptional event or at the request
 * of another process.
 *
 * The services documented here are reserved to Xenomai kernel-space threads,
 * user-space threads switch to secondary mode when handling signals, and use
 * Linux regular signals services.
 *
 * Xenomai POSIX skin signals are implemented as real-time signals, meaning
 * that they are queued when posted several times to a thread before the
 * first notification is handled, and that each signal carry additional data in
 * a @b siginfo_t object. In order to ensure consistence with user-space
 * signals, valid signals number range from 1 to SIGRTMAX, signals from SIGRTMIN
 * to SIGRTMAX being higher priority than signals from 1 to SIGRTMIN-1. As a
 * special case, signal 0 may be used with services pthread_kill() and
 * pthread_sigqueue_np() to check if a thread exists, but entails no other
 * action.
 *
 * The action to be taken upon reception of a signal depends on the thread
 * signal mask, (see pthread_sigmask()), and on the settings described by a
 * @b sigaction structure (see sigaction()).
 * 
 *@{*/

#ifdef CONFIG_XENO_OPT_PERVASIVE
#include <nucleus/shadow.h>
#endif /* CONFIG_XENO_OPT_PERVASIVE */
#include <asm/xenomai/system.h>	/* For xnlock. */
#include <posix/timer.h>	/* For pse51_timer_notified. */
#include <posix/sig.h>

static void pse51_default_handler(int sig);

typedef void siginfo_handler_t(int, siginfo_t *, void *);

#define user2pse51_sigset(set) ((pse51_sigset_t *)(set))
#define PSE51_SIGQUEUE_MAX 64

#define SIGRTMAX 64
static struct sigaction actions[SIGRTMAX];
static pse51_siginfo_t pse51_infos_pool[PSE51_SIGQUEUE_MAX];
#ifdef CONFIG_SMP
static xnlock_t pse51_infos_lock = XNARCH_LOCK_UNLOCKED;
#endif
static xnpqueue_t pse51_infos_free_list;

#ifdef CONFIG_XENO_OPT_PERVASIVE
#define SIG_MAX_REQUESTS 64	/* Must be a ^2 */

static int pse51_signals_apc;

static struct pse51_signals_threadsq_t {
	int in, out;
	pthread_t thread[SIG_MAX_REQUESTS];
} pse51_signals_threadsq[XNARCH_NR_CPUS];

static void pse51_signal_schedule_request(pthread_t thread)
{
	int cpuid = rthal_processor_id(), reqnum;
	struct pse51_signals_threadsq_t *rq = &pse51_signals_threadsq[cpuid];
	spl_t s;

	/* Signal the APC, to have it delegate signals to Linux. */
	splhigh(s);
	reqnum = rq->in;
	rq->thread[reqnum] = thread;
	rq->in = (reqnum + 1) & (SIG_MAX_REQUESTS - 1);
	splexit(s);

	rthal_apc_schedule(pse51_signals_apc);
}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

static pse51_siginfo_t *pse51_new_siginfo(int sig, int code, union sigval value)
{
	xnpholder_t *holder;
	pse51_siginfo_t *si;
	spl_t s;

	xnlock_get_irqsave(&pse51_infos_lock, s);
	holder = getpq(&pse51_infos_free_list);
	xnlock_put_irqrestore(&pse51_infos_lock, s);

	if (!holder)
		return NULL;

	si = link2siginfo(holder);
	si->info.si_signo = sig;
	si->info.si_code = code;
	si->info.si_value = value;

	return si;
}

static void pse51_delete_siginfo(pse51_siginfo_t * si)
{
	spl_t s;

	initph(&si->link);
	si->info.si_signo = 0;	/* Used for debugging. */

	xnlock_get_irqsave(&pse51_infos_lock, s);
	insertpqlr(&pse51_infos_free_list, &si->link, 0);
	xnlock_put_irqrestore(&pse51_infos_lock, s);
}

static inline void emptyset(pse51_sigset_t *set)
{

	*set = 0ULL;
}

static inline void fillset(pse51_sigset_t *set)
{

	*set = ~0ULL;
}

static inline void addset(pse51_sigset_t *set, int sig)
{

	*set |= ((pse51_sigset_t)1 << (sig - 1));
}

static inline void delset(pse51_sigset_t *set, int sig)
{

	*set &= ~((pse51_sigset_t)1 << (sig - 1));
}

static inline int ismember(const pse51_sigset_t *set, int sig)
{

	return (*set & ((pse51_sigset_t)1 << (sig - 1))) != 0;
}

static inline int isemptyset(const pse51_sigset_t *set)
{
	return (*set) == 0ULL;
}

static inline void andset(pse51_sigset_t *set,
			  const pse51_sigset_t *left,
			  const pse51_sigset_t *right)
{
	*set = (*left) & (*right);
}

static inline void orset(pse51_sigset_t *set,
			 const pse51_sigset_t *left,
			 const pse51_sigset_t *right)
{
	*set = (*left) | (*right);
}

static inline void andnotset(pse51_sigset_t *set,
			     const pse51_sigset_t *left,
			     const pse51_sigset_t *right)
{
	*set = (*left) & ~(*right);
}

/**
 * Initialize and empty a signal set.
 *
 * This service initializes ane empties the signal set pointed to by @a set.
 *
 * @param set address of a the signal set to be initialized.
 *
 * @retval 0
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigemptyset.html">
 * Specification.</a>
 * 
 */
int sigemptyset(sigset_t * set)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);

	emptyset(pse51_set);

	return 0;
}

/**
 * Initialize and fill a signal set.
 *
 * This service initializes ane fills the signal set pointed to by @a set.
 *
 * @param set address of a the signal set to be filled.
 *
 * @retval 0
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigfillset.html">
 * Specification.</a>
 * 
 */
int sigfillset(sigset_t * set)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);

	fillset(pse51_set);

	return 0;
}

/**
 * Add a signal to a signal set.
 *
 * This service adds the signal number @a sig to the signal set pointed to by @a
 * set.
 *
 * @param set address of a signal set;
 *
 * @param sig signal to be added to @a set.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a sig is not a valid signal number.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigaddset.html">
 * Specification.</a>
 * 
 */
int sigaddset(sigset_t * set, int sig)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);

	if ((unsigned)(sig - 1) > SIGRTMAX - 1) {
		thread_set_errno(EINVAL);
		return -1;
	}

	addset(pse51_set, sig);

	return 0;
}

/**
 * Delete a signal from a signal set.
 *
 * This service remove the signal number @a sig from the signal set pointed to
 * by @a set.
 *
 * @param set address of a signal set;
 *
 * @param sig signal to be removed from @a set.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a sig is not a valid signal number.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigdelset.html">
 * Specification.</a>
 * 
 */
int sigdelset(sigset_t * set, int sig)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);

	if ((unsigned)(sig - 1) > SIGRTMAX - 1) {
		thread_set_errno(EINVAL);
		return -1;
	}

	delset(pse51_set, sig);

	return 0;
}

/**
 * Test for a signal in a signal set.
 *
 * This service tests whether the signal number @a sig is member of the signal
 * set pointed to by @a set.
 *
 * @param set address of a signal set;
 *
 * @param sig tested signal number.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a sig is not a valid signal number.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigismember.html">
 * Specification.</a>
 * 
 */
int sigismember(const sigset_t * set, int sig)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);

	if ((unsigned)(sig - 1) > SIGRTMAX - 1) {
		thread_set_errno(EINVAL);
		return -1;
	}

	return ismember(pse51_set, sig);
}

/* Must be called with nklock lock, irqs off, may reschedule. */
void pse51_sigqueue_inner(pthread_t thread, pse51_siginfo_t * si)
{
	unsigned prio;
	int signum;

	if (!pse51_obj_active(thread, PSE51_THREAD_MAGIC, struct pse51_thread))
		 return;

	signum = si->info.si_signo;
	/* Since signals below SIGRTMIN are not real-time, they should be treated
	   after real-time signals, hence their priority. */
	prio = signum < SIGRTMIN ? signum + SIGRTMAX : signum;

	initph(&si->link);

	if (ismember(&thread->sigmask, signum)) {
		addset(&thread->blocked_received.mask, signum);
		insertpqfr(&thread->blocked_received.list, &si->link, prio);
	} else {
		addset(&thread->pending.mask, signum);
		insertpqfr(&thread->pending.list, &si->link, prio);
		thread->threadbase.signals = 1;
	}

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (testbits(thread->threadbase.state, XNSHADOW))
		pse51_signal_schedule_request(thread);
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	if (thread == pse51_current_thread()
	    || xnpod_unblock_thread(&thread->threadbase))
		xnpod_schedule();
}

void pse51_sigunqueue(pthread_t thread, pse51_siginfo_t * si)
{
	pse51_sigqueue_t *queue;
	xnpholder_t *next;

	if (ismember(&thread->sigmask, si->info.si_signo))
		queue = &thread->blocked_received;
	else
		queue = &thread->pending;

	/* If si is the only signal queued with its signal number, clear the
	   mask. We do not have "prevpq", we hence use findpq, even though this is
	   much less efficient. */
	next = nextpq(&queue->list, &si->link);
	if ((!next || next->prio != si->link.prio)
	    && findpqh(&queue->list, si->link.prio) == &si->link)
		delset(&queue->mask, si->info.si_signo);

	removepq(&queue->list, &si->link);
}

/* Unqueue any siginfo of "queue" whose signal number is member of "set",
   starting with "start". If "start" is NULL, start from the list head. */
static pse51_siginfo_t *pse51_getsigq(pse51_sigqueue_t * queue,
				      pse51_sigset_t *set,
				      pse51_siginfo_t ** start)
{
	xnpholder_t *holder, *next;
	pse51_siginfo_t *si;

	next = (start && *start) ? &(*start)->link : getheadpq(&queue->list);

	while ((holder = next)) {
		next = nextpq(&queue->list, holder);
		si = link2siginfo(holder);

		if (ismember(set, si->info.si_signo))
			goto found;
	}

	if (start)
		*start = NULL;

	return NULL;

      found:
	removepq(&queue->list, holder);
	if (!next || next->prio != holder->prio)
		delset(&queue->mask, si->info.si_signo);

	if (start)
		*start = next ? link2siginfo(next) : NULL;

	return si;
}

/**
 * Examine and change a signal action.
 *
 * The @b sigaction structure descibes the actions to be taken upon signal
 * delivery. A @b sigaction structure is associated with every signal, for the
 * kernel-space as a whole.
 *
 * If @a oact is not @a NULL, this service returns at the address @a oact, the
 * current value of the @b sigaction structure associated with the signal @a
 * sig.
 *
 * If @a act is not @a NULL, this service set to the value pointed to by @a act,
 * the @b sigaction structure associated with the signal @a sig.
 *
 * The structure @b sigaction has the following members:
 * - @a sa_flags, is a bitwise OR of the flags;
 *   - SA_RESETHAND, meaning that the signal handler will be reset to SIG_GFL
 *     and SA_SIGINFO cleared upon reception of a signal,
 *   - SA_NODEFER, meaning that the signal handler will be called with the
 *     signal @a sig not masked when handling the signal @a sig,
 *   - SA_SIGINFO, meaning that the member @a sa_sigaction of the @b sigaction
 *     structure will be used as a signal handler instead of @a sa_handler
 * - @a sa_mask, of type @b sigset_t, is the value to which the thread signals
 *   mask will be set during execution of the signal handler (@a sig is
 *   automatically added to this set if SA_NODEFER is not set in @a sa_flags);
 * - @a sa_handler, of type <b>void (*)(int)</b> is the signal handler which
 *   will be called upon signal delivery if SA_SIGINFO is not set in @a
 *   sa_flags, or one of SIG_IGN or SIG_DFL, meaning that the signal will be
 *   respectively ignored or handled with the default handler;
 * - @a sa_sigaction, of type <b>void (*)(int, siginfo_t *, void *)</b> is the
 *   signal handler which will be called upon signal delivery if SA_SIGINFO is
 *   set in @a sa_flags.
 *
 * When using @a sa_handler as a signal handler, it is passed the number of the
 * received signal, when using @a sa_sigaction, two additional arguments are
 * passed:
 * - a pointer to a @b siginfo_t object, containing additional information about
 *   the received signal;
 * - a void pointer, always null in this implementation.
 *
 * The following members of the @b siginfo_t structure are filled by this
 * implementation:
 * - @a si_signo, the signal number;
 * - @a si_code, the provenance of the signal, one of:
 *     - SI_QUEUE, the signal was queued with pthread_sigqueue_np(),
 *     - SI_USER, the signal was queued with pthread_kill(),
 *     - SI_TIMER, the signal was queued by a timer (see timer_settime()),
 *     - SI_MESQ, the signal was queued by a message queue (see mq_notify());
 * - @a si_value, an additional datum, of type @b union @b sigval.
 *
 * @param sig a signal number;
 *
 * @param act if not null, description of the action to be taken upon
 * notification of the signal @a sig;
 *
 * @param oact if not null, address where the previous description of the signal
 * action is stored on success.
 *
 * @retval 0 on sucess;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a sig is an invalid signal number;
 * - ENOTSUP, the @a sa_flags member of @a act contains other flags than
 *   SA_RESETHAND, SA_NODEFER and SA_SIGINFO;
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigaction.html">
 * Specification.</a>
 * 
 */
int sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
	spl_t s;

	if ((unsigned)(sig - 1) > SIGRTMAX - 1) {
		thread_set_errno(EINVAL);
		return -1;
	}

	if (act && testbits(act->sa_flags, ~SIGACTION_FLAGS)) {
		thread_set_errno(ENOTSUP);
		return -1;
	}

	xnlock_get_irqsave(&nklock, s);

	if (oact)
		*oact = actions[sig - 1];

	if (act) {
		struct sigaction *dest_act = &actions[sig - 1];

		*dest_act = *act;

		if (!(testbits(act->sa_flags, SA_NODEFER)))
			addset(user2pse51_sigset(&dest_act->sa_mask), sig);
	}

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Send a signal to a thread.
 *
 * This service send the signal @a sig to the Xenomai POSIX skin thread @a
 * thread (created with pthread_create()). If @a sig is zero, this service check
 * for existence of the thread @a thread, but no signal is sent.
 *
 * @param thread thread identifier;
 *
 * @param sig signal number.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a sig is an invalid signal number;
 * - EAGAIN, the maximum number of pending signals has been exceeded;
 * - ESRCH, @a thread is an invalid thread identifier.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_kill.html">
 * Specification.</a>
 * 
 */
int pthread_kill(pthread_t thread, int sig)
{
	pse51_siginfo_t *si = NULL;
	spl_t s;

	if ((unsigned)sig > SIGRTMAX)
		return EINVAL;

	if (sig) {
		si = pse51_new_siginfo(sig, SI_USER, (union sigval)0);

		if (!si)
			return EAGAIN;
	}

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(thread, PSE51_THREAD_MAGIC, struct pse51_thread)) {
		xnlock_put_irqrestore(&nklock, s);
		return ESRCH;
	}

	if (sig)
		pse51_sigqueue_inner(thread, si);

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Queue a signal to a thread.
 *
 * This service send the signal @a sig to the Xenomai POSIX skin thread @a
 * thread (created with pthread_create()), with the value @a value. If @a sig is
 * zero, this service check for existence of the thread @a thread, but no signal
 * is sent.
 *
 * This service is equivalent to the POSIX service sigqueue(), except that the
 * signal is directed to a thread instead of being directed to a process.
 *
 * @param thread thread identifier,
 *
 * @param sig signal number,
 *
 * @param value additional datum passed to @a thread with the signal @a sig.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a sig is an invalid signal number;
 * - EAGAIN, the maximum number of pending signals has been exceeded;
 * - ESRCH, @a thread is an invalid thread identifier.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigqueue.html">
 * sigqueue() specification.</a>
 * 
 */
int pthread_sigqueue_np(pthread_t thread, int sig, union sigval value)
{
	pse51_siginfo_t *si = NULL;	/* Avoid spurious warning. */
	spl_t s;

	if ((unsigned)sig > SIGRTMAX)
		return EINVAL;

	if (sig) {
		si = pse51_new_siginfo(sig, SI_QUEUE, value);

		if (!si)
			return EAGAIN;
	}

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(thread, PSE51_THREAD_MAGIC, struct pse51_thread)) {
		xnlock_put_irqrestore(&nklock, s);
		return ESRCH;
	}

	if (sig)
		pse51_sigqueue_inner(thread, si);

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Examine pending signals.
 *
 * This service stores, at the address @a set, the set of signals that are
 * currently blocked and have been received by the calling thread.
 *
 * @param set address where the set of blocked and received signals are stored
 * on success.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EPERM, the calling context is invalid.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigpending.html">
 * Specification.</a>
 * 
 */
int sigpending(sigset_t * set)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);
	pthread_t cur = pse51_current_thread();
	spl_t s;

	if (!cur) {
		thread_set_errno(EPERM);
		return -1;
	}

	/* Lock nklock, in order to prevent pthread_kill from modifying
	 * blocked_received while we are reading */
	xnlock_get_irqsave(&nklock, s);

	*pse51_set = cur->blocked_received.mask;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Examine and change the set of signals blocked by a thread.
 *
 * The signal mask of a thread is the set of signals that are blocked by this
 * thread.
 *
 * If @a oset is not NULL, this service stores, at the address @a oset the
 * current signal mask of the calling thread.
 *
 * If @a set is not NULL, this service sets the signal mask of the calling
 * thread according to the value of @a how, as follow:
 * - if @a how is SIG_BLOCK, the signals in @a set are added to the calling
 *   thread signal mask;
 * - if @a how is SIG_SETMASK, the calling thread signal mask is set to @a set;
 * - if @a how is SIG_UNBLOCK, the signals in @a set are removed from the
 *   calling thread signal mask.
 *
 * If some signals are unblocked by this service, they are handled before this
 * service returns.
 *
 * @param how if @a set is not null, a value indicating how to interpret @a set;
 *
 * @param set if not null, a signal set that will be used to modify the calling
 * thread signal mask;
 *
 * @param oset if not null, address where the previous value of the calling
 * thread signal mask will be stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EPERM, the calling context is invalid;
 * - EINVAL, @a how is not SIG_BLOCK, SIG_UNBLOCK or SIG_SETMASK.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_sigmask.html">
 * Specification.</a>
 * 
 */
int pthread_sigmask(int how, const sigset_t * set, sigset_t * oset)
{
	pse51_sigset_t *pse51_set = user2pse51_sigset(set);
	pse51_sigset_t *pse51_oset = user2pse51_sigset(oset);
	pthread_t cur = pse51_current_thread();
	pse51_sigset_t unblocked;
	spl_t s;

	if (!cur)
		return EPERM;

	emptyset(&unblocked);

	xnlock_get_irqsave(&nklock, s);

	if (pse51_oset)
		*pse51_oset = cur->sigmask;

	if (!pse51_set)
		goto unlock_and_exit;

	if (xnthread_signaled_p(&cur->threadbase))
		/* Call xnpod_schedule to deliver any soon-to-be-blocked pending
		   signal, after this call, no signal is pending. */
		xnpod_schedule();

	switch (how) {

	case SIG_BLOCK:

		orset(&cur->sigmask, &cur->sigmask, pse51_set);
		break;

	case SIG_UNBLOCK:
		/* Mark as pending any signal which was received while
		   blocked and is going to be unblocked. */
		andset(&unblocked, pse51_set, &cur->blocked_received.mask);
		andnotset(&cur->sigmask, &cur->pending.mask, &unblocked);
		break;

	case SIG_SETMASK:

		andnotset(&unblocked, &cur->blocked_received.mask, pse51_set);
		cur->sigmask = *pse51_set;
		break;

	default:

		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	/* Handle any unblocked signal. */
	if (!isemptyset(&unblocked)) {
		pse51_siginfo_t *si, *next = NULL;

		cur->threadbase.signals = 0;

		while ((si =
			pse51_getsigq(&cur->blocked_received, &unblocked,
				      &next))) {
			int sig = si->info.si_signo;
			unsigned prio;

			prio = sig < SIGRTMIN ? sig + SIGRTMAX : sig;
			addset(&cur->pending.mask, si->info.si_signo);
			insertpqfr(&cur->pending.list, &si->link, prio);
			cur->threadbase.signals = 1;

			if (!next)
				break;
		}

		/* Let pse51_dispatch_signals do the job. */
		if (cur->threadbase.signals)
			xnpod_schedule();
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

static int pse51_sigtimedwait_inner(const sigset_t * set,
				    siginfo_t * si, int timed, xnticks_t to)
{
	pse51_sigset_t non_blocked, *pse51_set = user2pse51_sigset(set);
	pse51_siginfo_t *received;
	pthread_t thread;
	int err = 0;
	spl_t s;

	thread = pse51_current_thread();

	if (!thread || xnpod_unblockable_p())
		return EPERM;

	/* All signals in "set" must be blocked in order for sigwait to
	   work reliably. */
	andnotset(&non_blocked, pse51_set, &thread->sigmask);
	if (!isemptyset(&non_blocked))
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	received = pse51_getsigq(&thread->blocked_received, pse51_set, NULL);

	if (!received) {
		thread_cancellation_point(&thread->threadbase);

		xnpod_suspend_thread(&thread->threadbase, XNDELAY,
				     timed ? to : XN_INFINITE,
				     XN_RELATIVE, NULL);

		thread_cancellation_point(&thread->threadbase);

		if (xnthread_test_info(&thread->threadbase, XNBREAK)) {
			if (!
			    (received =
			     pse51_getsigq(&thread->blocked_received, pse51_set,
					   NULL)))
				err = EINTR;
		} else if (xnthread_test_info(&thread->threadbase, XNTIMEO))
			err = EAGAIN;
	}

	if (!err) {
		*si = received->info;
		if (si->si_code == SI_QUEUE || si->si_code == SI_USER)
			pse51_delete_siginfo(received);
		else if (si->si_code == SI_TIMER)
			pse51_timer_notified(received);
		/* Nothing to be done for SI_MESQ. */
	}

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * Wait for signals.
 *
 * This service blocks a Xenomai kernel-space POSIX skin thread until a signal
 * of the set @a set is received. If a signal in @a set is not currently blocked
 * by the calling thread, this service returns immediately with an error. The
 * signal received is stored at the address @a sig.
 *
 * If a signal of the set @a set was already pending, it is cleared and this
 * service returns immediately.
 *
 * Signals are received in priority order, i.e. from SIGRTMIN to SIGRTMAX, then
 * from 1 to SIGRTMIN-1.
 *
 * @param set set of signals to wait for;
 *
 * @param sig address where the received signal will be stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EPERM, the caller context is invalid;
 * - EINVAL, a signal in @a set is not currently blocked.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigwait.html">
 * Specification.</a>
 * 
 */
int sigwait(const sigset_t * set, int *sig)
{
	siginfo_t info;
	int err;

	do {
		err = pse51_sigtimedwait_inner(set, &info, 0, XN_INFINITE);
	}
	while (err == EINTR);

	if (!err)
		*sig = info.si_signo;

	return err;
}

/**
 * Wait for signals.
 *
 * This service is equivalent to the sigwait() service, except that it returns,
 * at the address @a info, the @b siginfo_t object associated with the received
 * signal instead of only returning the signal number.
 *
 * @param set set of signals to wait for;
 *
 * @param info address where the received @b siginfo_t object will be stored on
 * success.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EPERM, the caller context is invalid;
 * - EINVAL, a signal in @a set is not currently blocked.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
* @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigwaitinfo.html">
 * Specification.</a>
 * 
 */
int sigwaitinfo(const sigset_t * __restrict__ set,
		siginfo_t * __restrict__ info)
{
	siginfo_t loc_info;
	int err;

	if (!info)
		info = &loc_info;

	do {
		err = pse51_sigtimedwait_inner(set, info, 0, XN_INFINITE);
	}
	while (err == EINTR);

	/* Sigwaitinfo does not have the same behaviour as sigwait, errors are
	   returned through errno. */
	if (err) {
		thread_set_errno(err);
		return -1;
	}

	return 0;
}

/**
 * Wait during a bounded time for signals.
 *
 * This service is equivalent to the sigwaitinfo() service, except that the
 * calling thread is only blocked until the timeout specified by @a timeout
 * expires.
 *
 * @param set set of signals to wait for;
 *
 * @param info address where the received @b siginfo_t object will be stored on
 * success;
 *
 * @param timeout the timeout, expressed as a time interval.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, the specified timeout is invalid;
 * - EPERM, the caller context is invalid;
 * - EINVAL, a signal in @a set is not currently blocked;
 * - EAGAIN, no signal was received and the specified timeout expired.
 *
 * @par Valid contexts:
 * - Xenomai POSIX skin kernel-space thread.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/sigtimedwait.html">
 * Specification.</a>
 * 
 */
int sigtimedwait(const sigset_t * __restrict__ set,
		 siginfo_t * __restrict__ info,
		 const struct timespec *__restrict__ timeout)
{
	xnticks_t to = XN_INFINITE;
	int err;

	if (timeout) {
		if ((unsigned long)timeout->tv_nsec >= ONE_BILLION) {
			err = EINVAL;
			goto out;
		}

		to = ts2ticks_ceil(timeout) + 1;
	}

	do {
		err = pse51_sigtimedwait_inner(set, info, !!timeout, to);
	}
	while (err == EINTR);

      out:
	if (err) {
		thread_set_errno(err);
		return -1;
	}

	return 0;
}

static void pse51_dispatch_signals(xnsigmask_t sigs)
{
	pse51_siginfo_t *si, *next = NULL;
	pse51_sigset_t saved_mask;
	pthread_t thread;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	thread = pse51_current_thread();

	saved_mask = thread->sigmask;

	while ((si =
		pse51_getsigq(&thread->pending, &thread->pending.mask,
			      &next))) {
		struct sigaction *action = &actions[si->info.si_signo - 1];
		siginfo_t info = si->info;

		if (si->info.si_code == SI_TIMER)
			pse51_timer_notified(si);

		if (si->info.si_code == SI_QUEUE || si->info.si_code == SI_USER)
			pse51_delete_siginfo(si);

		/* Nothing to be done for SI_MESQ. */

		if (action->sa_handler != SIG_IGN) {
			int use_info = testbits(action->sa_flags, SA_SIGINFO);
			siginfo_handler_t *info_handler =
			    (siginfo_handler_t *) action->sa_sigaction;
			sighandler_t handler = action->sa_handler;

			if (handler == SIG_DFL)
				handler = pse51_default_handler;

			thread->sigmask = *user2pse51_sigset(&action->sa_mask);

			if (testbits(action->sa_flags, SA_RESETHAND)) {
				action->sa_flags &= ~SA_SIGINFO;
				action->sa_handler = SIG_DFL;
			}

			if (!use_info)
				handler(info.si_signo);
			else
				info_handler(info.si_signo, &info, NULL);
		}

		if (!next)
			break;
	}

	thread->sigmask = saved_mask;
	thread->threadbase.signals = 0;

	xnlock_put_irqrestore(&nklock, s);
}

#ifdef CONFIG_XENO_OPT_PERVASIVE
static void pse51_dispatch_shadow_signals(xnsigmask_t sigs)
{
	/* Migrate to secondary mode in order to get the signals delivered by
	   Linux. */
	xnshadow_relax(1);
}

static void pse51_signal_handle_request(void *cookie)
{
	int cpuid = smp_processor_id(), reqnum;
	struct pse51_signals_threadsq_t *rq = &pse51_signals_threadsq[cpuid];

	while ((reqnum = rq->out) != rq->in) {
		pthread_t thread = rq->thread[reqnum];
		pse51_siginfo_t *si;
		spl_t s;

		rq->out = (reqnum + 1) & (SIG_MAX_REQUESTS - 1);

		xnlock_get_irqsave(&nklock, s);

		thread->threadbase.signals = 0;

		while ((si = pse51_getsigq(&thread->pending,
					   &thread->pending.mask, NULL))) {
			siginfo_t info = si->info;

			if (si->info.si_code == SI_TIMER)
				pse51_timer_notified(si);

			if (si->info.si_code == SI_QUEUE
			    || si->info.si_code == SI_USER)
				pse51_delete_siginfo(si);
			/* Nothing to be done for SI_MESQ. */

			/* Release the big lock, before calling a function which may
			   reschedule. */
			xnlock_put_irqrestore(&nklock, s);

			send_sig_info(info.si_signo,
				      &info,
				      xnthread_user_task(&thread->threadbase));

			xnlock_get_irqsave(&nklock, s);

			thread->threadbase.signals = 0;
		}

		xnlock_put_irqrestore(&nklock, s);
	}
}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

void pse51_signal_init_thread(pthread_t newthread, const pthread_t parent)
{
	emptyset(&newthread->blocked_received.mask);
	initpq(&newthread->blocked_received.list);
	emptyset(&newthread->pending.mask);
	initpq(&newthread->pending.list);

	/* parent may be NULL if pthread_create is not called from a pse51 thread. */
	if (parent)
		newthread->sigmask = parent->sigmask;
	else
		emptyset(&newthread->sigmask);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (testbits(newthread->threadbase.state, XNSHADOW))
		newthread->threadbase.asr = &pse51_dispatch_shadow_signals;
	else
#endif /* CONFIG_XENO_OPT_PERVASIVE */
		newthread->threadbase.asr = &pse51_dispatch_signals;

	newthread->threadbase.asrmode = 0;
	newthread->threadbase.asrimask = 0;
}

/* Unqueue, and free any pending siginfo structure. Assume we are called nklock
   locked, IRQ off. */
void pse51_signal_cleanup_thread(pthread_t thread)
{
	pse51_sigqueue_t *queue = &thread->pending;
	pse51_siginfo_t *si;

	while (queue) {
		while ((si = pse51_getsigq(queue, &queue->mask, NULL))) {
			if (si->info.si_code == SI_TIMER)
				pse51_timer_notified(si);

			if (si->info.si_code == SI_QUEUE
			    || si->info.si_code == SI_USER)
				pse51_delete_siginfo(si);

			/* Nothing to be done for SI_MESQ. */
		}

		queue =
		    (queue ==
		     &thread->pending ? &thread->blocked_received : NULL);
	}
}

void pse51_signal_pkg_init(void)
{
	int i;

	/* Fill the pool. */
	initpq(&pse51_infos_free_list);
	for (i = 0; i < PSE51_SIGQUEUE_MAX; i++)
		pse51_delete_siginfo(&pse51_infos_pool[i]);

	for (i = 1; i <= SIGRTMAX; i++) {
		actions[i - 1].sa_handler = SIG_DFL;
		emptyset(user2pse51_sigset(&actions[i - 1].sa_mask));
		actions[i - 1].sa_flags = 0;
	}

#ifdef CONFIG_XENO_OPT_PERVASIVE
	pse51_signals_apc = rthal_apc_alloc("posix_signals_handler",
					    &pse51_signal_handle_request, NULL);

	if (pse51_signals_apc < 0)
		printk("Unable to allocate APC: %d !\n", pse51_signals_apc);
#endif /* CONFIG_XENO_OPT_PERVASIVE */
}

void pse51_signal_pkg_cleanup(void)
{
#if XENO_DEBUG(POSIX)
	int i;

	for (i = 0; i < PSE51_SIGQUEUE_MAX; i++)
		if (pse51_infos_pool[i].info.si_signo)
			xnprintf("Posix siginfo structure %p was not freed, "
				 "freeing now.\n", &pse51_infos_pool[i].info);
#endif /* XENO_DEBUG(POSIX) */

#ifdef CONFIG_XENO_OPT_PERVASIVE
	rthal_apc_free(pse51_signals_apc);
#endif /* CONFIG_XENO_OPT_PERVASIVE */
}

static void pse51_default_handler(int sig)
{
	pthread_t cur = pse51_current_thread();

	xnpod_fatal("Thread %s received unhandled signal %d.\n",
		    thread_name(cur), sig);
}

/*@}*/

EXPORT_SYMBOL(sigemptyset);
EXPORT_SYMBOL(sigfillset);
EXPORT_SYMBOL(sigaddset);
EXPORT_SYMBOL(sigdelset);
EXPORT_SYMBOL(sigismember);
EXPORT_SYMBOL(pthread_kill);
EXPORT_SYMBOL(pthread_sigmask);
EXPORT_SYMBOL(pthread_sigqueue_np);
EXPORT_SYMBOL(pse51_sigaction);

EXPORT_SYMBOL(sigpending);
EXPORT_SYMBOL(sigwait);
EXPORT_SYMBOL(sigwaitinfo);
EXPORT_SYMBOL(sigtimedwait);
