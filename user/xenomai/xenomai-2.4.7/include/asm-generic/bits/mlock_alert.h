#ifndef _XENO_ASM_GENERIC_BITS_MLOCK_ALERT_H
#define _XENO_ASM_GENERIC_BITS_MLOCK_ALERT_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

__attribute__ ((weak))
int xeno_sigxcpu_no_mlock = 1;

__attribute__ ((weak, visibility ("internal")))
void xeno_handle_mlock_alert(int sig)
{
	struct sigaction sa;

	if (xeno_sigxcpu_no_mlock) {
		fprintf(stderr, "Xenomai: process memory not locked "
			"(missing mlockall?)\n");
		fflush(stderr);
		exit(4);
	}

	/* XNTRAPSW was set for the thread but no user-defined handler
	   has been set to override our internal handler, so let's
	   invoke the default signal action. */

	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGXCPU, &sa, NULL);
	pthread_kill(pthread_self(), SIGXCPU);
}

#endif /* _XENO_ASM_GENERIC_BITS_MLOCK_ALERT_H */
