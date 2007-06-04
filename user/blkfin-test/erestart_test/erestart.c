#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>

#define ERRNOVAL -516 /* ERESTART_RESTARTBLOCK */

void sighandler (int x)
{
    signal (SIGALRM, sighandler);
}

int main ()
{
    register int r0 asm("R0");
    register int p0 asm("P0");
    struct itimerval itv;
    int x, y, i,j;
    int fail, total_fail = 0;

    signal (SIGALRM, sighandler);
    itv.it_value.tv_sec = 0;
    itv.it_value.tv_usec = 10000;
    itv.it_interval = itv.it_value;
    setitimer (ITIMER_REAL, &itv, NULL);

    for (j = 0; j < 10000; j++) {
	fail = 0;
	/* Cycle through ERESTARTSYS..ERESTART_RESTARTBLOCK.  */
	int errnoval = -512 - (j % 5);
	for (i = x = y = 0; i < 10000; i++) {
	    r0 = errnoval;
	    p0 = 5;
	    asm ("%0 += 1; %1 += 1;" : "=da" (x), "=da" (y) : "0" (x), "1" (y));
	    asm volatile ("" : "=d" (r0), "=a" (p0) : "0" (r0), "1" (p0));
	    if (r0 != errnoval)
		fail++;
	}
	if (fail || x != y) {
	    total_fail++;
	    printf ("FAIL\n");
	}
    }
    if (!total_fail)
	printf ("PASS\n");
}
