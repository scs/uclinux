#ifndef _BFIN_SIGINFO_H
#define _BFIN_SIGINFO_H

#include <linux/types.h>
#include <asm-generic/siginfo.h>

#define UID16_SIGINFO_COMPAT_NEEDED

#define si_uid16	_sifields._kill._uid

#define ILL_ILLPARAOP	(__SI_FAULT|2)	/* illegal opcode combine ***********/
#define ILL_ILLEXCPT	(__SI_FAULT|4)	/* unrecoverable exception ***********/
#define ILL_CPLB_VI	(__SI_FAULT|9)	/* D/I CPLB protect violation *********/
#define IlL_CPLB_MISS	(__SI_FAULT|10)	/* D/I CPLB miss *********/
#define ILL_CPLB_MULHIT	(__SI_FAULT|11)	/* D/I CPLB multiple hit *********/

/*
 * SIGFPE si_codes
 */
#define FPE_INTDIV	(__SI_FAULT|1)	/* integer divide by zero */
#define FPE_INTOVF	(__SI_FAULT|2)	/* integer overflow */
#define FPE_FLTDIV	(__SI_FAULT|3)	/* floating point divide by zero */
#define FPE_FLTOVF	(__SI_FAULT|4)	/* floating point overflow */
#define FPE_FLTUND	(__SI_FAULT|5)	/* floating point underflow */
#define FPE_FLTRES	(__SI_FAULT|6)	/* floating point inexact result */
#define FPE_FLTINV	(__SI_FAULT|7)	/* floating point invalid operation */
#define FPE_FLTSUB	(__SI_FAULT|8)	/* subscript out of range */
#define NSIGFPE		8

/*
 * SIGSEGV si_codes
 */
#define SEGV_MAPERR	(__SI_FAULT|1)	/* address not mapped to object */
#define SEGV_ACCERR	(__SI_FAULT|2)	/* invalid permissions for mapped object */
#define NSIGSEGV	2

/*
 * SIGBUS si_codes
 */
#define BUS_OPFETCH	(__SI_FAULT|4)  /* error from instruction fetch *********/

/*
 * SIGTRAP si_codes
 */
#define TRAP_STEP	(__SI_FAULT|1)	/* single-step breakpoint**************/
#define TRAP_TRACEFLOW	(__SI_FAULT|2)	/* trace buffer overflow **************/
#define TRAP_WATCHPT	(__SI_FAULT|3)  /* watchpoint match      **************/
#define TRAP_ILLTRAP	(__SI_FAULT|4)	/* illegal trap          **************/

/*
 * SIGCHLD si_codes
 */
#define CLD_EXITED	(__SI_CHLD|1)	/* child has exited */
#define CLD_KILLED	(__SI_CHLD|2)	/* child was killed */
#define CLD_DUMPED	(__SI_CHLD|3)	/* child terminated abnormally */
#define CLD_TRAPPED	(__SI_CHLD|4)	/* traced child has trapped */
#define CLD_STOPPED	(__SI_CHLD|5)	/* child has stopped */
#define CLD_CONTINUED	(__SI_CHLD|6)	/* stopped child has continued */
#define NSIGCHLD	6

/*
 * SIGPOLL si_codes
 */
#define POLL_IN		(__SI_POLL|1)	/* data input available */
#define POLL_OUT	(__SI_POLL|2)	/* output buffers available */
#define POLL_MSG	(__SI_POLL|3)	/* input message available */
#define POLL_ERR	(__SI_POLL|4)	/* i/o error */
#define POLL_PRI	(__SI_POLL|5)	/* high priority input available */
#define POLL_HUP	(__SI_POLL|6)	/* device disconnected */
#define NSIGPOLL	6

/*
 * sigevent definitions
 * 
 * It seems likely that SIGEV_THREAD will have to be handled from 
 * userspace, libpthread transmuting it to SIGEV_SIGNAL, which the
 * thread manager then catches and does the appropriate nonsense.
 * However, everything is written out here so as to not get lost.
 */
#define SIGEV_SIGNAL	0	/* notify via signal */
#define SIGEV_NONE	1	/* other notification: meaningless */
#define SIGEV_THREAD	2	/* deliver via thread creation */

#define SIGEV_MAX_SIZE	64
#define SIGEV_PAD_SIZE	((SIGEV_MAX_SIZE/sizeof(int)) - 3)

#define sigev_notify_function	_sigev_un._sigev_thread._function
#define sigev_notify_attributes	_sigev_un._sigev_thread._attribute

#ifdef __KERNEL__
#include <linux/string.h>


extern int copy_siginfo_to_user(siginfo_t *to, siginfo_t *from);

#endif /* __KERNEL__ */
#endif
