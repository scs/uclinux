/*
 * Copyright (C) 2001-2006 Philippe Gerum <rpm@xenomai.org>.
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
 *
 * This file satisfies the references within the emulator code
 * mimicking a pSOS+ like API built upon the Xenomai nucleus.
 *
 * pSOS and pSOS+ are registered trademarks of Wind River Systems, Inc.
 */

#ifndef _PSOS_PSOS_H
#define _PSOS_PSOS_H

#include <nucleus/thread.h>

#define PSOS_SKIN_MAGIC     0x50534F53
#define PSOS_SKIN_VERSION   5

#ifndef SUCCESS
#define SUCCESS 0
#endif

#define T_NOPREEMPT   0x0001
#define T_PREEMPT     0x0000
#define T_TSLICE      0x0002
#define T_NOTSLICE    0x0000
#define T_NOASR       0x0004
#define T_ASR         0x0000
#define T_SUPV        0x2000
#define T_USER        0x0000
#define T_LEVELMASK0  0x0000
#define T_LEVELMASK1  0x0100
#define T_LEVELMASK2  0x0200
#define T_LEVELMASK3  0x0300
#define T_LEVELMASK4  0x0400
#define T_LEVELMASK5  0x0500
#define T_LEVELMASK6  0x0600
#define T_LEVELMASK7  0x0700
#define T_NOISR       0x0700
#define T_ISR         0x0000
#define T_GLOBAL      0x0001
#define T_LOCAL       0x0000
#define T_NOFPU       0x0000
#define T_FPU         0x0002

/* Those bits are Xenomai-specific. */
#define T_SHADOW      0x8000
#define  T_SHIELD      XNSHIELD
#define  T_TRAPSW      XNTRAPSW
#define  T_RPIOFF      XNRPIOFF

#define T_START_MASK   (T_NOPREEMPT|T_TSLICE|T_NOASR|T_SUPV|T_NOISR|T_LEVELMASK7)
#define T_MODE_MASK    (T_NOPREEMPT|T_TSLICE|T_NOASR|T_NOISR| \
			T_LEVELMASK7|T_SHIELD|T_TRAPSW|T_RPIOFF)

#define RN_PRIOR      0x0002
#define RN_FIFO       0x0000
#define RN_DEL        0x0004
#define RN_NODEL      0x0000
#define RN_NOWAIT     0x0001
#define RN_WAIT       0x0000

#define SM_GLOBAL     0x0001
#define SM_LOCAL      0x0000
#define SM_PRIOR      0x0002
#define SM_FIFO       0x0000
#define SM_NOWAIT     0x0001
#define SM_WAIT       0x0000

#define EV_NOWAIT     0x0001
#define EV_WAIT       0x0000
#define EV_ANY        0x0002
#define EV_ALL        0x0000

#define K_GLOBAL      0x0001
#define K_LOCAL       0x0000

#define PT_GLOBAL     0x0001
#define PT_LOCAL      0x0000
#define PT_DEL        0x0004
#define PT_NODEL      0x0000

#define Q_GLOBAL      0x0001
#define Q_LOCAL       0x0000
#define Q_PRIOR       0x0002
#define Q_FIFO        0x0000
#define Q_LIMIT       0x0004
#define Q_NOLIMIT     0x0000
#define Q_PRIBUF      0x0008
#define Q_SYSBUF      0x0000
#define Q_NOWAIT      0x0001
#define Q_WAIT        0x0000

#define ERR_TIMEOUT  0x01
#define ERR_NODENO   0x04
#define ERR_OBJDEL   0x05
#define ERR_OBJID    0x06
#define ERR_OBJTYPE  0x07
#define ERR_OBJNF    0x09

#define ERR_NOTCB    0x0E
#define ERR_NOSTK    0x0F
#define ERR_TINYSTK  0x10
#define ERR_PRIOR    0x11
#define ERR_ACTIVE   0x12
#define ERR_NACTIVE  0x13
#define ERR_SUSP     0x14
#define ERR_NOTSUSP  0x15
#define ERR_SETPRI   0x16
#define ERR_REGNUM   0x17

#define ERR_RNADDR   0x1B
#define ERR_UNITSIZE 0x1C
#define ERR_TINYUNIT 0x1D
#define ERR_TINYRN   0x1E
#define ERR_SEGINUSE 0x1F
#define ERR_TOOBIG   0x21
#define ERR_NOSEG    0x22
#define ERR_NOTINRN  0x23
#define ERR_SEGADDR  0x24
#define ERR_SEGFREE  0x25
#define ERR_RNKILLD  0x26
#define ERR_TATRNDEL 0x27

#define ERR_PTADDR   0x28
#define ERR_BUFSIZE  0x29
#define ERR_TINYPT   0x2A
#define ERR_BUFINUSE 0x2B
#define ERR_NOBUF    0x2C
#define ERR_BUFADDR  0x2D
#define ERR_BUFFREE  0x2F

#define ERR_MSGSIZ   0x31
#define ERR_BUFSIZ   0x32
#define ERR_NOQCB    0x33
#define ERR_NOMGB    0x34
#define ERR_QFULL    0x35
#define ERR_QKILLD   0x36
#define ERR_NOMSG    0x37
#define ERR_TATQDEL  0x38
#define ERR_MATQDEL  0x39
#define ERR_VARQ     0x3A
#define ERR_NOTVARQ  0x3B

#define ERR_NOEVS    0x3C
#define ERR_NOTINASR 0x3E
#define ERR_NOASR    0x3F

#define ERR_NOSCB    0x41
#define ERR_NOSEM    0x42
#define ERR_SKILLD   0x43
#define ERR_TATSDEL  0x44

#define ERR_NOTIME   0x47
#define ERR_ILLDATE  0x48
#define ERR_ILLTIME  0x49
#define ERR_ILLTICKS 0x4A
#define ERR_BADTMID  0x4C
#define ERR_TMNOTSET 0x4D
#define ERR_TOOLATE  0x4E

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define as_return() return
#define i_return()  return

u_long as_catch(void (*routine)(void),
		u_long mode);

u_long tm_tick(void);

u_long t_restart(u_long tid,
		 u_long targs[]);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include <psos+/syscall.h>

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void k_fatal(u_long err_code,
	     u_long flags);

u_long as_send(u_long tid,
	       u_long signals);

u_long ev_receive(u_long events,
		  u_long flags,
		  u_long timeout,
		  u_long *events_r);

u_long ev_send(u_long tid,
	       u_long events);

u_long pt_create(const char *name,
		 void *paddr,
		 void *laddr,
		 u_long psize,
		 u_long bsize,
		 u_long flags,
		 u_long *tid_r,
		 u_long *nbuf_r);

u_long pt_delete(u_long tid);

u_long pt_getbuf(u_long tid,
		 void **bufaddr);

u_long pt_ident(const char *name,
		u_long node,
		u_long *tid_r);

u_long pt_retbuf(u_long tid,
		 void *buf);

u_long q_broadcast(u_long qid,
		   u_long msgbuf[4],
		   u_long *count_r);

u_long q_create(const char *name,
		u_long maxnum,
		u_long flags,
		u_long *qid_r);

u_long q_delete(u_long qid);

u_long q_ident(const char *name,
	       u_long node,
	       u_long *qid_r);

u_long q_receive(u_long qid,
		 u_long flags,
		 u_long timeout,
		 u_long msgbuf[4]);

u_long q_send(u_long qid,
	      u_long msgbuf[4]);

u_long q_urgent(u_long qid,
		u_long msgbuf[4]);

u_long q_vcreate(const char *name,
		 u_long flags,
		 u_long maxnum,
		 u_long maxlen,
		 u_long *qid_r);

u_long q_vdelete(u_long qid);

u_long q_vident(const char *name,
		u_long node,
		u_long *qid_r);

u_long q_vreceive(u_long qid,
		  u_long flags,
		  u_long timeout,
		  void *msgbuf,
		  u_long buflen,
		  u_long *msglen_r);

u_long q_vsend(u_long qid,
	       void *msgbuf,
	       u_long msglen);

u_long q_vurgent(u_long qid,
		 void *msgbuf,
		 u_long msglen);

u_long q_vbroadcast(u_long qid,
		    void *msgbuf,
		    u_long msglen,
		    u_long *count_r);

u_long rn_create(const char *name,
		 void *rnaddr,
		 u_long rnsize,
		 u_long usize,
		 u_long flags,
		 u_long *rnid_r,
		 u_long *allocsize_r);

u_long rn_delete(u_long rnid);

u_long rn_getseg(u_long rnid,
		 u_long size,
		 u_long flags,
		 u_long timeout,
		 void **segaddr);

u_long rn_ident(const char *name,
		u_long *rnid_r);

u_long rn_retseg(u_long rnid,
		 void *segaddr);

u_long sm_create(const char *name,
		 u_long icount,
		 u_long flags,
		 u_long *smid_r);

u_long sm_delete(u_long smid);

u_long sm_ident(const char *name,
		u_long node,
		u_long *smid_r);

u_long sm_p(u_long smid,
	    u_long flags,
	    u_long timeout);

u_long sm_v(u_long smid);

u_long t_create(const char *name,
		u_long prio,
		u_long sstack,
		u_long ustack,
		u_long flags,
		u_long *tid_r);

u_long t_shadow(const char *name, /* Xenomai extension. */
		u_long prio,
		u_long flags,
		u_long *tid_r);

u_long t_delete(u_long tid);

u_long t_getreg(u_long tid,
		u_long regnum,
		u_long *regvalue_r);

u_long t_ident(const char *name,
	       u_long node,
	       u_long *tid_r);

u_long t_mode(u_long clrmask,
	      u_long setmask,
	      u_long *oldmode_r);

u_long t_resume(u_long tid);

u_long t_setpri(u_long tid,
		u_long newprio,
		u_long *oldprio_r);

u_long t_setreg(u_long tid,
		u_long regnum,
		u_long regvalue);

u_long t_start(u_long tid,
	       u_long mode,
	       void (*startaddr)(u_long a0,
				 u_long a1,
				 u_long a2,
				 u_long a3),
	       u_long targs[]);

u_long t_suspend(u_long tid);

u_long tm_cancel(u_long tmid);

u_long tm_evafter(u_long ticks,
		  u_long events,
		  u_long *tmid_r);

u_long tm_evevery(u_long ticks,
		  u_long events,
		  u_long *tmid_r);

u_long tm_evwhen(u_long date,
		 u_long time,
		 u_long ticks,
		 u_long events,
		 u_long *tmid_r);

u_long tm_get(u_long *date_r,
	      u_long *time_r,
	      u_long *ticks_r);

u_long tm_set(u_long date,
	      u_long time,
	      u_long ticks);

u_long tm_wkafter(u_long ticks);

u_long tm_wkwhen(u_long date,
		 u_long time,
		 u_long ticks);

u_long tm_getm(unsigned long long *ns_r); /* Xenomai extension. */

u_long tm_signal(u_long value,	/* Xenomai extension. */
		 u_long interval,
		 int signo,
		 u_long *tmid_r);

u_long tm_getc(unsigned long long *ticks_r); /* Xenomai extension. */

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* !_PSOS_PSOS_H */
