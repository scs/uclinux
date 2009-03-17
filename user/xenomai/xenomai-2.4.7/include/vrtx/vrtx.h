/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_VRTX_VRTX_H
#define _XENO_VRTX_VRTX_H

#include <nucleus/types.h>

#define VRTX_SKIN_MAGIC    0x56525458
#define VRTX_SKIN_VERSION  6

#define TBSSUSP   0x0001
#define TBSMBOX   0x0002
#define TBSPUTC   0x0008
#define TBSDELAY  0x0020
#define TBSQUEUE  0x0040
#define TBSIDLE   0x0100
#define TBSFLAG   0x0200
#define TBSSEMA   0x0400
#define TBSMUTEX  0x0800
#define TBSADELAY 0x8000

#define RET_OK   0x00
#define ER_TID   0x01
#define ER_TCB   0x02
#define ER_MEM   0x03
#define ER_NMB   0x04
#define ER_MIU   0x05
#define ER_ZMW   0x06
#define ER_BUF   0x07
#define ER_TMO   0x0A
#define ER_NMP   0x0B
#define ER_QID   0x0C
#define ER_QFL   0x0D
#define ER_PID   0x0E
#define ER_IIP   0x12
#define ER_NOCB  0x30
#define ER_ID    0x31
#define ER_PND   0x32
#define ER_DEL   0x33
#define ER_OVF   0x34

#define seconds      tv_sec
#define nanoseconds  tv_nsec

typedef struct _TCB {

	int TCBSTAT;

} TCB;

typedef struct _vrtx_hdesc {

	int hid;
	void *hcb;
	size_t hsize;

} vrtx_hdesc_t;

typedef struct _vrtx_pdesc {

	int pid;
	void *ptcb;
	size_t ptsize;

} vrtx_pdesc_t;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void ui_timer(void);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include <vrtx/syscall.h>

#endif /* __KERNEL__ || __XENO_SIM__ */

/*
 * The following macros return normalized or native VRTX priority
 * values. The core pod uses an ascending [0-257] priority scale
 * (include/nucleus/core.h), whilst the VRTX personality exhibits a
 * decreasing scale [255-0]; normalization is done in the [1-256]
 * range so that priority 0 is kept for non-realtime shadows.
 */
#define vrtx_normalized_prio(prio)  \
  ({ int __p = (prio) ? XNCORE_MAX_PRIO - (prio) - 1 : 0; __p; })
#define vrtx_denormalized_prio(prio) \
  ({ int __p = (prio) ? 256 - (prio) : 0; __p; })

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void sc_putc(int c);

int sc_tecreate(void (*entry)(void *),
		int tid,
		int prio,
		int mode,
		unsigned long user,
		unsigned long sys,
		char *paddr,
		unsigned long psize,
		int *errp);

int sc_tcreate(void (*entry)(void*),
	       int tid,
	       int prio,
	       int *errp);

void sc_tdelete(int tid,
		int opt,
		int *errp);

TCB *sc_tinquiry(int pinfo[],
		 int tid,
		 int *errp);

void sc_tpriority(int tid,
		  int prio,
		  int *errp);

void sc_tresume(int tid,
		int opt,
		int *errp);

void sc_tslice(unsigned short ticks);

void sc_tsuspend(int tid,
		 int opt,
		 int *errp);

void sc_lock(void);

void sc_unlock(void);

int sc_mcreate(unsigned int opt,
	       int *errp);

void sc_maccept(int mid,
		int *errp);

void sc_mdelete(int mid,
		int opt, int *errp);

int sc_minquiry(int mid,
		int *errp);

void sc_mpend(int mid,
	      unsigned long timeout,
	      int *errp);

void sc_mpost(int mid,
	      int *errp);

int sc_qcreate(int qid,
	       int qsize,
	       int *errp);

int sc_qecreate(int qid,
		int qsize,
		int opt,
		int *errp);
  
void sc_qdelete(int qid,
		int opt,
		int *errp);
  
void sc_qjam(int qid,
	     char *msg,
	     int *errp);

void sc_qpost(int qid,
	      char *msg,
	      int *errp);

void sc_qbrdcst(int qid,
	       char *msg,
	       int *errp);

char *sc_qaccept(int qid,
		 int *errp);

char *sc_qinquiry(int qid,
		  int *countp,
		  int *errp);

char *sc_qpend(int qid,
	       long timeout,
	       int *errp);

void sc_post(char **mboxp,
	     char *msg,
	     int *errp);

char *sc_accept(char **mboxp,
		int *errp);

char *sc_pend(char **mboxp,
	      long timeout,
	      int *errp);

int sc_fcreate(int *errp);

void sc_fdelete(int fid,
		int opt,
		int *errp);

void sc_fpost(int fid,
	      int mask,
	      int *errp);

int sc_fpend(int fid,
	     long timeout,
	     int mask,
	     int opt,
	     int *errp);

int sc_fclear(int fid,
	      int mask,
	      int *errp);

int sc_finquiry(int fid,
		int *errp);

int sc_screate(unsigned initval,
	       int opt,
	       int *errp);

void sc_sdelete(int semid,
		int opt,
		int *errp);

void sc_spend(int semid,
	      long timeout,
	      int *errp);

void sc_saccept(int semid,
	      int *errp);

void sc_spost(int semid,
	      int *errp);

int sc_sinquiry(int semid,
		int *errp);

int sc_pcreate(int pid,
	       char *paddr,
	       long psize,
	       long bsize,
	       int *errp);

void sc_pdelete(int tid,
		int opt,
		int *errp);

void sc_pextend(int pid,
		char *eaddr,
		long esize,
		int *errp);

void sc_pinquiry(unsigned long info[3],
		 int pid,
		 int *errp);

char *sc_gblock(int pid,
		int *errp);

void sc_rblock(int pid,
	       char *blockp,
	       int *errp);

int sc_hcreate(char *heapaddr,
	       unsigned long heapsize,
	       unsigned log2psize,
	       int *errp);

void sc_hdelete(int hid,
		int opt,
		int *errp);

char *sc_halloc(int hid,
		unsigned long size,
		int *errp);

void sc_hfree(int hid,
	      char *block,
	      int *errp);

void sc_hinquiry(int info[3],
		 int hid,
		 int *errp);

void sc_delay(long timeout);

void sc_adelay (struct timespec time,
		int *errp);

void sc_stime(unsigned long ticks);

unsigned long sc_gtime(void);

void sc_gclock(struct timespec *timep,
	       unsigned long *nsp,
	       int *errp);

void sc_sclock(struct timespec time,
	       unsigned long ns,
	       int *errp);

int sc_gversion(void);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* !_XENO_VRTX_VRTX_H */
