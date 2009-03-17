/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _UITRON_UITRON_H
#define _UITRON_UITRON_H

#include <uitron/syscall.h>

#define uITRON_SKIN_MAGIC   0x54524F4E

/*
 * Common Constants and Data Structure Packet Formats
 */

#define NADR   (-1)   /* invalid address or pointer value */
#ifndef TRUE
#define TRUE     1    /* true */
#define FALSE    0    /* false */
#endif /* !TRUE */

#define TMO_POL  0     /* polling */
#define TMO_FEVR (-1)  /* wait forever */

typedef signed char B;		/* signed 8-bit integer */
typedef signed short H;		/* signed 16-bit integer */
typedef signed int W;		/* signed 32-bit integer */
typedef unsigned UB;		/* unsigned 8-bit integer */
typedef unsigned short UH;      /* unsigned 16-bit integer */
typedef unsigned int UW;        /* unsigned 32-bit integer */

typedef unsigned VW;            /* unpredictable data type (32-bit size) */
typedef unsigned short VH;      /* unpredictable data type (16-bit size) */
typedef unsigned char VB;	/* unpredictable data type (8-bit size) */

typedef void *VP;		/* pointer to an unpredictable data type */
typedef void (*FPTR)(void);	/* program start address -- should be FP, but conflicts */

typedef W INT;
typedef UW UINT;
typedef W BOOL;
typedef H FN;
typedef W ID;
typedef ID BOOL_ID;
typedef W HNO;
typedef W RNO;
typedef W NODE;
typedef UW ATR;
typedef W ER;
typedef W PRI;
typedef W TMO;

/* for task management functions */

typedef struct t_ctsk {

    VP    exinf;     /* extended information */
    ATR   tskatr;    /* task attributes */
    FPTR  task;      /* task start address */
    PRI   itskpri;   /* initial task priority */
    INT   stksz;     /* stack size */

    /* No implementation-dependent part */

} T_CTSK;

#define TA_ASM    0x0      /* program written in assembly language */
#define TA_HLNG   0x1      /* program written in high-level language */
#define TA_COP0   0x8000   /* uses coprocessor having ID = 0 */
#define TA_COP1   0x4000   /* uses coprocessor having ID = 1 */
#define TA_COP2   0x2000   /* uses coprocessor having ID = 2 */
#define TA_COP3   0x1000   /* uses coprocessor having ID = 3 */
#define TA_COP4   0x0800   /* uses coprocessor having ID = 4 */
#define TA_COP5   0x0400   /* uses coprocessor having ID = 5 */
#define TA_COP6   0x0200   /* uses coprocessor having ID = 6 */
#define TA_COP7   0x0100   /* uses coprocessor having ID = 7 */
#define TA_SHADOW 0x1000   /* shadow task (Xenomai user-space task) */

#define TSK_SELF  0   /* task specifies itself */

#define TPRI_INI  0   /* specifies the initial priority on task startup
			 (chg_pri) */
#define TPRI_RUN  0   /* specifies the highest priority during execution
			 (rot_rdq) */

typedef struct t_rtsk {
    VP     exinf;     /* extended information */
    PRI    tskpri;    /* current priority */
    UINT   tskstat;   /* task state */
    /* the following are represent extended features of support
       [level X] (implementation-dependent) */
    UINT   tskwait;   /* cause of wait */
    ID     wid;       /* ID of object being waited for */
    INT    wupcnt;    /* wakeup request count */
    INT    suscnt;    /* SUSPEND request count */
    ATR    tskatr;    /* task attributes */
    FPTR   task;      /* task start address */
    PRI    itskpri;   /* initial task priority */
    INT    stksz;     /* stack size */

    /* Implementation-dependent part */

} T_RTSK;


#define TTS_RUN  0x01   /* RUN */
#define TTS_RDY  0x02   /* READY */
#define TTS_WAI  0x04   /* WAIT */
#define TTS_SUS  0x08   /* SUSPEND */
#define TTS_WAS  0x0C   /* WAIT-SUSPEND */
#define TTS_DMT  0x10   /* DORMANT */

#define TTW_SLP  0x0001   /* wait due to slp_tsk or tslp_tsk */
#define TTW_DLY  0x0002   /* wait due to dly_tsk */
#define TTW_NOD  0x0008   /* connection function response wait */
#define TTW_FLG  0x0010   /* wait due to wai_flg or twai_flg */
#define TTW_SEM  0x0020   /* wait due to wai_sem or twai_sem */
#define TTW_MBX  0x0040   /* wait due to rcv_msg or trcv_msg */
#define TTW_SMBF 0x0080   /* wait due to snd_mbf or tsnd_mbf */
#define TTW_MBF  0x0100   /* wait due to rcv_mbf or trcv_mbf */
#define TTW_CAL  0x0200   /* wait for rendezvous call */
#define TTW_ACP  0x0400   /* wait for rendezvous accept */
#define TTW_RDV  0x0800   /* wait for rendezvous completion */
#define TTW_MPL  0x1000   /* wait due to get_blk or tget_blk */
#define TTW_MPF  0x2000   /* wait due to get_blf or tget_blf */

/* for semaphore functions */

typedef struct t_csem {
    VP    exinf;    /* extended information */
    ATR   sematr;   /* semaphore attributes */
    /* Following is the extended function for [level X]. */
    INT   isemcnt;   /* initial semaphore count */
    INT   maxsem;    /* maximum semaphore count */

    /* Implementation-dependent part */

} T_CSEM;

#define TA_TFIFO 0x00   /* waiting tasks are handled by FIFO */
#define TA_TPRI  0x01   /* waiting tasks are handled by priority */

typedef struct t_rsem {
    VP      exinf;    /* extended information */
    BOOL_ID wtsk;     /* indicates whether or not there is a waiting
			 task */
    INT     semcnt;   /* current semaphore count */

    /* Implementation-dependent part */

} T_RSEM;

/* for eventflag functions */

typedef struct t_cflg {
    VP     exinf;     /* extended information */
    ATR    flgatr;    /* eventflag attribute */
    UINT   iflgptn;   /* initial eventflag */

    /* Implementation-dependent part */

} T_CFLG;

#define TA_WSGL 0x00   /* multiple tasks are not allowed to wait (Wait
			  Single Task) */
#define TA_WMUL 0x08   /* multiple tasks are allowed to wait (Wait
			  Multiple Task) */

#define TWF_ANDW 0x00   /* AND wait */
#define TWF_ORW  0x02   /* OR wait */
#define TWF_CLR  0x01   /* clear specification */

typedef struct t_rflg {
    VP        exinf;      /* extended information */
    BOOL_ID   wtsk;       /* indicates whether or not there is a
			     waiting task */
    UINT      flgptn;     /* eventflag bit pattern */

    /* Implementation-dependent part */

} T_RFLG;

/* for mailbox functions */

typedef struct t_cmbx {
    VP    exinf;    /* extended information */
    ATR   mbxatr;   /* mailbox attributes */
    /* Following is implementation-dependent function */
    INT   bufcnt;   /* ring buffer size */

    /* Implementation-dependent part */

} T_CMBX;

#define TA_MFIFO  0x00   /* messages are handled by FIFO */
#define TA_MPRI   0x02   /* messages are handled by priority */

typedef struct t_msg {

    /* Implementation-dependent part */

    VB   msgcont[1];
} T_MSG;

typedef struct t_rmbx {
    VP        exinf;    /* extended information */
    BOOL_ID   wtsk;     /* indicates whether or not there is a
			   waiting task */
    T_MSG*    pk_msg;   /* message to be sent next */

    /* Implementation-dependent part */

} T_RMBX;

/* for messagebuffer functions */

typedef struct t_cmbf {
    VP    exinf;    /* extended information */
    ATR   mbfatr;   /* messagebuffer attributes */
    INT   bufsz;    /* messagebuffer size */
    INT   maxmsz;   /* maximum size of messages */

    /* Implementation-dependent part */

} T_CMBF;

#define TMBF_OS  (-4)   /* messagebuffer used for OS error log */
#define TMBF_DB  (-3)   /* messagebuffer used for debugging */

typedef struct t_rmbf {
    VP        exinf;     /* extended information */
    BOOL_ID   wtsk;      /* indicates whether or not there is a
			    task waiting to receive a message */
    BOOL_ID   stsk;      /* indicates whether or not there is a
			    task waiting to send a message */
    INT       msgsz;     /* size of message to be sent next */
    INT       frbufsz;   /* size of free buffer */

    /* Implementation-dependent part */

} T_RMBF;

/* for port or rendezvous functions */

typedef struct t_cpor {
    VP    exinf;     /* extended information */
    ATR   poratr;    /* port attributes */
    INT   maxcmsz;   /* maximum call message size */
    INT   maxrmsz;   /* maximum reply message size */

    /* Implementation-dependent part */

} T_CPOR;

#define TA_NULL 0   /* specifies no particular attributes */

typedef struct t_rpor {
    VP        exinf;   /* extended information */
    BOOL_ID   wtsk;    /* indicates whether or not there is a task
			  waiting to call a rendezvous */
    BOOL_ID   atsk;    /* indicates whether or not there is a task
			  waiting to accept a rendezvous */

    /* Implementation-dependent part */

} T_RPOR;

/* for interrupt management functions */

typedef struct t_dint {
    ATR   intatr;   /* interrupt handler attributes */
    FPTR  inthdr;   /* interrupt handler address */

    /* Implementation-dependent part */

} T_DINT;

/* for memorypool management functions */

typedef struct t_cmpl {
    VP    exinf;    /* extended information */
    ATR   mplatr;   /* memorypool attributes */
    INT   mplsz;    /* memorypool size */

    /* Implementation-dependent part */

} T_CMPL;

#define TMPL_OS  (-4)   /* memorypool used by OS */

typedef struct t_rmpl {
    VP        exinf;    /* extended information */
    BOOL_ID   wtsk;     /* indicates whether or not there are
			   waiting tasks */
    INT       frsz;     /* total size of free memory */
    INT       maxsz;    /* size of largest contiguous memory */

    /* Implementation-dependent part */

} T_RMPL;

typedef struct t_cmpf {
    VP    exinf;     /* extended information */
    ATR   mpfatr;    /* memorypool attributes */
    INT   mpfcnt;    /* block count for entire memorypool */
    INT   blfsz;     /* fixed-size memory block size */

    /* Implementation-dependent part */

} T_CMPF;

typedef struct t_rmpf {
    VP        exinf;    /* extended information */
    BOOL_ID   wtsk;     /* indicates whether or not there are
			   waiting tasks */
    INT       frbcnt;   /* free block count */

    /* Implementation-dependent part */

} T_RMPF;

/* for time management functions */

typedef struct t_systime {
    H    utime;   /* upper 16 bits */
    UW   ltime;   /* lower 32 bits */
} SYSTIME, CYCTIME, ALMTIME, DLYTIME;

typedef struct t_dcyc {
    VP        exinf;    /* extended information */
    ATR       cycatr;   /* cyclic handler attributes */
    FPTR      cychdr;   /* cyclic handler address */
    UINT      cycact;   /* cyclic handler activation */
    CYCTIME   cyctim;   /* cyclic startup period */
} T_DCYC;

#define TCY_OFF  0x00   /* do not invoke cyclic handler */
#define TCY_ON   0x01   /* invoke cyclic handler */
#define TCY_INT  0x02   /* initialize cycle count */

typedef struct t_rcyc {
    VP        exinf;    /* extended information */
    CYCTIME   lfttim;   /* time left before next handler startup */
    UINT      cycact;   /* cyclic handler activation */

    /* Implementation-dependent part */

} T_RCYC;

typedef struct t_dalm {
    VP        exinf;    /* extended information */
    ATR       almatr;   /* alarm handler attributes */
    FPTR      almhdr;   /* alarm handler address */
    UINT      tmmode;   /* start time specification mode */
    ALMTIME   almtim;   /* handler startup time */
} T_DALM;

#define TTM_ABS  0x00   /* specified as an absolute time */
#define TTM_REL  0x01   /* specified as a relative time */

typedef struct t_ralm {
    VP        exinf;    /* extended information */
    ALMTIME   lfttim;   /* time left before next handler startup */

    /* Implementation-dependent part */

} T_RALM;

/* for system management functions */

typedef struct t_ver {
    UH   maker;     /* vendor */
    UH   id;        /* format number */
    UH   spver;     /* specification version */
    UH   prver;     /* product version */
    UH   prno[4];   /* product control information */
    UH   cpu;       /* CPU information */
    UH   var;       /* variation descriptor */
} T_VER;

typedef struct t_rsys {
    INT   sysstat;   /* system state */

    /* Implementation-dependent part */

} T_RSYS;

#define TSS_TSK  0   /* normal state in which dispatching is enabled during
			task portion execution */
#define TSS_DDSP 1   /* state after dis_dsp has been executed during task
			portion execution (dispatch disabled) */
#define TSS_LOC  3   /* state after loc_cpu has been executed during task
			portion execution (interrupt and dispatch disabled) */
#define TSS_INDP 4   /* state during execution of task-independent portions
			(interrupt and timer handlers) */

typedef struct t_rcfg {

    /* Implementation-dependent part */

} T_RCFG;

typedef struct t_dsvc {
    ATR   svcatr;   /* extended SVC handler attributes */
    FPTR  svchdr;   /* extended SVC handler address */

    /* Implementation-dependent part */

} T_DSVC;

typedef struct t_dexc {
    ATR   excatr;   /* exception handler attributes */
    FPTR  exchdr;   /* exception handler address */

    /* Implementation-dependent part */

} T_DEXC;

#define E_OK       0       /* Normal completion */
#define E_SYS      (-5)    /* System error */
#define E_NOMEM    (-10)   /* Insufficient memory */
#define E_NOSPT    (-17)   /* Feature not supported */
#define E_INOSPT   (-18)   /* Feature not supported  */
#define E_RSFN     (-20)   /* Reserved function code number */
#define E_RSATR    (-24)   /* Reserved attribute */
#define E_PAR      (-33)   /* Parameter error */
#define E_ID       (-35)   /* Invalid ID number */
#define E_NOEXS    (-52)   /* Object does not exist */
#define E_OBJ      (-63)   /* Invalid object state */
#define E_MACV     (-65)   /* Memory access disabled/invalid */
#define E_OACV     (-66)   /* Object access violation */
#define E_CTX      (-69)   /* Context error */
#define E_QOVR     (-73)   /* Queuing or nesting overflow */
#define E_DLT      (-81)   /* Object being waited for was deleted */
#define E_TMOUT    (-85)   /* Polling failure or timeout exceeded */
#define E_RLWAI    (-86)   /* WAIT state was forcibly released */
#define EN_CTXID   (-121)  /* Task-related call in non-task context */

/*
 * The following macros return normalized or native priority values
 * for the underlying pod. The core pod providing user-space support
 * uses an ascending [0..257] priority scale (include/nucleus/core.h),
 * whilst the uITRON personality exhibits a decreasing scale
 * [8..1]. We normalize to the range [92..99], leaving 0 unchanged.
 */
#define ui_normalized_prio(prio)	({ int __p = (prio) ? XNCORE_HIGH_PRIO - (prio) + 1 : 0; __p; })
#define ui_denormalized_prio(prio)	ui_normalized_prio(prio)

#ifdef __cplusplus
extern "C" {
#endif

/* Task Management Functions */

ER cre_tsk(ID tskid,
	   T_CTSK *pk_ctsk);

ER shd_tsk(ID tskid, /* Shadow task - Xenomai extension. */
	   T_CTSK *pk_ctsk);

ER del_tsk(ID tskid);

ER sta_tsk(ID tskid,
	   INT stacd);

void ext_tsk(void);

void exd_tsk(void);

ER ter_tsk(ID tskid);

ER dis_dsp(void);

ER ena_dsp(void);

ER chg_pri(ID tskid,
	   PRI tskpri);

ER rot_rdq(PRI tskpri);

ER rel_wai(ID tskid);

ER get_tid(ID *p_tskid);

ER ref_tsk(T_RTSK *pk_rtsk,
	   ID tskid);

ER sus_tsk(ID tskid);

ER rsm_tsk(ID tskid);

ER frsm_tsk(ID tskid);

ER slp_tsk(void);

ER tslp_tsk(TMO tmout);

ER wup_tsk(ID tskid);

ER can_wup(INT *p_wupcnt,
	   ID tskid);

/* Synchronization and Communication Functions */

ER cre_sem(ID semid,
	   T_CSEM *pk_csem);

ER del_sem(ID semid);

ER sig_sem(ID semid);

ER wai_sem(ID semid);

ER preq_sem(ID semid);

ER twai_sem(ID semid,
	    TMO tmout);

ER ref_sem(T_RSEM *pk_rsem,
	   ID semid);

ER cre_flg(ID flgid,
	   T_CFLG *pk_cflg);

ER del_flg(ID flgid);

ER set_flg(ID flgid,
	   UINT setptn);

ER clr_flg(ID flgid,
	   UINT clrptn);

ER wai_flg(UINT *p_flgptn,
	   ID flgid,
	   UINT waiptn,
	   UINT wfmode);

ER pol_flg(UINT *p_flgptn,
	   ID flgid,
	   UINT waiptn,
	   UINT wfmode);

ER twai_flg(UINT *p_flgptn,
	    ID flgid,
	    UINT waiptn,
	    UINT wfmode,
	    TMO tmout);

ER ref_flg(T_RFLG *pk_rflg,
	   ID flgid);

ER cre_mbx(ID mbxid,
	   T_CMBX* pk_cmbx);

ER del_mbx(ID mbxid);

ER snd_msg(ID mbxid,
	   T_MSG *pk_msg);

ER rcv_msg(T_MSG **ppk_msg,
	   ID mbxid);

ER prcv_msg(T_MSG **ppk_msg,
	    ID mbxid);

ER trcv_msg(T_MSG **ppk_msg,
	    ID mbxid,
	    TMO tmout);

ER ref_mbx(T_RMBX *pk_rmbx,
	   ID mbxid);

/* Extended Synchronization and Communication Functions */

ER cre_mbf(ID mbfid,
	   T_CMBF *pk_cmbf);

ER del_mbf(ID mbfid);

ER snd_mbf(ID mbfid,
	   VP msg,
	   INT msgsz);

ER psnd_mbf(ID mbfid,
	    VP msg,
	    INT msgsz);

ER tsnd_mbf(ID mbfid,
	    VP msg,
	    INT msgsz,
	    TMO tmout);

ER rcv_mbf(VP msg,
	   INT *p_msgsz,
	   ID mbfid);

ER prcv_mbf(VP msg,
	    INT *p_msgsz,
	    ID mbfid);

ER trcv_mbf(VP msg,
	    INT *p_msgsz,
	    ID mbfid,
	    TMO tmout);

ER ref_mbf(T_RMBF *pk_rmbf,
	   ID mbfid);

ER cre_por(ID porid,
	   T_CPOR *pk_cpor);

ER del_por(ID porid);

ER cal_por(VP msg,
	   INT *p_rmsgsz,
	   ID porid,
	   UINT calptn,
	   INT cmsgsz);

ER pcal_por(VP msg,
	    INT *p_rmsgsz,
	    ID porid,
	    UINT calptn,
	    INT cmsgsz);

ER tcal_por(VP msg,
	    INT *p_rmsgsz,
	    ID porid,
	    UINT calptn,
	    INT cmsgsz,
	    TMO tmout);

ER acp_por(RNO *p_rdvno,
	   VP msg,
	   INT *p_cmsgsz,
	   ID porid,
	   UINT acpptn);

ER pacp_por(RNO *p_rdvno,
	    VP msg,
	    INT *p_cmsgsz,
	    ID porid,
	    UINT acpptn);

ER tacp_por(RNO *p_rdvno,
	    VP msg,
	    INT *p_cmsgsz,
	    ID porid,
	    UINT acpptn,
	    TMO tmout);

ER  fwd_por(ID porid,
	    UINT calptn,
	    RNO rdvno,
	    VP msg,
	    INT cmsgsz);

ER rpl_rdv(RNO rdvno,
	   VP msg,
	   INT rmsgsz);

ER ref_por(T_RPOR *pk_rpor,
	   ID porid);

/* Interrupt Management Functions */

ER def_int(UINT dintno,
	   T_DINT *pk_dint);

void ret_int(void);

void ret_wup(ID tskid);

ER loc_cpu(void);

ER unl_cpu(void);

ER dis_int(UINT eintno);

ER ena_int(UINT eintno);

/* Memorypool Management Functions */

ER cre_mpl(ID mplid,
	   T_CMPL *pk_cmpl);

ER del_mpl(ID mplid);

ER get_blk(VP *p_blk,
	   ID mplid,
	   INT blksz);

ER pget_blk(VP *p_blk,
	    ID mplid,
	    INT blksz);

ER tget_blk(VP *p_blk,
	    ID mplid,
	    INT blksz,
	    TMO tmout);

ER rel_blk(ID mplid,
	   VP blk);

ER ref_mpl(T_RMPL *pk_rmpl,
	   ID mplid);

ER cre_mpf(ID mpfid,
	   T_CMPF *pk_cmpf);

ER del_mpf(ID mpfid);

ER get_blf(VP *p_blf,
	   ID mpfid);

ER pget_blf(VP *p_blf,
	    ID mpfid);

ER tget_blf(VP *p_blf,
	    ID mpfid,
	    TMO tmout);

ER rel_blf(ID mpfid,
	   VP blf);

ER ref_mpf(T_RMPF *pk_rmpf,
	   ID mpfid);

/* Time Management Functions */

ER set_tim(SYSTIME *pk_tim);

ER get_tim(SYSTIME *pk_tim);

ER dly_tsk(DLYTIME dlytim);

ER def_cyc(HNO cycno,
	   T_DCYC *pk_dcyc);

ER act_cyc(HNO cycno,
	   UINT cycact);

ER ref_cyc(T_RCYC *pk_rcyc,
	   HNO cycno);

ER def_alm(HNO almno,
	   T_DALM *pk_dalm);

ER ref_alm(T_RALM *pk_ralm,
	   HNO almno);

void ret_tmr(void);

/* System Management Functions */

ER get_ver(T_VER *pk_ver);

ER ref_sys(T_RSYS *pk_rsys);

ER ref_cfg(T_RCFG *pk_rcfg);

ER def_svc(FN s_fncd,
	   T_DSVC *pk_dsvc);

ER def_exc(UINT exckind,
	   T_DEXC *pk_dexc);

#ifdef __cplusplus
}
#endif

#endif /* !_UITRON_UITRON_H */
