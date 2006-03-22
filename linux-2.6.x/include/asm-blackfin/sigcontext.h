#ifndef _ASM_BLACKFIN_SIGCONTEXT_H
#define _ASM_BLACKFIN_SIGCONTEXT_H

/* Add new entries at the end of the structure only.  */
struct sigcontext {
	unsigned long sc_mask;	/* old sigmask */
	unsigned long sc_usp;	/* old user stack pointer */
	unsigned long sc_r0;
	unsigned long sc_r1;
	unsigned long sc_p0;
	unsigned long sc_p1;
	unsigned long sc_p2;
	unsigned long sc_p3;
	unsigned short sc_seqstat;
	unsigned long sc_pc;
	unsigned long sc_retx;
	unsigned long sc_rets;
	unsigned long sc_r2;
	unsigned long sc_r3;
	unsigned long sc_r4;
	unsigned long sc_l0;
	unsigned long sc_l1;
	unsigned long sc_l2;
	unsigned long sc_l3;
};

#endif
