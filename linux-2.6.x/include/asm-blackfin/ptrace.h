#ifndef _BFIN_PTRACE_H
#define _BFIN_PTRACE_H


/*
 * GCC defines register number like this:
 * -----------------------------
 *       0 - 7 are data registers R0-R7
 *       8 - 15 are address registers P0-P7
 *      16 - 31 dsp registers I/B/L0 -- I/B/L3 & M0--M3
 *      32 - 33 A registers A0 & A1
 *      34 -    status register
 * -----------------------------
 *
 * We follows above, except:
 *      32-33 --- Low 32-bit of A0&1
 *      34-35 --- High 8-bit of A0&1
 */

#ifndef __ASSEMBLY__


/* this struct defines the way the registers are stored on the
   stack during a system call. */

struct pt_regs {
	long ipend;
	long seqstat;
	long rete;
	long retn;
	long retx;
	long pc;	/* PC == RETI*/
	long rets;
	long reserved;	/* Used as scratch during system calls */
	long astat;
	long lb1;
	long lb0;
	long lt1;
	long lt0;
	long lc1;
	long lc0;
	long a1w;
	long a1x;
	long a0w;
	long a0x;
	long b3;
	long b2;
	long b1;
	long b0;
	long l3;
	long l2;
	long l1;
	long l0;
	long m3;
	long m2;
	long m1;
	long m0;
	long i3;
	long i2;
	long i1;
	long i0;
	long usp;
	long fp;
	long p5;
	long p4;
	long p3;
	long p2;
	long p1;
	long p0;
	long r7;
	long r6;
	long r5;
	long r4;
	long r3;
	long r2;
	long r1;
	long r0;
	long orig_r0;
	long syscfg;
};



/* Arbitrarily choose the same ptrace numbers as used by the Sparc code. */
#define PTRACE_GETREGS            12
#define PTRACE_SETREGS            13	/* ptrace signal  */

#ifdef __KERNEL__

#ifndef PS_S
#define PS_S  (0x0c00)  
/* Bit 11:10 of SEQSTAT defines user/supervisor/debug mode
 *        00: user 
 *        01: supervisor
 *        1x: debug
 */

#define PS_M  (0x1000)  /*  I am not sure why this is required here Akbar  */
#endif

#define user_mode(regs) (!((regs)->seqstat & PS_S))
#define instruction_pointer(regs) ((regs)->pc)
extern void show_regs(struct pt_regs *);

#endif /* __KERNEL__ */
#endif /* __ASSEMBLY__ */
#endif /* _BFIN_PTRACE_H */
