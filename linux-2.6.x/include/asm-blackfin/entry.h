#ifndef __BFIN_ENTRY_H
#define __BFIN_ENTRY_H

#include <linux/config.h>
#include <asm/setup.h>
#include <asm/page.h>

/*
 * Stack layout in 'ret_from_exception':
 *
 */

/*
 * Register %p2 is now set to the current task throughout
 * the whole kernel.
 */

#ifdef __ASSEMBLY__

#define	LFLUSH_I_AND_D	0x00000808
#define	LSIGTRAP	5

/* process bits for task_struct.flags */
#define	PF_TRACESYS_OFF	3
#define	PF_TRACESYS_BIT	5
#define	PF_PTRACED_OFF	3
#define	PF_PTRACED_BIT	4
#define	PF_DTRACE_OFF	1
#define	PF_DTRACE_BIT	5

# define SAVE_ALL_SYS		save_context_no_interrupts
# define SAVE_CONTEXT		save_context_with_interrupts

# define RESTORE_ALL_SYS	restore_context_no_interrupts
# define RESTORE_CONTEXT	restore_context_with_interrupts


/*
 * Code to save processor context.
 *  We even save the register which are preserved by a function call
 *	 - r4, r5, r6, r7, p3, p4, p5
 */
.macro save_context_with_interrupts
	
//	[--sp] = RETI;	/*orig_pc*/
	[--sp] = SYSCFG;

	[--sp] = R0;	/*orig_r0*/
	[--sp] = ( R7:0, P5:0 );
	[--sp] = fp;
	[--sp] = usp;

	[--sp] = i0;
	[--sp] = i1;
	[--sp] = i2;
	[--sp] = i3;

	[--sp] = m0;
	[--sp] = m1;
	[--sp] = m2;
	[--sp] = m3;

	[--sp] = l0;
	[--sp] = l1;
	[--sp] = l2;
	[--sp] = l3;

	[--sp] = b0;
	[--sp] = b1;
	[--sp] = b2;
	[--sp] = b3;
	[--sp] = a0.x;
	[--sp] = a0.w;
	[--sp] = a1.x;
	[--sp] = a1.w;

	[--sp] = LC0;
	[--sp] = LC1;
	[--sp] = LT0;
	[--sp] = LT1;
	[--sp] = LB0;
	[--sp] = LB1;

	[--sp] = ASTAT;

	[--sp] = r0;	/* Skip reserved */
	[--sp] = RETS;
	[--sp] = RETI;
	[--sp] = RETX;
	[--sp] = RETN;
	[--sp] = RETE;
	[--sp] = SEQSTAT;
	/*[--sp] = SYSCFG;*/
	[--sp] = r0;	/* Skip IPEND as well. */
.endm

.macro save_context_no_interrupts
	
//	[--sp] = RETI;	/* orig_pc */
	[--sp] = SYSCFG;
	[--sp] = R0;	/* orig_r0 */
	[--sp] = ( R7:0, P5:0 );
	[--sp] = fp;
	[--sp] = usp;

	[--sp] = i0;
	[--sp] = i1;
	[--sp] = i2;
	[--sp] = i3;

	[--sp] = m0;
	[--sp] = m1;
	[--sp] = m2;
	[--sp] = m3;

	[--sp] = l0;
	[--sp] = l1;
	[--sp] = l2;
	[--sp] = l3;

	[--sp] = b0;
	[--sp] = b1;
	[--sp] = b2;
	[--sp] = b3;
	[--sp] = a0.x;
	[--sp] = a0.w;
	[--sp] = a1.x;
	[--sp] = a1.w;

	[--sp] = LC0;
	[--sp] = LC1;
	[--sp] = LT0;
	[--sp] = LT1;
	[--sp] = LB0;
	[--sp] = LB1;

	[--sp] = ASTAT;

	[--sp] = r0;	/* Skip reserved */
	[--sp] = RETS;
	r0 = RETI;
	[--sp] = r0;
	[--sp] = RETX;
	[--sp] = RETN;
	[--sp] = RETE;
	[--sp] = SEQSTAT;
	/*[--sp] = SYSCFG;*/
	[--sp] = r0;	/* Skip IPEND as well. */

.endm
	 
.macro restore_context_no_interrupts
	sp += 4;	/* Skip IPEND */
	/*SYSCFG = [sp++];*/
	SEQSTAT = [sp++];
	RETE = [sp++];
	RETN = [sp++];
	RETX = [sp++];
	r0 = [sp++];
	RETI = r0;	/* Restore RETI indirectly when in exception */
	RETS = [sp++];

	sp += 4;	/* Skip Reserved */

	ASTAT = [sp++];

	LB1 = [sp++];
	LB0 = [sp++];
	LT1 = [sp++];
	LT0 = [sp++];
	LC1 = [sp++];
	LC0 = [sp++];

	a1.w = [sp++];
	a1.x = [sp++];
	a0.w = [sp++];
	a0.x = [sp++];
	b3 = [sp++];
	b2 = [sp++];
	b1 = [sp++];
	b0 = [sp++];

	l3 = [sp++];
	l2 = [sp++];
	l1 = [sp++];
	l0 = [sp++];

	m3 = [sp++];
	m2 = [sp++];
	m1 = [sp++];
	m0 = [sp++];

	i3 = [sp++];
	i2 = [sp++];
	i1 = [sp++];
	i0 = [sp++];

	/* Don't mess with USP unless we have to. Things break if we do. */
	/* usp = [sp++]; */
	sp += 4;
	fp = [sp++];

	( R7 : 0, P5 : 0) = [ SP ++ ];
	sp += 4;	/* Skip orig_r0 */
	
	SYSCFG = [sp++];
	//sp += 4;	/* Skip orig_pc */
.endm

.macro restore_context_with_interrupts
	sp += 4;	/* Skip IPEND */
	/*SYSCFG = [sp++];*/
	SEQSTAT = [sp++];
	RETE = [sp++];
	RETN = [sp++];
	RETX = [sp++];
	RETI = [sp++];
	RETS = [sp++];

	sp += 4;	/* Skip Reserved */

	ASTAT = [sp++];

	LB1 = [sp++];
	LB0 = [sp++];
	LT1 = [sp++];
	LT0 = [sp++];
	LC1 = [sp++];
	LC0 = [sp++];

	a1.w = [sp++];
	a1.x = [sp++];
	a0.w = [sp++];
	a0.x = [sp++];
	b3 = [sp++];
	b2 = [sp++];
	b1 = [sp++];
	b0 = [sp++];

	l3 = [sp++];
	l2 = [sp++];
	l1 = [sp++];
	l0 = [sp++];

	m3 = [sp++];
	m2 = [sp++];
	m1 = [sp++];
	m0 = [sp++];

	i3 = [sp++];
	i2 = [sp++];
	i1 = [sp++];
	i0 = [sp++];

	/* Don't mess with USP unless we have to. Things break if we do. */
	/* usp = [sp++]; */
	sp += 4;
	fp = [sp++];

	( R7 : 0, P5 : 0) = [ SP ++ ];
	sp += 4;	/* Skip orig_r0 */
	SYSCFG = [sp++];
	///sp += 4;	/* Skip orig_pc */
.endm

#define STR(X) STR1(X)
#define STR1(X) #X

# define PT_OFF_ORIG_R0		208
# define PT_OFF_SR		8

#endif	/* __ASSEMBLY__	*/

#endif	/* __BFIN_ENTRY_H */

