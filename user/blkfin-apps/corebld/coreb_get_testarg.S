#include <blackfin.h>
.global start;
.global _start;
.global __stack_top;

.text
_start:
start:
	/* Enable CYCLES */
	R0 = 0x32;
	SYSCFG = R0;
	SSYNC;

	r1 = 0;
	r2 = 0;
	r3 = 0;
	r4 = 0;
	r5 = 0;
	r6 = 0;
	r7 = 0;

	p0 = 0;
	p1 = 0;
	p2 = 0;
	p3 = 0;
	p4 = 0;
	p5 = 0;

	i0 = 0;
	i1 = 0;
	i2 = 0;
	i3 = 0;
	m0 = 0;
	m1 = 0;
	m2 = 0;
	m3 = 0;
	l0 = 0;
	l1 = 0;
	l2 = 0;
	l3 = 0;
	b0 = 0;
	b1 = 0;
	b2 = 0;
	b3 = 0;

	lc0 = r0;
	lc1 = r0;

	SSYNC;

	/*
	 * Configure stack
	 */
	r0.h = __stack_top;
	r0.l = __stack_top;
	sp = r0;
	fp = sp;

	/* To keep ourselves in supervisor mode */
	p0.l = (EVT15 & 0xFFFF);
	p0.h = (EVT15 >> 16);

	p1.l = _real_start;
	p1.h = _real_start;
	[p0] = p1;

	p0.l = (IMASK & 0xFFFF);
	p0.h = (IMASK >> 16);
	r0.l = 0x8000;
	r0.h = 0xffff;
	[p0] = r0;
	raise 15;
	p0.l = WAIT_HERE;
	p0.h = WAIT_HERE;
	reti = p0;
	rti;

WAIT_HERE:
	jump WAIT_HERE;

.global _real_start;
_real_start:
	/* Enable interrupts */
	[--sp] = reti;
	r0 = [sp++];

	/* Disable WatchDog */
	p0.l = (WDOGB_CTL & 0xFFFF);
	p0.h = (WDOGB_CTL >> 16);
	r0 = ((0xad << 4) | (0x3 << 1))(z);
	w[p0] = r0;

change_arg:
	P0.H = 0xFEB0;
	P0.L = 0x0000;
	R0.H = 0x0000;
	R0.L = 0x0002;
	[P0] = R0;
do_nothing:
	IDLE;
	jump do_nothing;
