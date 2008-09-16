/*
 * Customer exception handler - do our dirty work and get out
 *
 * Copyright (c) 2007 Analog Devices Inc.
 *
 * Licensed under the GPL-2 or later.
 */

#include <linux/linkage.h>
#include <asm/blackfin.h>

ENTRY(_ex_dmach1)
	p5.h = HI(MDMA_D1_CURR_DESC_PTR);
	p5.l = LO(MDMA_D1_CURR_DESC_PTR);
	p4.h = HI(MDMA_S1_CURR_DESC_PTR);
	p4.l = LO(MDMA_S1_CURR_DESC_PTR);
	[p5] = r1;
	[p4] = r0;
	p5.l = LO(MDMA_D1_CONFIG);
	p4.l = LO(MDMA_S1_CONFIG);

	r2 = r2 >> 16 || w[p4] = r2;
	w[p5] = r2;
	csync;

	p5.h = _bfin_return_from_exception;
	p5.l = _bfin_return_from_exception;
	jump (p5);
ENDPROC(_ex_dmach1)
