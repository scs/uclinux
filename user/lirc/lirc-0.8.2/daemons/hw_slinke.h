/*      $Id: hw_slinke.h,v 5.2 2002/05/04 09:36:27 lirc Exp $      */

/****************************************************************************
 ** hw_slinke.h *************************************************************
 ****************************************************************************
 *
 * routines for Slink-e
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *	modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
 *  modified for Slink-e receiver by Max Spring <mspring@employees.org>
 */

#ifndef _HW_SLINKE_H
#define _HW_SLINKE_H

#include "drivers/lirc.h"

int slinke_decode(struct ir_remote *remote
                 ,ir_code          *prep
                 ,ir_code          *codep
                 ,ir_code          *postp
                 ,int              *repeat_flagp
                 ,lirc_t           *remaining_gapp);
                 
int slinke_init(void);
int slinke_deinit(void);
char *slinke_rec(struct ir_remote *remotes);
lirc_t slinke_readdata(lirc_t timetout);

#endif
