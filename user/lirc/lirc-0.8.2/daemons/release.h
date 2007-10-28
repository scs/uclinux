/*      $Id: release.h,v 1.1 2007/05/06 11:54:02 lirc Exp $      */

/****************************************************************************
 ** release.h ***************************************************************
 ****************************************************************************
 *
 * release.h - automatic release event generation
 *
 * Copyright (C) 2007 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 

#ifndef RELEASE_H
#define RELEASE_H

#include "ir_remote_types.h"

void register_input(void);
void register_button_press(struct ir_remote *remote, struct ir_ncode *ncode,
			   ir_code code, int reps);
void set_release_suffix(const char *s);
void get_release_time(struct timeval *tv);
const char *check_release_event(void);
const char *trigger_release_event(void);
const char *release_map_remotes(struct ir_remote *old, struct ir_remote *new);

#endif /* RELEASE_H */
