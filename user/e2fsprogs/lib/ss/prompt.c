/*
 * prompt.c: Routines for retrieving and setting a prompt.
 *
 * $Header: /cvs/sw/new-wave/user/e2fsprogs/lib/ss/prompt.c,v 1.1.1.1 2001/11/11 23:20:38 davidm Exp $
 * $Locker:  $
 *
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose is hereby granted, provided that
 * the names of M.I.T. and the M.I.T. S.I.P.B. not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  M.I.T. and the
 * M.I.T. S.I.P.B. make no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include <stdio.h>
#include "ss_internal.h"

#ifdef __STDC__
void ss_set_prompt(int sci_idx, char *new_prompt)
#else
void ss_set_prompt(sci_idx, new_prompt)
     int sci_idx;
     char *new_prompt;
#endif
{
     ss_info(sci_idx)->prompt = new_prompt;
}

#ifdef __STDC__
char *ss_get_prompt(int sci_idx)
#else
char *ss_get_prompt(sci_idx)
     int sci_idx;
#endif
{
     return(ss_info(sci_idx)->prompt);
}
