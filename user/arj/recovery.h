/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in RECOVERY.C are declared here.
 *
 */

#ifndef RECOVERY_INCLUDED
#define RECOVERY_INCLUDED

/* Recovery threshold */

#define RECOVERY_THRESHOLD       488    /* Each 488K is 1 block */

/* Prototypes */

unsigned long calc_protdata_size(unsigned long limit, int threshold);
int create_protfile(FILE *stream, unsigned long offset, int state);
unsigned long chk_prot_sig(FILE *stream, unsigned long rp_ofs);
int recover_file(char *name, char *protname, char *rec_name, int test_mode, unsigned long sig_offset);

#endif

