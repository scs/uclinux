/*
 * cddb.h for dagrab
 */

#ifndef _CDDB_H
#define _CDDB_H		1

#include "main.h"

void ExpandTempl(char *out, char *templ, int tn, cd_trk_list * tl,
		 int escape);
void TerminateTempl(char *out);
int cddb_main(cd_trk_list * tl);
char *cddb_getdir();
unsigned long cddb_discid(cd_trk_list * tl);
int cddb_gettitle(char *data, char *title, int n);

#endif				/* _CDDB_H */
