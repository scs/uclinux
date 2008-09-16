/*
 * print.h for dagrab
 */

#ifndef _PRINT_H
#define _PRINT_H 1

#include "main.h"

extern const int V_STAT[3];

void dagrab_stderr(char *fmt, ...);
int view_status(int id, const void *val);
void cd_disp_TOC(cd_trk_list * tl);
void show_help(int which);
char *resttime(int sec);
void bad_par(int *real, int min, int max, char *mes);
void show_examples();

#endif				/* _PRINT_H */
