#ifndef __PROC_SIGNALS_H
#define __PROC_SIGNALS_H
/* signals.h - signal name handling */

extern void list_signals(void);

/* Lists all known signal names on standard output. */

extern int get_signal(char *name,char *cmd);
extern int get_signal2(char *name);

/* Returns the signal number of NAME. If no such signal exists, an error
   message is displayed and the program is terminated. CMD is the name of the
   application. */
#endif

