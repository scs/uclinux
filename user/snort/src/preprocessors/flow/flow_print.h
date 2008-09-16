#ifndef _FLOW_PRINT_H
#define _FLOW_PRINT_H

int flow_printf(const char *format, ...);
int flow_fatalerror(const char *format, ...);
int flow_errormsg(const char *format, ...);
int flow_set_daemon(void);


#endif /* _FLOW_PRINT_H */

