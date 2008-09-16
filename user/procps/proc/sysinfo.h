#ifndef SYSINFO_H
#define SYSINFO_H

extern unsigned long Hertz;   /* clock tick frequency */

#define JT unsigned long
extern int four_cpu_numbers(JT *uret, JT *nret, JT *sret, JT *iret);
#undef JT

extern int        loadavg(double *av1, double *av5, double *av15);
extern int        uptime (double *uptime_secs, double *idle_secs);
extern unsigned long long ** get_meminfo(void);

enum meminfo_row { meminfo_main = 0,
		   meminfo_swap };

enum meminfo_col { meminfo_total = 0, meminfo_used, meminfo_free,
		   meminfo_shared, meminfo_buffers, meminfo_cached
};

extern unsigned read_total_main(void);

#endif /* SYSINFO_H */
