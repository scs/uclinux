#ifndef __LIB_NASL_H__
#define __LIB_NASL_H__

/*
 * NASL language level
 * Below 1000 is 1.2.6 and before
 *
 * Level 1000:
 * ACT_INIT, ACT_KILL_HOST and ACT_END
 *
 * Level 2000:
 * NASL2
 *
 * Level 2010:
 * Fix repeat / until loop
 * Handle icmp_seq parameter in forge_icmp_packet
 *
 */
#define NASL_LEVEL 2010


int execute_nasl_script(struct arglist *, const char *, int);
char * nasl_version();

/* execute_nasl_script modes */
#define NASL_EXEC_DESCR		(1 << 0)
#define NASL_EXEC_PARSE_ONLY	(1 << 1)

#endif
