#ifndef _BLACKFIN_PARAM_H
#define _BLACKFIN_PARAM_H

#ifdef __KERNEL__
#define HZ 		100
#define	USER_HZ		HZ
#define	CLOCKS_PER_SEC	(USER_HZ)
#endif

#ifndef HZ
#define HZ 100
#endif

#define EXEC_PAGESIZE	4096

#ifndef NOGROUP
#define NOGROUP		(-1)
#endif

#define MAXHOSTNAMELEN	64	/* max length of hostname */

#endif				/* _BLACKFIN_PARAM_H */
