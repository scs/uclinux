#ifndef _BFINNOMMU_PARAM_H
#define _BFINNOMMU_PARAM_H

#include <linux/config.h>

#ifndef HZ
#ifdef CONFIG_BFIN
#define HZ 100		/* need changes accordingly	*/
#endif
#endif
#ifdef __KERNEL__
#define	USER_HZ		HZ
#define	CLOCKS_PER_SEC	(USER_HZ)
#endif

#define EXEC_PAGESIZE	4096

#ifndef NGROUPS
#define NGROUPS		32
#endif

#ifndef NOGROUP
#define NOGROUP		(-1)
#endif

#define MAXHOSTNAMELEN	64	/* max length of hostname */

#endif /* _BFINNOMMU_PARAM_H */
