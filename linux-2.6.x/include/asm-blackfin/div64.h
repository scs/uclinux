#ifndef _BFINNOMMU_DIV64_H
#define _BFINNOMMU_DIV64_H

/* n = n / base; return rem; */

#define do_div(n,base) ({					\
	int __res;						\
	__res = ((unsigned long) n) % (unsigned) base;		\
	n = ((unsigned long) n) / (unsigned) base;		\
	__res;							\
})

#endif /* _BFIN_DIV64_H */
