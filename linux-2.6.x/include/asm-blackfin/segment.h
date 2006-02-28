#ifndef _BFIN_SEGMENT_H
#define _BFIN_SEGMENT_H

#define __KERNEL_DS   (0x5)
#define __USER_DS     (0x1)

#ifndef __ASSEMBLY__

typedef struct {
	unsigned long seg;
} mm_segment_t;

#define MAKE_MM_SEG(s)	((mm_segment_t) { (s) })
#define USER_DS		MAKE_MM_SEG(__USER_DS)
#define KERNEL_DS	MAKE_MM_SEG(__KERNEL_DS)

static inline mm_segment_t get_fs(void)
{
	return USER_DS;
}

static inline mm_segment_t get_ds(void)
{
	return KERNEL_DS;
}

static inline void set_fs(mm_segment_t val)
{
}

#define segment_eq(a,b)	((a).seg == (b).seg)

#endif				/* __ASSEMBLY__ */

#endif				/* _BFIN_SEGMENT_H */
