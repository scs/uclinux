#ifndef _BFIN_SEGMENT_H
#define _BFIN_SEGMENT_H


#define __KERNEL_DS   0x5
#define __USER_DS     0x1 

#ifndef __ASSEMBLY__

/* define constants */
typedef unsigned long mm_segment_t;         /* domain register      */
 
#define KERNEL_DS   0x5
#define USER_DS     0x1 

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

#define segment_eq(a,b) ((a) == (b))

#endif /* __ASSEMBLY__ */

#endif /* _BFIN_SEGMENT_H */
