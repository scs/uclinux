#ifndef _BFIN_SEGMENT_H
#define _BFIN_SEGMENT_H


#ifndef __ASSEMBLY__

/* define constants */
typedef unsigned long mm_segment_t;         /* domain register      */
#endif
 
#define KERNEL_CS   0x0
#define KERNEL_DS   0x0
#define __KERNEL_CS   0x0
#define __KERNEL_DS   0x0
 
#define USER_CS     0x1
#define USER_DS     0x1 
#define __USER_CS     0x1
#define __USER_DS     0x1 

#define get_ds()        (KERNEL_DS)
#define set_fs(val)
#define get_fs()        (__USER_DS)
#define segment_eq(a,b) ((a) == (b))


#endif /* _BFIN_SEGMENT_H */
