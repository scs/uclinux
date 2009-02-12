#ifndef _XENO_NUCLEUS_PPD_H
#define _XENO_NUCLEUS_PPD_H

#include <nucleus/queue.h>

struct mm_struct;

typedef struct xnshadow_ppd_key {
    unsigned long muxid;
    struct mm_struct *mm;
} xnshadow_ppd_key_t;

typedef struct xnshadow_ppd_t {
    xnshadow_ppd_key_t key;
    xnholder_t link;
#define link2ppd(ln)	container_of(ln, xnshadow_ppd_t, link)
} xnshadow_ppd_t;

#define xnshadow_ppd_muxid(ppd) ((ppd)->key.muxid)

#define xnshadow_ppd_mm(ppd)    ((ppd)->key.mm)

/* Call with nklock locked irqs off. */
xnshadow_ppd_t *xnshadow_ppd_get(unsigned muxid);

#endif /* _XENO_NUCLEUS_PPD_H */
