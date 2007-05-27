/*
 * uCheader.h:  uCbootstrap header specification
 *
 * NOTE that this is provided here only for reference.
 *      The primary authority for this is the kernel
 *      include file: include/asm-m68knommu/uCbootstrap.h
 *
 * (c) 2004 Michael Leslie, Arcturus Networks Inc.
 *          <mleslie@arcturusnetworks.com>
 *
 */

#if !defined (_UCHEADER_H_)
#define _UCHEADER_H_
#define _UCHEADER_VERSION_ 0.1

typedef struct {
  unsigned char magic[8];     /* magic number "uCimage\0" */
  int           header_size;  /* after which data begins */
  int           data_size;    /* size of image in bytes */
  char          datecode[12]; /* output of 'date -I': "yyyy-mm-dd" */
  unsigned char md5sum[16];   /* binary md5sum of data */
  char          name[128];    /* filename or ID */
  char          padding[84];  /* pad to 256 bytes*/
} uCimage_header;

#define UCHEADER_MAGIC "uCimage\0" /* including one terminating zero */

#endif /* !defined (_UCHEADER_H_) */


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
