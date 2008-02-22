#include <stdio.h>
#include "mdma.h"

unsigned buf1[1024];
unsigned buf2[1024];
unsigned buf3[1024];
//unsigned buf4[1024] __attribute__ ((l1_data));
unsigned buf4[1024];

#define FLUSH_REGION(address,size) \
        __asm__ __volatile__(   \
        "[--SP]=%0;"            \
        "%0+=31;"               \
        "%0>>=5;"               \
        "cc=%0==0;"             \
        "if cc jump 2f;"        \
        "p0=%0;"                \
        "p1=%1;"                \
        "lsetup (1f,1f) LC1=P0\n" \
        "1:\n"                  \
        "flush [P1++]\n"        \
        "2:\n"                  \
        "%0=[SP++]\n"           \
        :                       \
        : "d" (size), "a" (address) \
        : "LC1", "LT1", "LB1", "P0", "P1" )

#define FLUSHINV_REGION(address,size) \
        __asm__ __volatile__(   \
        "[--SP]=%0;"            \
        "%0+=31;"               \
        "%0>>=5;"               \
        "cc=%0==0;"             \
        "if cc jump 2f;"        \
        "p0=%0;"                \
        "p1=%1;"                \
        "lsetup (1f,1f) LC1=P0\n" \
        "1:\n"                  \
        "flushinv [P1++]\n"     \
        "2:\n"                  \
        "%0=[SP++]\n"           \
        :                       \
        : "d" (size), "a" (address) \
        : "LC1", "LT1", "LB1", "P0", "P1" )

main()
{
  int i;
  unsigned f;
  unsigned t0;
  bfdmactrl_t *b = alloc_dmactrl (4);

  for (i=0;i<1024;i++)
    buf4[i] = i;

  FLUSH_REGION(buf4, 1024*sizeof(unsigned));

//  pblkl(buf4, 16, 64, 16);
  
  printf ("%08x\n", b);
  dma_add_move (b, buf1, buf4, 1024);
  dma_add_move (b, buf2, buf4, 1024);
  dma_add_move (b, buf3, buf4, 1024);
  dma_add_stop_flag (b);
  bfmdma (b);
  t0 = bfdma_wait (b);
  printf ("%d\n", t0);

  FLUSHINV_REGION(buf1, 1024*sizeof(unsigned));
  FLUSHINV_REGION(buf2, 1024*sizeof(unsigned));
  FLUSHINV_REGION(buf3, 1024*sizeof(unsigned));
//  pblkl(buf1, 16, 64, 16);
//  pblkl(buf2, 16, 16, 16);
//  pblkl(buf3, 16, 16, 16);

  if (memcmp (buf4,buf1, 1024*4) != 0)
    printf ("buf1 is not correct\n");
  if (memcmp (buf4,buf2, 1024*4) != 0)
    printf ("buf2 is not correct\n");
  if (memcmp (buf4,buf3, 1024*4) != 0)
    printf ("buf3 is not correct\n");
  printf ("ok!\n");
}
