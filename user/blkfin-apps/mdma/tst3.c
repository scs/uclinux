#include <stdio.h>
#include "mdma.h"

unsigned buf1[1024];
unsigned buf2[1024];
unsigned buf3[1024];
unsigned buf4[1024] __attribute__ ((l1_data));

main()
{
  int i,j,x;
  unsigned f;
  unsigned t0;
  unsigned char *p;
  bfdmactrl_t *b = alloc_dmactrl (2);

  for (i=0;i<1024;i++)
    buf4[i] = 0;
  x=0;
  p=buf4;
  for (i=0;i<16;i++) {
      for (j=0;j<16;j++) {
          p[j] = x++;
      }
      p += 40;
  }
  pblk (buf4,17,18,40);
  printf ("%08x\n", b);
  bfdma_align32move (b, buf1, buf4, 16, 16, 24, 40);
  dma_add_stop_flag (b);
  dma_print (b);
  f = bfmdma (b);
  t0 = bfdma_wait (b);
  printf ("%d\n", t0);
  pblk (buf1,20,18,24);
}
