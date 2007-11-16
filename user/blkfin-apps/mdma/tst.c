#include <stdio.h>
#include "mdma.h"

unsigned buf1[1024];
unsigned buf2[1024];
unsigned buf3[1024];
unsigned buf4[1024] __attribute__ ((l1_data));

main()
{
  int i;
  unsigned f;
  unsigned t0;
  bfdmactrl_t *b = alloc_dmactrl (4);

  for (i=0;i<1024;i++)
    buf4[i] = i;

  printf ("%08x\n", b);
  dma_add_move (b, buf4, buf1, 1024);
  dma_add_move (b, buf4, buf2, 1024);
  dma_add_move (b, buf4, buf3, 1024);
  dma_add_stop_flag (b);
  bfmdma (b);
  t0 = bfdma_wait (b);
  printf ("%d\n", t0);

  if (memcmp (buf4,buf1, 1024*4) != 0)
    printf ("buf1 is not correct\n");
  if (memcmp (buf4,buf2, 1024*4) != 0)
    printf ("buf2 is not correct\n");
  if (memcmp (buf4,buf3, 1024*4) != 0)
    printf ("buf3 is not correct\n");
  printf ("ok!\n");
}
