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
  unsigned *p;
  bfdmactrl_t *b = alloc_dmactrl (2);
  for (i=0;i<1024;i++)
    buf4[i] = 0;

  x=0;
  p=buf4 +2+20;
  for (i=0;i<16;i++) {
      for (j=0;j<16;j++) {
          p[j] = x++;
      }
      p += 20;
  }

  pblkl (buf4+2,17,18,20);


  printf ("%08x\n", b);

  dma_add_block_move (b, 4, buf1,     256, 1, 0,
                            buf4+22,  16, 16, 20);
  dma_add_stop_flag (b);
  dma_print (b);

  f = bfmdma (b);
  t0 = bfdma_wait (f);
  printf ("%d\n", t0);
  pblkl (buf1,16,16,16);

  p = buf1;
  for (j=0;j<16;j++) {
      printf ("%2d: ", j);
      for (i=0;i<20;i++)
          printf ("%4d ",*p++);
      printf ("\n");
  }
  printf ("\n");
  for (i=0;i<256;i++)
      if (buf1[i] != i) 
          printf ("error %d\n",i);
  printf ("ok!\n");
}
