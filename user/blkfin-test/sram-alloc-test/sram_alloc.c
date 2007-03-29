#include <stdio.h>
#include <bits/bfin_sram.h>

int main ()
{
  char * a;
  a = (char *) sram_alloc (100, L1_DATA_A_SRAM);
  printf ("a = %x\n", a);
  sram_free (a);
  a = (char *) sram_alloc (1000, L1_DATA_B_SRAM);
  printf ("a = %x\n", a);
  sram_free (a);

  return  0;
}

