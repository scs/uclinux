#include <stdio.h>
#include <bits/bfin_sram.h>

int main ()
{
  char * a;
  a = (char *) sram_alloc (100, L1_DATA_A_SRAM);
  if ( a == null )
        printf("L1_DATA_A_SRAM ALLOC FAIL\n");
  else
        printf("L1_DATA_A_SRAM ALLOC PASS\n");

  printf ("a = %x\n", a);
  sram_free (a);
  a = (char *) sram_alloc (1000, L1_DATA_B_SRAM);
  if ( a == null )
        printf("L1_DATA_B_SRAM ALLOC FAIL\n");
  else
        printf("L1_DATA_B_SRAM ALLOC PASS\n");

  printf ("a = %x\n", a);
  sram_free (a);

  return  0;
}

