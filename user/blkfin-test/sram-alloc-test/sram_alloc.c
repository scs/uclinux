#include <stdio.h>
#include <bfin_sram.h>

int main ()
{
  char * a;
  a = (char *) sram_alloc (1, L1_DATA_A_SRAM);
  if ( a == NULL)
        printf("L1_DATA_A_SRAM ALLOC FAIL\n");
  else
        printf("L1_DATA_A_SRAM ALLOC PASS\n");

  printf ("a = %x\n", a);
  sram_free (a);
  a = (char *) sram_alloc (1, L1_DATA_B_SRAM);
  if ( a == NULL )
        printf("L1_DATA_B_SRAM ALLOC FAIL\n");
  else
        printf("L1_DATA_B_SRAM ALLOC PASS\n");

  printf ("a = %x\n", a);
  sram_free (a);

  return  0;
}

