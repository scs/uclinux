#include <stdio.h>
#include <string.h>
#include <bfin_sram.h>

#define MEM_SIZE 256

int main(void)
{
	int i = 1;
	char *src = (char *) malloc(MEM_SIZE);
	char *dest = (char *) malloc(MEM_SIZE);
	char *sram = (char *) sram_alloc(MEM_SIZE, L1_INST_SRAM);
	char *ptr;

	memset(src, '*', MEM_SIZE);
	memset(dest, 'a', MEM_SIZE);

/*
 * test case 1 - dma_memcpy from src(SDRAM) to sram(SRAM) and sram(SRAM) to dest(SDRAM), then compare
 *               src(SDRAM) and dest(SDRAM) to make sure that copy into or from SRAM is ok.
 */

	ptr = (char *) dma_memcpy(sram, src, MEM_SIZE);
	if (ptr)
		printf("dma_memcpy SDRAM to SRAM\n");
	else
		printf("dma_memcpy SDRAM to SRAM fail\n");

	ptr = (char *) dma_memcpy(dest, sram, MEM_SIZE);
	if (ptr)
		printf("dma_memcpy SRAM to SDRAM\n");
	else
		printf("dma_memcpy SRAM to SDRAM fail\n");

	if(! (i = memcmp(dest, src, MEM_SIZE)) )
		printf("dma_memcpy test case 1 pass, memcmp result is %d\n", i);
	else
		printf("dma_memcpy test case 1 fail, memcmp result is %d\n", i);

/*
 * test case 2 - dma_memcpy from src(SDRAM) to dest(SDRAM), memcmp of src and dest,
 *               make sure that dma_memcpy in SDRAM is ok
 */

	memset(dest, 'b', MEM_SIZE);
	ptr = (char *) dma_memcpy(dest, src, MEM_SIZE);
	if (ptr)
		printf("dma_memcpy SDRAM to SDRAM\n");
	else
		printf("dma_memcpy SDRAM to SDRAM fail\n");

	if( !(i = memcmp(dest, src, MEM_SIZE)) )
		printf("dma_memcpy test case 2 pass, memcmp result is %d\n", i);
	else
		printf("dma_memcpy test case 2 fail, memcmp result is %d\n", i);

	free(src);
	free(dest);
	sram_free(sram);

	return 0;
}
