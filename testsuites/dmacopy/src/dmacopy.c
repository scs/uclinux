#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfin_sram.h>

#define MEM_SIZE 256

static void dump_diff(char *ptr_a, char *ptr_b, int len)
{
	int i;
	printf("\toffsets differ:");
	for (i = 0; i < len; ++i)
		if (ptr_a[i] != ptr_b[i])
			printf(" %i", i);
	printf("\n");
}

int main(void)
{
	int i, ret;
	char *src = malloc(MEM_SIZE);
	char *dest = malloc(MEM_SIZE);
	char *sram = sram_alloc(MEM_SIZE, L1_INST_SRAM);
	char *ptr;

	ret = 0;
	memset(src, '*', MEM_SIZE);
	memset(dest, 'a', MEM_SIZE);

/*
 * test case 1 - dma_memcpy from src(SDRAM) to sram(SRAM) and sram(SRAM) to dest(SDRAM), then compare
 *               src(SDRAM) and dest(SDRAM) to make sure that copy into or from SRAM is ok.
 */

	ptr = dma_memcpy(sram, src, MEM_SIZE);
	if (ptr)
		printf("PASS: dma_memcpy SDRAM to SRAM\n");
	else
		printf("FAIL: dma_memcpy SDRAM to SRAM\n"), ++ret;

	ptr = dma_memcpy(dest, sram, MEM_SIZE);
	if (ptr)
		printf("PASS: dma_memcpy SRAM to SDRAM\n");
	else
		printf("FAIL: dma_memcpy SRAM to SDRAM\n"), ++ret;

	i = memcmp(dest, src, MEM_SIZE);
	if (!i)
		printf("PASS: dma_memcpy test case 1, memcmp result is %d\n", i);
	else {
		printf("FAIL: dma_memcpy test case 1, memcmp result is %d\n", i), ++ret;
		dump_diff(dest, src, MEM_SIZE);
	}

/*
 * test case 2 - dma_memcpy from src(SDRAM) to dest(SDRAM), memcmp of src and dest,
 *               make sure that dma_memcpy in SDRAM is ok
 */

	memset(dest, 'b', MEM_SIZE);
	ptr = dma_memcpy(dest, src, MEM_SIZE);
	if (ptr)
		printf("PASS: dma_memcpy SDRAM to SDRAM\n");
	else
		printf("FAIL: dma_memcpy SDRAM to SDRAM\n"), ++ret;

	i = memcmp(dest, src, MEM_SIZE);
	if (!i)
		printf("PASS: dma_memcpy test case 2, memcmp result is %d\n", i);
	else {
		printf("FAIL: dma_memcpy test case 2, memcmp result is %d\n", i), ++ret;
		dump_diff(dest, src, MEM_SIZE);
	}

	free(src);
	free(dest);
	sram_free(sram);

	return ret;
}
