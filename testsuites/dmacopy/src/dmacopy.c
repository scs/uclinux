#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfin_sram.h>

#define MEM_SIZE 0x1000

static inline void show_diff(int first, int last)
{
	printf(" %i", first);
	if (first != last)
		printf("...%i", last);
}

static void dump_diff(char *ptr_a, char *ptr_b, int len)
{
	int i, first = -1, last;
	printf("\toffsets differ:");
	for (i = 0; i < len; ++i) {
		if (ptr_a[i] != ptr_b[i]) {
			if (first == -1)
				first = i;
			last = i;
		} else if (first != -1) {
			show_diff(first, last);
			first = last = -1;
		}
	}
	if (first != -1)
		show_diff(first, last);
	printf("\n");
}

int main(void)
{
	int i, ret;
	char *src = malloc(MEM_SIZE);
	char *dst = malloc(MEM_SIZE);
	char *sram = sram_alloc(MEM_SIZE, L1_INST_SRAM);
	char *ptr;

	if (!src) {
		printf("FAIL: src = malloc(%i) failed\n", MEM_SIZE);
		return 1;
	}
	if (!dst) {
		printf("FAIL: dst = malloc(%i) failed\n", MEM_SIZE);
		return 1;
	}

	ret = 0;
	memset(src, '*', MEM_SIZE);
	memset(dst, 'a', MEM_SIZE);

/*
 * test case 1 - dma_memcpy from src(SDRAM) to sram(SRAM) and sram(SRAM) to dst(SDRAM), then compare
 *               src(SDRAM) and dst(SDRAM) to make sure that copy into or from SRAM is ok.
 */

	if (!sram)
		printf("SKIP: SDRAM <-> SRAM: sram_alloc(%i) failed\n", MEM_SIZE), ++ret;
	else {
		ptr = dma_memcpy(sram, src, MEM_SIZE);
		if (ptr)
			printf("PASS: dma_memcpy SDRAM to SRAM\n");
		else
			printf("FAIL: dma_memcpy SDRAM to SRAM\n"), ++ret;

		ptr = dma_memcpy(dst, sram, MEM_SIZE);
		if (ptr)
			printf("PASS: dma_memcpy SRAM to SDRAM\n");
		else
			printf("FAIL: dma_memcpy SRAM to SDRAM\n"), ++ret;

		i = memcmp(dst, src, MEM_SIZE);
		if (!i)
			printf("PASS: dma_memcpy test case 1, memcmp result is %d\n", i);
		else {
			printf("FAIL: dma_memcpy test case 1, memcmp result is %d\n", i), ++ret;
			dump_diff(dst, src, MEM_SIZE);
		}
	}

/*
 * test case 2 - dma_memcpy from src(SDRAM) to dst(SDRAM), memcmp of src and dst,
 *               make sure that dma_memcpy in SDRAM is ok
 */

	memset(dst, 'b', MEM_SIZE);
	ptr = dma_memcpy(dst, src, MEM_SIZE);
	if (ptr)
		printf("PASS: dma_memcpy SDRAM to SDRAM\n");
	else
		printf("FAIL: dma_memcpy SDRAM to SDRAM\n"), ++ret;

	i = memcmp(dst, src, MEM_SIZE);
	if (!i)
		printf("PASS: dma_memcpy test case 2, memcmp result is %d\n", i);
	else {
		printf("FAIL: dma_memcpy test case 2, memcmp result is %d\n", i), ++ret;
		dump_diff(dst, src, MEM_SIZE);
	}

	free(src);
	free(dst);
	sram_free(sram);

	return ret;
}
