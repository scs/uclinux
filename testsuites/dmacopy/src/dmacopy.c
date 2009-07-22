

#include <bfin_sram.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

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

/* Make sure dma_memcpy() does not over/under flow the buffers given to it.
 * We do this by padding each buffer with a canary at the start and end.  So
 * the actual allocation looks like:
 * [size][canary][ ... buffer ... ][canary]
 * The canary used is the pointer returned by malloc so we know we have a
 * unique value at all times.  If dma_memcpy() does anything bad, the canaries
 * will get killed in the process.
 */
#define canary_size sizeof(char *)
static void *xmalloc(size_t size)
{
	char *ret = malloc(size + (canary_size * 2) + sizeof(size));
	char *canary, *canary1, *canary2;
	if (!ret) {
		printf("FAIL: malloc(%zu) failed\n", size);
		exit(10);
	}
	canary = (void *)&ret;
	canary1 = ret + canary_size;
	canary2 = canary1 + canary_size + size;
	memcpy(ret, &size, sizeof(size));
	memcpy(canary1, canary, canary_size);
	memcpy(canary2, canary, canary_size);
	return ret + sizeof(size) + canary_size;
}
static void xfree(void *ptr)
{
	char *ret;
	char *canary, *canary1, *canary2;
	size_t size;
	ret = (char *)ptr - sizeof(size) - canary_size;
	canary = (void *)&ret;
	memcpy(&size, ret, sizeof(size));
	canary1 = ret + canary_size;
	canary2 = canary1 + canary_size + size;
	if (memcmp(canary, canary1, canary_size))
		printf("FAIL: leading canary was killed {%i,%i,%i,%i} vs {%i,%i,%i,%i}!\n",
			canary1[0], canary1[1], canary1[2], canary1[3], canary[0], canary[1], canary[2], canary[3]);
	if (memcmp(canary, canary2, canary_size))
		printf("FAIL: trailing canary was killed {%i,%i,%i,%i} vs {%i,%i,%i,%i}!\n",
			canary2[0], canary2[1], canary2[2], canary2[3], canary[0], canary[1], canary[2], canary[3]);
	free(ret);
}

int is_l1_inst(void *paddr)
{
	unsigned long addr = (unsigned long)paddr & 0xfff00000;
	if (addr == 0xffa00000 || addr == 0xff600000)
		return 1;
	else
		return 0;
}

/* Do the actual test:
 *  - set buffers to values known to be different
 *  - copy src to chk
 *  - copy chk to dst
 *  - compare src and dst
 */
int _do_test(char *src_desc, char *dst_desc, char *src, char *dst, char *chk, int size)
{
	static int test_num = 1;
	int ret = 0, i;
	void *ptr;

	memset(src, 's', size);
	memset(dst, 'd', size);
	__builtin_bfin_ssync();
	if (!is_l1_inst(chk))
		memset(chk, 'c', size);

	ptr = dma_memcpy(chk, src, size);
	if (ptr)
		printf("PASS: dma_memcpy %s[s] to %s[c]\n", src_desc, dst_desc);
	else
		printf("FAIL: dma_memcpy %s[s] to %s[c]\n", src_desc, dst_desc), ++ret;

	if (!is_l1_inst(chk)) {
		i = memcmp(chk, src, size);
		if (!i)
			printf("PASS: dma_memcpy(chk, src) test case %i, memcmp result is %d\n", test_num, i);
		else {
			printf("FAIL: dma_memcpy(chk, src) test case %i, memcmp result is %d\n", test_num, i), ++ret;
			dump_diff(chk, src, size);
		}
	}

	ptr = dma_memcpy(dst, chk, size);
	if (ptr)
		printf("PASS: dma_memcpy %s[c] to %s[d]\n", dst_desc, src_desc);
	else
		printf("FAIL: dma_memcpy %s[c] to %s[d]\n", dst_desc, src_desc), ++ret;

	if (!is_l1_inst(chk)) {
		i = memcmp(dst, chk, size);
		if (!i)
			printf("PASS: dma_memcpy(dst, chk) test case %i, memcmp result is %d\n", test_num, i);
		else {
			printf("FAIL: dma_memcpy(dst, chk) test case %i, memcmp result is %d\n", test_num, i), ++ret;
			dump_diff(dst, chk, size);
		}
	}

	i = memcmp(dst, src, size);
	if (!i)
		printf("PASS: dma_memcpy(dst, src) test case %i, memcmp result is %d\n", test_num, i);
	else {
		printf("FAIL: dma_memcpy(dst, src) test case %i, memcmp result is %d\n", test_num, i), ++ret;
		dump_diff(dst, src, size);
	}

	++test_num;

	return ret;
}

/*
 * test case 1 - dma_memcpy from src(SDRAM) to sram(SRAM) and sram(SRAM) to dst(SDRAM), then compare
 *               src(SDRAM) and dst(SDRAM) to make sure that copy into or from SRAM is ok.
 *               also check that 8/16/32 bit transfers work by mucking with alignment.
 */
int sram_test(int size, char *sram_desc, int flags)
{
	int ret = 0;
	char *src = xmalloc(size);
	char *dst = xmalloc(size);
	char *sram = sram_alloc(size, flags);

	printf("TEST:  --- SRAM (%s) <-> SDRAM w/%i bytes ---\n", sram_desc, size);

	if (!sram) {
		printf("FAIL: sram_alloc(%i) failed\n", size);
		return 1;
	}

	if ((ulong)src % 4 != 0 || (ulong)dst % 4 != 0 ||
	    (ulong)sram % 4 != 0 || size % 4 != 0)
	{
		printf("FAIL: SRAM src/dst/size are not 32bit aligned to start:\n"
			"\t%p / %p / %p / %i\n",
			src, dst, sram, size);
		return 1;
	}

	ret += _do_test("SDRAMx32", "SRAMx32", src, dst, sram, size);
	ret += _do_test("SDRAMx16", "SRAMx16", src+2, dst+2, sram+2, size-2);
	ret += _do_test("SDRAMx8", "SRAMx8", src+1, dst+1, sram+1, size-1);

	xfree(src);
	xfree(dst);
	sram_free(sram);

	return ret;
}

/*
 * test case 2 - dma_memcpy from src(SDRAM) to dst(SDRAM), memcmp of src and dst,
 *               make sure that dma_memcpy in SDRAM is ok
 *               also check that 8/16/32 bit transfers work by mucking with alignment.
 */
int sdram_test(int size)
{
	int ret = 0;
	char *src = xmalloc(size);
	char *dst = xmalloc(size);
	char *chk = xmalloc(size);

	printf("TEST:  --- SDRAM <-> SDRAM w/%i bytes ---\n", size);

	if ((ulong)src % 4 != 0 || (ulong)dst % 4 != 0 ||
	    (ulong)chk % 4 != 0 || size % 4 != 0)
	{
		printf("FAIL: SDRAM src/dst/size are not 32bit aligned to start\n"
			"\t%p / %p / %p / %i\n",
			src, dst, chk, size);
		return 1;
	}

	ret += _do_test("SDRAMx32", "SDRAMx32", src, dst, chk, size);
	ret += _do_test("SDRAMx16", "SDRAMx16", src+2, dst+2, chk+2, size-2);
	ret += _do_test("SDRAMx8", "SDRAMx8", src+1, dst+1, chk+1, size-1);

	xfree(src);
	xfree(dst);
	xfree(chk);

	return ret;
}

int has_l2(void)
{
	/* if the part does not have L2, then don't try to use it */
	return WEXITSTATUS(system("grep -qs '^L2 SRAM[[:space:]]*:[[:space:]]*[1-9]' /proc/cpuinfo")) == 0;
}

/*
 * Setup some "background noise" and really stress the hell out of the DMA
 * memcpy code.  We do this by forking off a bunch of children and each child
 * continuously does small random memcpy's over and over.  If the kernel
 * locking is safe, then there should be no problem processing all these
 * small children as well as the large buffers the main test does.
 */
pid_t children[20];
void maybe_run_child(int argc, char *argv[])
{
	if (argc != 2 || strcmp(argv[1], "child"))
		return;

	srandom(time(0));
	while (1) {
		char src[256], dst[256];
		dma_memcpy(src, dst, random() % 256);
	}
}
bool spawn_children(int argc, char *argv[])
{
	size_t i;

	maybe_run_child(argc, argv);

	for (i = 0; i < ARRAY_SIZE(children); ++i) {
		children[i] = vfork();
		if (children[i] < 0) {
			perror("vfork() failed");
			return false;
		} else if (!children[i]) {
			execlp(argv[0], argv[0], "child", NULL);
			perror("execlp() failed");
			return false;
		}
	}
	return true;
}
void kill_children(void)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(children); ++i)
		kill(children[i], SIGKILL);
}

#define TEST_RANGE(range, func, args...) \
	for (i = 0; i < ARRAY_SIZE(range##_range); ++i) \
		ret += func(range##_range[i], ## args)

int main(int argc, char *argv[])
{
	int ret = 0, i;
	int sml_range[] = { 4, 0x10, 0x1000 };
	int mid_range[] = { 4, 0x10, 0x1000, 0x10000, 0x12340 };
	int lrg_range[] = { 4, 0x10, 0x1000, 0x10000, 0x12340, 0x22340, 0x32340, 0x42340, 0x54320, 0x323450 };

	if (!spawn_children(argc, argv))
		return -1;

	TEST_RANGE(sml, sram_test, "L1 INST", L1_INST_SRAM);
	TEST_RANGE(sml, sram_test, "L1 DATA", L1_DATA_SRAM);
	if (has_l2())
		TEST_RANGE(mid, sram_test, "L2", L2_SRAM);
	TEST_RANGE(lrg, sdram_test);

	if (ret)
		printf("SUMMARY: %i tests failed\n", ret);
	else
		printf("SUMMARY: all tests passed\n");

	kill_children();

	return ret;
}
