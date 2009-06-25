#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>

#define passert(expr) ({ if (!(expr)) { perror(#expr); exit(1); } })

enum {
	BF_DMA_REQUEST = 0,
	BF_DMA_FREE,
	BF_DMA_RUN,
	BF_DMA_ARUN,
};

struct dmasg {
	void *next_desc_addr;
	void *start_addr;
	unsigned short cfg;
	unsigned short x_count;
	short x_modify;
	unsigned short y_count;
	short y_modify;
} __attribute__((packed));

struct dma_state {
	unsigned int channel;
	volatile int done;
	struct dmasg dsc_src, dsc_dst;
};

#define SIZE 1024
char src[SIZE], dst[SIZE];
char src2[SIZE*2], dst2[SIZE*2];

#define ioctl(fd, cmd, arg) \
({ \
	int ret; \
	printf("ioctl(%i, %i: "#cmd", %p) = ", fd, cmd, arg); \
	ret = ioctl(fd, cmd, arg); \
	printf("%i", ret); \
	if (ret) \
		printf(" (%s)", strerror(errno)); \
	printf("\n"); \
})

static void dump(char *c, size_t l)
{
	size_t i;
	for (i = 0; i < l; ++i)
		printf("%x ", c[i]);
	printf("\n");
}

static unsigned int scan_file(const char *prefix, const char *reg)
{
	unsigned int ret;
	char *file;
	FILE *fp;
	asprintf(&file, "%s%s", prefix, reg);
	fp = fopen(file, "r");
	if (!fp) {
		perror(file);
		return 0;
	}
	fscanf(fp, "%x", &ret);
	fclose(fp);
	return ret;
}

void decode_state(const char *prefix)
{
	unsigned int NEXT_DESC_PTR = scan_file(prefix, "NEXT_DESC_PTR");
	unsigned int START_ADDR    = scan_file(prefix, "START_ADDR");
	unsigned int CONFIG        = scan_file(prefix, "CONFIG");
	unsigned int X_COUNT       = scan_file(prefix, "X_COUNT");
	unsigned int X_MODIFY      = scan_file(prefix, "X_MODIFY");
	unsigned int Y_COUNT       = scan_file(prefix, "Y_COUNT");
	unsigned int Y_MODIFY      = scan_file(prefix, "Y_MODIFY");
	unsigned int CURR_DESC_PTR = scan_file(prefix, "CURR_DESC_PTR");
	unsigned int CURR_ADDR     = scan_file(prefix, "CURR_ADDR");
	unsigned int IRQ_STATUS    = scan_file(prefix, "IRQ_STATUS");
	unsigned int CURR_X_COUNT  = scan_file(prefix, "CURR_X_COUNT");
	unsigned int CURR_Y_COUNT  = scan_file(prefix, "CURR_Y_COUNT");

	printf("  --- %s ---\n", prefix);
	printf("desc: curr: 0x%08x  next: 0x%08x\n", CURR_DESC_PTR, NEXT_DESC_PTR);
	printf("addr: curr: 0x%08x start: 0x%08x\n", CURR_ADDR, START_ADDR);
	printf("X: curr: 0x%04x count: 0x%04x mod: 0x%04x (%i)\n", CURR_X_COUNT, X_COUNT, X_MODIFY, (short)X_MODIFY);
	printf("Y: curr: 0x%04x count: 0x%04x mod: 0x%04x (%i)\n", CURR_Y_COUNT, Y_COUNT, Y_MODIFY, (short)Y_MODIFY);

	printf("dma config: 0x%04x (%sabled %s ", CONFIG,
		(CONFIG & (1 << 0)) ? "en" : "dis",
		(CONFIG & (0x1 << 1)) ? "write" : "read");
	switch (CONFIG & (0x3 << 2)) {
		case 0x3: printf("WDSIZE:INVALID "); break;
		case 0x2: printf("32-bit "); break;
		case 0x1: printf("16-bit "); break;
		case 0x0: printf("8-bit "); break;
	}
	printf("%s %s%s%s",
		(CONFIG & (0x1 << 4)) ? "2D" : "1D",
		(CONFIG & (0x1 << 5)) ? "sync " : "",
		(CONFIG & (0x1 << 6)) ? "di_sel " : "",
		(CONFIG & (0x1 << 7)) ? "interrupt " : "");
	unsigned int NDSIZE = CONFIG & (0xF << 8);
	if (NDSIZE > 0 && NDSIZE < 10)
		printf("NDSIZE_%i ", NDSIZE);
	else if (NDSIZE >= 10)
		printf("NDSIZE:INVALID:%i ", NDSIZE);
	unsigned int FLOW = CONFIG & (0x7 << 12);
	switch (FLOW) {
		case 0: printf("stop"); break;
		case 1: printf("autobuffer"); break;
		case 4: printf("descriptor_array"); break;
		case 6: printf("descriptor_list_small"); break;
		case 7: printf("descriptor_list_large"); break;
		default: printf("FLOW:INVALID:%i", FLOW);
	}
	printf(")\n");
	printf("irq status: 0x%04x (%s%s%s%s)\n", IRQ_STATUS,
		(IRQ_STATUS & (0x1 << 0)) ? "done " : "",
		(IRQ_STATUS & (0x1 << 1)) ? "err " : "",
		(IRQ_STATUS & (0x1 << 2)) ? "dfetch " : "",
		(IRQ_STATUS & (0x1 << 3)) ? "run " : "");
}
#if 0
#define ds_s1() decode_state("/sys/kernel/debug/blackfin/MDMA Source 1/MDMA_S1_")
#define ds_d1() decode_state("/sys/kernel/debug/blackfin/MDMA Destination 1/MDMA_D1_")
#define ds_1() ds_s1(), ds_d1()
#else
#define ds_1()
#endif

int main(int argc, char *argv[])
{
	int i, fd;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	fd = open("/dev/bfin-dma", O_WRONLY);
	passert(fd != -1);
	printf("open(/dev/bfin-dma) = %i\n", fd);

	if (argc == 2) {
		if (!strcmp(argv[1], "-d")) {
			/* -d = decode dma state */
			ds_1();
			return 0;
		} else if (!strcmp(argv[1], "-f")) {
			/* -f = force free dma channel */
			struct dma_state state = { .channel = 1 };
			ioctl(fd, BF_DMA_FREE, &state);
			return 0;
		}
	}

	/* Do a synchronous transfer (8bit) first */
	struct dma_state state = {
		.channel = 1,
		.dsc_src = {
			.next_desc_addr = NULL,
			.start_addr = src,
			.cfg = 0x81,
			.x_count = sizeof(src),
			.x_modify = 1,
		},
		.dsc_dst = {
			.next_desc_addr = NULL,
			.start_addr = dst,
			.cfg = 0x83,
			.x_count = sizeof(dst),
			.x_modify = 1,
		},
	};
	ioctl(fd, BF_DMA_REQUEST, &state);

	ds_1();

	memset(src, 's', sizeof(src));
	memset(dst, 'd', sizeof(dst));
	ioctl(fd, BF_DMA_RUN, &state);
	i = memcmp(src, dst, sizeof(src));
	printf("memcmp = %i\n", i);
	if (i) {
		dump(src, sizeof(src));
		dump(dst, sizeof(dst));
	}

	ioctl(fd, BF_DMA_FREE, &state);

	/* Do an asynchronous transfer (16bit) next */
	struct dma_state state2 = {
		.channel = 1,
		.dsc_src = {
			.next_desc_addr = NULL,
			.start_addr = src2,
			.cfg = 0x85,
			.x_count = sizeof(src2) / 2,
			.x_modify = 2,
		},
		.dsc_dst = {
			.next_desc_addr = NULL,
			.start_addr = dst2,
			.cfg = 0x87,
			.x_count = sizeof(dst2) / 2,
			.x_modify = 2,
		},
	};
	ioctl(fd, BF_DMA_REQUEST, &state2);

	memset(src, 's', sizeof(src2));
	memset(dst, 'd', sizeof(dst2));
	ioctl(fd, BF_DMA_ARUN, &state2);
	i = 0;
	while (!state2.done)
		++i;
	printf("slept for %i loads\n", i);
	i = memcmp(src2, dst2, sizeof(src2));
	printf("memcmp = %i\n", i);
	if (i) {
		dump(src2, sizeof(src2));
		dump(dst2, sizeof(dst2));
	}

	ioctl(fd, BF_DMA_FREE, &state2);

	return 0;
}
