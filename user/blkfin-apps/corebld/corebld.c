/*
 * User space application to load a standalone Blackfin ELF
 * into the second core of a dual core Blackfin (like BF561).
 *
 * Copyright 2005-2009 Analog Devices Inc.
 *
 * Enter bugs at http://blackfin.uclinux.org/
 *
 * Licensed under the GPL-2 or later.
 */

#include <bfin_sram.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#ifndef EM_BLACKFIN
# define EM_BLACKFIN 106
#endif

#define CMD_COREB_START 2

static bool force = false;

static int open_coreb(void)
{
	int ret = open("/dev/coreb", O_RDWR);
	if (ret < 0) {
		perror("unable to open /dev/coreb");
		exit(10);
	}
	return ret;
}

static void start_coreb(void)
{
	int fd = open_coreb();
	ioctl(fd, CMD_COREB_START, NULL);
	close(fd);
}

static unsigned long total_mem(void)
{
	struct sysinfo info;
	if (sysinfo(&info))
		perror("sysinfo() failed");
	return info.totalram;
}

#define ASYNC_BASE 0x20000000
#define ASYNC_LEN  0x10000000

/* The valid memory map of Core B ... sanity checking so we don't
 * do something bad (by accident?)
 */
struct {
	void *start, *end;
	int index;
} mem_regions[] = {
	{	/* L1 Data Bank A */
		.start = (void*)0xFF400000,
		.end   = (void*)0xFF400000 + 0x8000,
		.index = 3,
	},{	/* L1 Data Bank B */
		.start = (void*)0xFF500000,
		.end   = (void*)0xFF500000 + 0x8000,
		.index = 2,
	},{	/* L1 Instruction SRAM */
		.start = (void*)0xFF600000,
		.end   = (void*)0xFF600000 + 0x4000,
		.index = 0,
	},{ /* L1 Instruction SRAM/Cache */
		.start = (void*)0xFF610000,
		.end   = (void*)0xFF610000 + 0x4000,
		.index = 1,
	},{	/* L2 SRAM */
		.start = (void*)0xFEB00000,
		.end   = (void*)0xFEB00000 + 0x20000,
		.index = -1,
	},{	/* SDRAM - just assume from 0 to top of ASYNC bank is OK */
		.start = (void*)0x00000000,
		.end   = (void*)0x30000000,
		.index = -1,
	}
};

/* XXX: should a lot of this be tossed out in favor of using dma_memcpy ? */
static int put_region(void *dst, size_t dst_size, const void *src, size_t src_size)
{
	size_t i;
	int ret;
	void *new_src = NULL;
	unsigned long ldst = (unsigned long)dst;

	/* figure out how to get this section into the memory map */
	for (i = 0; i < ARRAY_SIZE(mem_regions); ++i) {
		if (dst >= mem_regions[i].start && dst < mem_regions[i].end) {
			if (dst + dst_size > mem_regions[i].end) {
				fprintf(stderr, "section at 0x%p (length=%zi) overflows bound 0x%p!\n",
				        dst, dst_size, mem_regions[i].end);
				return -1;
			}
			break;
		}
	}
	if (i == ARRAY_SIZE(mem_regions)) {
		fprintf(stderr, "no valid memory region found for 0x%p\n", dst);
		return 1;
	}

	/* see if this is an alloced region */
	if (dst_size > src_size) {
		new_src = malloc(dst_size);
		if (!new_src) {
			fprintf(stderr, "out of memory (could not malloc(%zi))\n", dst_size);
			return 1;
		}
		/* if data and bss are merged into one load, copy over
		 * data first and zero fill the remaining section
		 */
		if (src_size)
			memcpy(new_src, src, src_size);
		memset(new_src + src_size, 0x00, dst_size - src_size);
		src = new_src;
	}

	/* move the memory into Core B -- L1 stuff needs kernel help */
#define MEM_ERR(fmt, args...) \
	fprintf(stderr, \
		"\nERROR: Your destination address looks wrong: %p\n" \
		fmt "; aborting.\n"\
		" (re-run with --force to skip this check)\n\n", dst, ## args)

	ret = 0;
	if (!force) {
		if (ldst >= 0xff000000) {
			/* should not load into Core A L1 */
			ret = 1;
			MEM_ERR("This seems to be Core A L1 memory");
		} else if (ldst >= ASYNC_BASE && ldst < ASYNC_BASE + ASYNC_LEN) {
			/* should not load into async memory */
			ret = 1;
			MEM_ERR("It doesn't really make sense to try and load into async");
		} else if (ldst >= total_mem() && ldst < 0xef000000) {
			/* should not load into unavailable memory */
			ret = 1;
			MEM_ERR("The max mem available on your system seems to be 0x%08lx,\n"
			        "but the destination is above that", total_mem());
		} else if (ldst <= 0x4000) {
			/* should not load into start of memory */
			ret = 1;
			MEM_ERR("The start of memory is reserved (NULL/fixed_code/kernel)");
		}
	}

	if (ret == 0) {
		if (ldst >= 0xff000000)
			dma_memcpy(dst, src, dst_size);
		else
			memcpy(dst, src, dst_size);
	}

	free(new_src);

	printf("writing to 0x%08lx, 0x%-7zx bytes: %s\n", (unsigned long)dst, dst_size,
		ret ? "FAILED" : "OK");

	return ret;
}

#define IS_ELF(buff) \
	(buff[EI_MAG0] == ELFMAG0 && \
	 buff[EI_MAG1] == ELFMAG1 && \
	 buff[EI_MAG2] == ELFMAG2 && \
	 buff[EI_MAG3] == ELFMAG3)

/* XXX: should we sanity check and make sure the ELF contains no relocations ? */
int elf_load(const char *buf)
{
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)buf;
	ElfW(Phdr) *phdr;
	int ret = 0;
	uint16_t i;

	/* make sure we have a valid ELF */
	if (!IS_ELF(ehdr->e_ident) || ehdr->e_machine != EM_BLACKFIN) {
		fprintf(stderr, "file is not a Blackfin ELF file\n");
		return 1;
	}

	/* make sure we have no unhandled program headers */
	phdr = (ElfW(Phdr) *)(buf + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; ++i) {
		switch (phdr->p_type) {
			case PT_LOAD: break;
			default:
				fprintf(stderr, "unhandled program header %i (%X): did you link this application properly?\n",
				        i, phdr->p_type);
				return 2;
		}
		++phdr;
	}

	/* now load all the program headers */
	phdr = (ElfW(Phdr) *)(buf + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; ++i) {
		ret |= put_region((void*)phdr->p_vaddr, phdr->p_memsz, buf + phdr->p_offset, phdr->p_filesz);
		++phdr;
	}

	/* VisualDSP fails to fully populate the program headers for
	 * bss sections so we need to walk the section headers.  weak.
	 */
	if (ehdr->e_flags == 0x4) { /* gcc doesnt use this flag */
		ElfW(Shdr) *shdr = (ElfW(Shdr) *)(buf + ehdr->e_shoff);
		printf("hacking around broken VDSP program header table\n");
		for (i = 0; i < ehdr->e_shnum; ++i) {
			/* assume NOBITS sections == bss */
			if (shdr->sh_type == SHT_NOBITS)
				ret |= put_region((void*)shdr->sh_addr, shdr->sh_size, NULL, 0);
			++shdr;
		}
	}

	return ret;
}

#define GETOPT_FLAGS "fshV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"force",      no_argument, NULL, 'f'},
	{"skip-start", no_argument, NULL, 's'},
	{"help",       no_argument, NULL, 'h'},
	{"version",    no_argument, NULL, 'V'},
	{NULL,         no_argument, NULL, 0x0}
};

__attribute__ ((noreturn))
static void show_version(void)
{
	printf("corebld - Blackfin Core B loader\nVersion: $Id$\n");
	exit(EXIT_SUCCESS);
}

__attribute__ ((noreturn))
static void show_usage(int exit_status)
{
	printf(
		"corebld - Load a standalone Blackfin ELF into Core B\n"
		"\n"
		"Usage: corebld [options] <Blackfin ELF>\n"
		"\n"
		"Options:\n"
		"\t-f, --force       force loading (ignore sanity checks)\n"
		"\t-s, --skip-start  skip starting of Core B -- just load\n"
	);
	exit(exit_status);
}

int main(int argc, char *argv[])
{
	int i, fd;
	struct stat stat;
	void *buf;
	bool skip_coreb_start = false;
	const char *coreb_elf;

	while ((i=getopt_long(argc, argv, GETOPT_FLAGS, long_opts, NULL)) != -1) {
		switch (i) {
		case 'f': force = true; break;
		case 's': skip_coreb_start = true; break;
		case 'h': show_usage(EXIT_SUCCESS);
		case 'V': show_version();
		case ':':
			fprintf(stderr, "Option '%c' is missing parameter", optopt);
			show_usage(EXIT_FAILURE);
		case '?':
			fprintf(stderr, "Unknown option '%c' or argument missing", optopt);
			show_usage(EXIT_FAILURE);
		default:
			fprintf(stderr, "Unhandled option '%c'; please report this", i);
			return EXIT_FAILURE;
		}
	}

	if (argc != optind + 1) {
		fprintf(stderr, "corebld takes exactly 1 ELF file to load\n");
		show_usage(EXIT_FAILURE);
	}

	/* sanity check kernel support */
	close(open_coreb());

	coreb_elf = argv[optind];

	fd = open(coreb_elf, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to load %s: %s\n", coreb_elf, strerror(errno));
		return EXIT_FAILURE;
	}

	if (fstat(fd, &stat) < 0) {
		fprintf(stderr, "Unable to stat %s: %s\n", coreb_elf, strerror(errno));
		return EXIT_FAILURE;
	}

	if (stat.st_size < EI_NIDENT) {
		fprintf(stderr, "File is too small to be an ELF\n");
		return EXIT_FAILURE;
	}

	buf = mmap(0, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "Unable to mmap %s: %s\n", coreb_elf, strerror(errno));
		return EXIT_FAILURE;
	}

	i = elf_load(buf);
	if (!i && !skip_coreb_start)
		start_coreb();

	munmap(buf, stat.st_size);
	close(fd);

	return i;
}
