#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "elf_common.h"
#include "elf32.h"

static void StartCoreB()
{
	int f = open("/dev/coreb", O_RDWR);
	ioctl(f, 2, NULL);
	close(f);
}

static void put_region(char *dst, const char *src, size_t count)
{
	int f = open("/dev/coreb", O_RDWR);
	int index = 0, ret = 0;
	unsigned long seek = 0;

	if (((unsigned long)dst >= 0xff600000) && 
	    ((unsigned long)dst <  0xff604000)) {
		if ((unsigned long)dst + count < 0xff604000) {
			index = 0;
			seek = (unsigned long)dst & 0x3fff;
		}
	} else if (((unsigned long)dst >= 0xff610000) &&
	           ((unsigned long)dst <  0xff614000)) {
		if ((unsigned long)dst + count < 0xff614000) {
			index = 1;
			seek = (unsigned long)dst & 0x3fff;
		}
	} else if (((unsigned long)dst >= 0xff500000) &&
	           ((unsigned long)dst <  0xff508000)) {
		if ((unsigned long)dst + count < 0xff508000) {
			index = 2;
			seek = (unsigned long)dst & 0x7fff;
		}
	} else if (((unsigned long)dst >= 0xff400000) &&
	           ((unsigned long)dst <  0xff408000)) {
		if ((unsigned long)dst + count < 0xff408000) {
			index = 3;
			seek = (unsigned long)dst & 0x7fff;
		}
	} 
	if (ret = ioctl(f, 1, &index))
		printf("ioctl return %d\n", ret);
	if (seek)
		if ((ret = lseek(f, seek, SEEK_SET)) < 0)
			printf("seek failed!\n");
	if (write(f, src, count) != count)
		printf("write failed!\n");
	close(f);
	printf("wrote %d bytes to 0x%08lx\n", count, (unsigned long)dst);
}

int elf_load(const char* buf)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)buf;

	if (!IS_ELF(*ehdr)) {
		printf("File is not an ELF file.\n");
		return -1;
	}

	if (ehdr->e_type != 2) /* bfin-elf */ {
		printf("File is not an bfin-elf file\n");
		return -1;
	}

	if (ehdr->e_machine != 0x6a) /* blackfin */ {
		printf("Machine type is not blackfin!\n");
		return -1;
	}

	{
		unsigned int section_ptr = (unsigned int)buf + ehdr->e_shoff;
		unsigned int section_cnt = ehdr->e_shnum;
		unsigned int section_sz  = ehdr->e_shentsize;
		int i;

		for (i = 0; i < section_cnt; ++i) {
			Elf32_Shdr *shdr = (Elf32_Shdr*)((char*)section_ptr + i*section_sz);
			unsigned long addr = shdr->sh_addr;
			unsigned long size = shdr->sh_size;

			if ((shdr->sh_flags & 0x0003) == 0x0003) {
				printf("Write %d bytes to 0x%08lx\n", size, addr);
				put_region((char*)addr, buf + shdr->sh_offset, size);
			}
		}
	}
	return 0;
}

int dxe_load(const char* buf)
{
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buf;

	if (!IS_ELF(*ehdr)) {
		printf("File is not an ELF file.\n");
		return -1;
	}

	if (ehdr->e_type != 8) /* blackfin .dxe */ {
		printf("File is not a VisualDSP dxe (%d)\n", ehdr->e_type);
		return -1;
	}

	if (ehdr->e_machine != 0x22) /* blackfin */ {
		printf("Machine type is not blackfin!\n");
		return -1;
	}

	{
		unsigned int section_ptr = (unsigned int)buf + ehdr->e_shoff;
		unsigned int section_cnt = ehdr->e_shnum;
		unsigned int section_sz  = ehdr->e_shentsize;
		int i;

		for (i = 0; i < section_cnt; ++i) {
			Elf32_Shdr *shdr = (Elf32_Shdr*)((char*)section_ptr + i*section_sz);
			unsigned long addr = shdr->sh_addr;
			unsigned long size = shdr->sh_size;
			if ((shdr->sh_flags & 0x408000) == 0x8000) {
				printf("Write %d bytes to 0x%08lx\n", size, addr);
				put_region((char*)addr, buf + shdr->sh_offset, size);
			}
		}
	}
	return 0;
}

int main(int argc, char* argv[])
{
	FILE* f;
	struct stat stat;
	char *buf;

	if (argc != 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 0;
	}
	if ((f = fopen(argv[1], "r")) == NULL) {
		printf("Unable to load %s\n", argv[1]);
		return 0;
	}

	if (fstat(fileno(f), &stat) < 0) {
		printf("Unable to stat %s\n", argv[1]);
		return 0;
	}

	if ((buf = malloc(stat.st_size)) == NULL) {
		printf("Unable to allocate %d bytes.\n", stat.st_size);
		return 0;
	}

	if (fread(buf, 1, stat.st_size, f) != stat.st_size) {
		printf("Unable to read %d bytes from %s\n", stat.st_size, argv[1]);
		return 0;
	}

	fclose(f);

	if (!dxe_load(buf))
		StartCoreB();
	else if (!elf_load(buf))
		StartCoreB();

	free(buf);

	return 0;
}

