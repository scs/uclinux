/*****************************************************************************/

/*
 *	flasher - simple code to flash program the flash on the SG590
 *
 *	(C) Copyright 2008, Greg Ungerer <gerg@snapgear.com>
 */

/*****************************************************************************/

#include "mips.h"

/*****************************************************************************/

static inline void writel(unsigned long addr, unsigned long v)
{
	*((volatile unsigned long *) addr) = v;
}

static inline unsigned long readl(unsigned long addr)
{
	return *((volatile unsigned long *) addr);
}

static inline void writeb(unsigned long addr, unsigned char v)
{
	*((volatile unsigned char *) addr) = v;
}

static inline unsigned long readb(unsigned long addr)
{
	return *((volatile unsigned char *) addr);
}

/*****************************************************************************/

static void delay(unsigned long cnt)
{
	for (; (cnt); cnt--)
		*((volatile unsigned long *) 0);
}

/*****************************************************************************/

void initled(void)
{
	writel(0x8001070000000810, 0x1);
	writel(0x8001070000000818, 0x1);
	writel(0x8001070000000820, 0x1);
	writel(0x8001070000000828, 0x1);
	writel(0x8001070000000830, 0x1);
	writel(0x8001070000000838, 0x1);
	writel(0x8001070000000840, 0x1);
	writel(0x8001070000000888, 0x1fc);
}

unsigned long ledchase[] = {
	0x004, 0x008, 0x010, 0x020, 0x040, 0x080,
	0x100, 0x080, 0x040, 0x020, 0x010, 0x008,
};

void cycleled(void)
{
	int i;

	for (i = 0; ;) {
		delay(15000000);
		writel(0x8001070000000888, ledchase[i]);
		if (i++ >= 11)
			i = 0;
		writel(0x8001070000000890, ledchase[i]);
	}
}

/*****************************************************************************/

void initserial(void)
{
	writel(0x8001180000000818, 0x83);
	writel(0x8001180000000880, 0x0f);
	writel(0x8001180000000888, 0x01);
	writel(0x8001180000000818, 0x03);
}

void putch(char c)
{
	while ((readl(0x8001180000000828) & 0x40) == 0)
		;
	writel(0x8001180000000840, c);
}

void putstr(char *s)
{
	while (*s != '\0')
		putch(*s++);
}

char hexdigits[] = "0123456789abcdef";

void putnum64(unsigned long val)
{
	int i, s;

	for (i = 0, s = 16-1; (i < 16); i++, s--)
		putch(hexdigits[(val >> (s*4)) & 0xf]);
}

void putnum32(unsigned int val)
{
	int i, s;

	for (i = 0, s = 8-1; (i < 8); i++, s--)
		putch(hexdigits[(val >> (s*4)) & 0xf]);
}

void putnum8(unsigned char val)
{
	putch(hexdigits[(val >> 4) & 0xf]);
	putch(hexdigits[val & 0xf]);
}

void hexdump(unsigned long addr, unsigned int len)
{
	int i;
	for (i = 0; (i < len); i++) {
		if ((i % 16) == 0) { putnum64(addr + i); putstr(":  "); }
		putnum8(readb(addr + i));
		putch(' ');
		if (((i+1) % 16) == 0) putstr("\n");
	}
}

/*****************************************************************************/

#define	FLASH_SECTORSIZE	(128*1024)


void flash_unlock(unsigned long addr)
{
	writeb(addr, 0x60);
	writeb(addr, 0xd0);

	while ((readb(addr) & 0x80) == 0)
		;

	writeb(addr, 0xff);
}

void flash_erase(unsigned long addr)
{
	writeb(addr, 0x20);
	writeb(addr, 0xd0);

	while ((readb(addr) & 0x80) == 0)
		;

	writeb(addr, 0xff);
}

void flash_writebyte(unsigned long addr, unsigned char v)
{
	writeb(addr, 0x40);
	writeb(addr, v);

	while ((readb(addr) & 0x80) == 0)
		;

	writeb(addr, 0xff);
}

void flash_writeblock(unsigned long addr, unsigned char *buf, int len)
{
	for (; (len); len--)
		flash_writebyte(addr++, *buf++);
}

void flash_program(void *from, unsigned int len)
{
	unsigned long addr = 0x1fc00000;
	unsigned long i, j;

	j = addr + len;
	putstr("Erasing: ");
	for (i = addr; (i < j); i += FLASH_SECTORSIZE) {
		flash_erase(i);
		putch('.');
	}
	putch('\n');

	putstr("Programming: ");
	for (i = addr; (i < j); i += FLASH_SECTORSIZE) {
		flash_writeblock(i, from, FLASH_SECTORSIZE);
		from += FLASH_SECTORSIZE;
		putch('.');
	}
	putch('\n');
}

/*****************************************************************************/

#ifdef SERIALLOAD

unsigned int serial_load(void *dst)
{
	unsigned char *p = dst;
	unsigned int idle, len;

	putstr("Send binary now...");

	len = 0;
	while (len == 0) {
		for (idle = 0; (idle < 2000000); idle++) {
			if (checkch()) {
				*p++ = getch();
				len++;
				idle = 0;
			}
		}
	}

	putstr("\nReceived 0x");
	putnum(len);
	putstr(" bytes\n");

	return len;
}

#endif /* SERIALLOAD */

/*****************************************************************************/

int main(void)
{
	int len;

	initserial();
	putstr("SG590 (CN50xx) flash programmer\n");

#ifdef SERIALLOAD
	len = serial_load((void *) 0x100000);
#else
	len = 5 * 128*1024;
#endif
	flash_program((void *) 0x100000, len);

	putstr("Done\n");

	return 0;
}

/*****************************************************************************/
