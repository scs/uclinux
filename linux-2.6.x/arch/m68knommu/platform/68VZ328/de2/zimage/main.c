
/*
 *  linux/arch/m68knommu/platform/MC68VZ328/de2/zimage/main.c
 *
 *  Copyright (C) 2002 Georges Menie
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */

extern unsigned char input_data[];
extern unsigned char input_data_end[];
extern unsigned char output_data[];

void outstring (char *s)
{
	extern void putc (int);

	while (*s)
		putc (*s++);
}

void unzip_image (void)
{
	void memgunzip (unsigned char *dst, const unsigned char *src,
					unsigned int sz);

	outstring ("Uncompressing Linux");
	memgunzip (output_data, input_data, input_data_end - input_data);
	outstring ("\r\nOk, booting the kernel.\r\n");
}
