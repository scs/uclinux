/*
 * File:         pngview.c
 *
 * Description:  View pngs on a frame buffer
 *
 * Modified:     Copyright 2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fb.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <png.h>

unsigned char *framebase = 0;
unsigned long ScreenWidth, ScreenHeight;
unsigned long ImageWidth, ImageHeight;

//#define RGB(r,g,b) (((b&0x1f)<<11)|((g&0x3f)<<5)|(r&0x1f))
//#define RGB(r,g,b) ~((((b&0xf8)<<8)|((g&0xfc)<<3)|(r>>3)))
#define RGB(r,g,b) ((((r&0xf8)<<8)|((g&0xfc)<<3)|(b>>3)))

void put_scanline_someplace_noscale(unsigned char **buffer, int row_width, unsigned long row)
{
	unsigned short *pD;
	unsigned char *pS;
	unsigned char r, g, b;
	unsigned long startx=0, starty=0;

	if (row >= ScreenHeight)
		return;

	if (ImageWidth < ScreenWidth)
		startx = (ScreenWidth - ImageWidth)/2;
	if (ImageHeight < ScreenHeight)
		starty = (ScreenHeight - ImageHeight)/2;

	pD = (unsigned short*)framebase + ((row+starty) * ScreenWidth);
	pS = buffer[row+1];

	while (startx--)
		pD++;
	while (row_width--) {
		if (row_width < ScreenWidth) {
			r = *pS++;
			g = *pS++;
			b = *pS++;
			// *pD++ = ((r<<7)&0x7c00) | ((g<<2)&0x03e0) | ((b>>3)&0x001f) | 0x8000;
			*pD++   = RGB(r,g,b);
		}
	}
}

static unsigned long *ScaleTableX, *ScaleTableY;
static int FixScale = 1;

void put_scanline_someplace_scale(unsigned char **buffer, int row_width, unsigned long row)
{
	int i, y = -1;
	unsigned char *pS;
	unsigned short *pD, *pC;
	unsigned char r, g, b;
	unsigned long startx=0, starty=0;

	for (i=0; i<ImageHeight; ++i) {
		if (ScaleTableY[i] == row) {
			y = i;
			break;
		}
	}

	if (y != -1) {
		int k_init, k_fin;
		k_init = (y == 0 ? ScaleTableY[y] : ScaleTableY[y-1]);
		k_fin  = ScaleTableY[y];

		if (ImageWidth < ScreenWidth)
			startx = (ScreenWidth - ImageWidth)/2;
		if (ImageHeight < ScreenHeight)
			starty = (ScreenHeight - ImageHeight)/2;

		pD = (unsigned short*)framebase + ((y+starty) * ScreenWidth) + startx;
		for (i=0; i<ImageWidth; ++i) {
			/* handle scaling of the image ... rather than slicing out
			 * rows/cols, let's do a cheesy interpolation
			 */
			int j, k;
			unsigned long sum_r = 0, sum_g = 0, sum_b = 0, num_pixels;
			for (j = ScaleTableX[i-1]; j < ScaleTableX[i]; ++j) {
				for (k = k_init; k < k_fin; ++k) {
					pS = buffer[k+1] + (j*3);
					if (pS > (buffer[k+1]+row_width))
						break;
					sum_r += *pS++;
					sum_g += *pS++;
					sum_b += *pS;
				}
			}

			j = (ScaleTableX[i] - ScaleTableX[i-1]);
			k = (k_fin - k_init);
			num_pixels = 1;
			if (j > 0) num_pixels *= j;
			if (k > 0) num_pixels *= k;
			r = (sum_r / num_pixels);
			g = (sum_g / num_pixels);
			b = (sum_b / num_pixels);

			/* output the final interpolated pixel */
			// *pD++ = ((r<<7)&0x7c00) | ((g<<2)&0x03e0) | ((b>>3)&0x001f) | 0x8000;
			*pD++   = RGB(r,g,b);
		}

		pC = (unsigned short*)framebase + ((y+starty) * ScreenWidth);

		for (i=y+1; i<ImageHeight; ++i) {
			if (ScaleTableY[i] == row) {
				pD = (unsigned short*)framebase + ((i+starty) * ScreenWidth);
				memcpy(pD, pC, ScreenWidth*2);
			} else if (ScaleTableX[i] > row)
				break;
		}
	}
}

unsigned long div45(unsigned long num1, unsigned long num2)
{
	if ((num1%num2) > (num2/2))
		return num1/num2+1;
	else
		return num1/num2;
}

void CreateScaleTable(int src_width, int src_height)
{
	int i;
	ScaleTableX = malloc(ImageWidth * sizeof(unsigned long));
	ScaleTableY = malloc(ImageHeight * sizeof(unsigned long));

	for (i=ImageWidth-1; i>=0; --i)
		ScaleTableX[i] = div45(i * src_width, ImageWidth);

	for (i=ImageHeight-1; i>=0; --i)
		ScaleTableY[i] = div45(i * src_height, ImageHeight);
}

void ReleaseScaleTable(void)
{
	free(ScaleTableX);
	free(ScaleTableY);
	ScaleTableX = ScaleTableY = NULL;
}


/* jacked some of this code from the libpng manual:
 * http://www.libpng.org/pub/png/book/chapter13.html
 */
int read_png_file(char *filename)
{
	FILE *infile;
	int bit_depth, color_type;
	int row_stride; /* physical row width in output buffer */
	png_structp png_ptr;
	png_infop info_ptr;
	png_uint_32 width, height;
	unsigned char sig[8], *image_data = NULL;
	png_bytep *row_pointers = NULL;
	png_uint_32 i, rowbytes;

	if ((infile = fopen(filename, "rb")) == NULL) {
		fprintf(stderr, "can't open %s\n", filename);
		return 0;
	}

	fread(sig, 1, 8, infile);
	if (!png_check_sig(sig, 8))
		goto close_and_err;

	png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (!png_ptr)
		goto close_and_err;

	info_ptr = png_create_info_struct(png_ptr);
	if (!info_ptr) {
		png_destroy_read_struct(&png_ptr, NULL, NULL);
		goto close_and_err;
	}

	if (setjmp(png_ptr->jmpbuf)) {
free_and_err:
		free(row_pointers);
		free(image_data);
		png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
close_and_err:
		fclose(infile);
		fprintf(stderr, "Error while reading file '%s'\n", filename);
		return 0;
	}

	png_init_io(png_ptr, infile);
	png_set_sig_bytes(png_ptr, 8);
	png_read_info(png_ptr, info_ptr);
	png_get_IHDR(png_ptr, info_ptr, &width, &height,
		&bit_depth, &color_type, NULL, NULL, NULL);

	if (color_type == PNG_COLOR_TYPE_PALETTE)
		png_set_expand(png_ptr);
	if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
		png_set_expand(png_ptr);
	if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS))
		png_set_expand(png_ptr);

	row_stride = width * height;

	row_pointers = malloc(sizeof(*row_pointers) * height);
	if (!row_pointers)
		goto free_and_err;

	png_read_update_info(png_ptr, info_ptr);
	rowbytes = png_get_rowbytes(png_ptr, info_ptr);

	image_data = malloc(rowbytes * height);
	if (!image_data)
		goto free_and_err;

	for (i = 0; i < height; ++i)
		row_pointers[i] = image_data + i*rowbytes;

	png_read_image(png_ptr, row_pointers);

	ImageWidth = width;
	ImageHeight = height;
	if (FixScale) {
		if (((double)ImageWidth/(double)ImageHeight) > ((double)ScreenWidth/(double)ScreenHeight)) {
			ImageHeight = (unsigned long)((double)ImageHeight*(double)ScreenWidth/(double)ImageWidth);
			ImageWidth = ScreenWidth;
		} else {
			ImageWidth = (unsigned long)((double)ImageWidth*(double)ScreenHeight/(double)ImageHeight);
			ImageHeight = ScreenHeight;
		}
		CreateScaleTable(width, height);
		printf("ImageWidth=%ld ImageHeight=%ld\n", ImageWidth, ImageHeight);
	}

	for (i = 0; i < height; ++i) {
		/* Assume put_scanline_someplace wants a pointer and sample count. */
		if (FixScale)
			put_scanline_someplace_scale(row_pointers, row_stride, i-1);
		else
			put_scanline_someplace_noscale(row_pointers, row_stride, i-1);
	}

	if (FixScale)
		ReleaseScaleTable();

	/* Now do some quick cleanup */
	png_read_end(png_ptr, info_ptr);
	png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
	free(row_pointers);
	free(image_data);
	fclose(infile);

	/* And we're done! */
	return 1;
}

int main(int argc, char *argv[])
{
	int i, j;
	int fd = -1;
	int sec = 5;

	struct fb_var_screeninfo vi, initial_vi;

	if (argc < 2) {
		printf(
			"Usage: pngview <-s[Seconds]> <-f|-o> file_1.png file_2.png ...\n"
			"\t-s[Seconds] : Time to show this picture\n"
			"\t-q : quiet mode\n"
			"\t-f : Fixed Scale\n"
			"\t-o : None-Fixed Scale\n");
		return -1;
	}

	if (getenv("TEST") != NULL) {
		printf("ret: %i\n", read_png_file(argv[1]));
		return 0;
	}

	fd = open("/dev/fb0", O_RDWR);
	if (fd < 0) {
		perror("could not open /dev/fb0");
		return 1;
	}

	ioctl(fd, FBIOGET_VSCREENINFO, &initial_vi);
	initial_vi.xoffset = initial_vi.yoffset = 0;

	ioctl(fd, FBIOGET_VSCREENINFO, &vi);

	framebase = mmap(0, vi.xres * vi.yres * 2, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (framebase == MAP_FAILED) {
		close(fd);
		perror("unable to mmap frame buffer");
		return 1;
	}

	ScreenWidth = vi.xres;
	ScreenHeight = vi.yres;

	memset(framebase, 0x00, vi.xres*vi.yres*2);

	for (i=1; i<argc; ++i) {
		for (j=0; j<vi.xres*vi.yres; j++)
			((unsigned short*)framebase)[j] = 0x8000;

		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
				case 'F': case 'f':
					FixScale = 1;
					break;
				case 'O': case 'o':
					FixScale = 0;
					break;
				case 'S': case 's':
					sec = atoi (argv[i]+2);
					break;
				case 'Q': case 'q':
					fclose(stdout);
					break;
			}
			continue;
		}
		printf("%d %d %d %d %d %d %d %d %d %d\n",
			vi.xres, vi.yres, vi.xres_virtual, vi.yres_virtual, vi.xoffset,
			vi.yoffset, vi.bits_per_pixel, vi.grayscale, vi.width, vi.height);
		printf("read %s %s\n", argv[i], read_png_file(argv[i]) ? "OK" : "FAIL");
		sleep(sec);
	}

	munmap(framebase, vi.xres * vi.yres * 2);
	close(fd);

	return 0;
}
