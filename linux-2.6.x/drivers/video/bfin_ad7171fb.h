/*
 * linux/drivers/video/bfin_ad7171.h -- Analog Devices Blackfin + AD7171 video out chip
 *
 * Based on vga16fb.c: Copyright 1999 Ben Pfaff <pfaffben@debian.org> and Petr Vandrovec <VANDROVE@vc.cvut.cz>
 * Copyright 2004 Ashutosh Kumar Singh (ashutosh.singh@rrap-software.com)
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.
 */

#define BLACK   (0x01800180)            /* black pixel pattern	*/
#define BLUE    (0x296E29F0)		/* blue pixel pattern	*/
#define RED     (0x51F0515A)		/* red pixel pattern	*/
#define MAGENTA (0x6ADE6ACA)            /* magenta pixel pattern*/
#define GREEN   (0x91229136)            /* green pixel pattern	*/
#define CYAN    (0xAA10AAA6)            /* cyan pixel pattern	*/
#define YELLOW  (0xD292D210)            /* yellow pixel pattern	*/
#define WHITE   (0xFE80FE80)            /* white pixel pattern	*/

#define true 	1
#define false	0

struct system_code_type {
	unsigned int sav;	/* Start of Active Video */
	unsigned int eav;	/* End of Active Video */
};

#ifdef CONFIG_NTSC
const struct system_code_type system_code_map[4] =
{
	{ 0xFF0000EC, 0xFF0000F1 },
	{ 0xFF0000AB, 0xFF0000B6 },
	{ 0xFF000080, 0xFF00009D },
	{ 0xFF0000C7, 0xFF0000DA }
};
#define FIELD1_VB_START		1
#define FIELD1_VB_END  		23
#define FIELD1_AV_START		24
#define FIELD1_AV_END  		263
#define FIELD2_VB_START		264
#define FIELD2_VB_END  		285
#define FIELD2_AV_START		286
#define FIELD2_AV_END  		585
#define HB_LENGTH		268

#define RGB_WIDTH      		720
#define RGB_HEIGHT     		480
#define YCBCR_WIDTH    		1716
#define YCBCR_HEIGHT   		525

#else /* CONFIG_PAL */
const struct system_code_type system_code_map[4] =
{
	{ 0xFF0000AB, 0xFF0000B6 },
	{ 0xFF000080, 0xFF00009D },
	{ 0xFF0000EC, 0xFF0000F1 },
	{ 0xFF0000C7, 0xFF0000DA }
};
#define FIELD1_VB_START		1
#define FIELD1_VB_END		22
#define FIELD1_AV_START		23
#define FIELD1_AV_END		310
#define FIELD2_VB_START 	311
#define FIELD2_VB_END		335
#define FIELD2_AV_START		336
#define FIELD2_AV_END		623
#define FIELD2_VB2_START 	624
#define FIELD2_VB2_END		625
#define HB_LENGTH		280

#define RGB_WIDTH       	720
#define RGB_HEIGHT      	576
#define YCBCR_WIDTH     	1728
#define YCBCR_HEIGHT    	625
#endif /* CONFIG_NTSL */

struct rgb_t {
	unsigned char r,g,b;
};

struct ycrcb_t {
	unsigned char   Cb,y1,Cr,y2;
};

struct adv7171 {
	unsigned char reg[128];

	int input;
	int enable;
	int bright;
	int contrast;
	int hue;
	int sat;
};

#define   I2C_ADV7171        0x54
