/*
 * v4l2 driver for Bfin533+ADV7171+ADV7183
 * Copyright (C) 2005 Rrap Software Pvt. Ltd. 
 * by Ashutosh K Singh <ashutosh.singh@rrap-software.com>
 * Based on 
 * Zoran zr36057/zr36067 PCI controller driver, for the
 * Pinnacle/Miro DC10/DC10+/DC30/DC30+, Iomega Buz, Linux
 * Media Labs LML33/LML33R10.  by Serguei Miridonov <mirsev@cicese.mx>
 *
 *
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/config.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <linux/interrupt.h>

#include <linux/spinlock.h>
#include <linux/videodev.h>
#include <linux/videodev2.h>

#define	BFIN_VID_TYPE  ( VID_TYPE_CAPTURE | VID_TYPE_OVERLAY )
#define	V4L2_BFIN_NAME "V4L2_BFIN_VIDEO_DRIVER"	

#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>

#include <linux/video_decoder.h>
#include <linux/video_encoder.h>
#include <asm/byteorder.h>
#include "bfin_v4l2_driver.h"

extern int init_device_bfin_v4l2();
extern int device_bfin_close();

#define BFIN_V4L2_VID_FLAGS V4L2_CAP_VIDEO_OUTPUT
#define BFIN_V4L2_HARDWARE 26	      	//Dont know what it should be !.
#define NO_OF_DEVICES 		1 	//It ll be changed to 2 when
					//support for captuter will
					//get activated.

#define NO_OF_FRAMES_PER_BUFFER		5
#define FRAME_SIZE_WITHOUT_BLANKING	754560
#define GENERIC_BUFFER_SIZE (NO_OF_FRAMES_PER_BUFFER * FRAME_SIZE_WITHOUT_BLANKING)
					//large enough to hold NO_OF_FRAMES_PER_BUFFER frames
					//of ycrcb data
#define V4L2_YCRCB_FRAME_SIZE 1512000	//size of one ycrcb frame
					//with blanking info(EAV,SAV)

char *ycrcb_buffer_out = NULL ;	//This is the pointer to
				//buffer from
				//which actual output to
				//IC AD7171 will occur
int *pre_ycrcb_buffer_out = NULL ;
struct bfin_v4l2 bfin_v4l2[NO_OF_DEVICES];


/*
 *   Open a bfin_v4l2 card. Right now the flags stuff is just playing
 */

static int
bfin_v4l2_open (struct inode *inode,
	    struct file  *file)
{
	unsigned int minor = iminor(inode);
	int i, res, first_open = 0, have_module_locks = 0;
	struct bfin_v4l2 *bfn = NULL; 
	struct bfin_v4l2_fh *fh;

	for (i = 0; i < NO_OF_DEVICES; i++) {
		if (bfin_v4l2[i].videodev->minor == minor) {
			bfn = &bfin_v4l2[i];
			break;
		}
	}
	if (!bfn) {
		printk("dev/video: device not found!\n");
		res = -ENODEV;
		goto open_unlock_and_return;
	}

/* Though we are directly assuming the device to 
 * be vout0 as our first target is to get 
 * video-out up, we ll have to use some device 
 * finding algorithm when code for capture
 * shall get incorporated.
 */

	/* try to grab a module lock */
	if (!try_module_get(THIS_MODULE)) {
		printk("dev/video: failed to acquire my own lock! PANIC!\n");
		res = -ENODEV;
		goto open_unlock_and_return;
	}
	have_module_locks = 1;

	if (bfn->user >= 1) {
		printk("dev/video: too many users (%d) on device\n",
			bfn->user);
		res = -EBUSY;
		goto open_unlock_and_return;
	}



	fh = (struct bfin_v4l2_fh *)kmalloc(sizeof(struct bfin_v4l2_fh), GFP_KERNEL);
	if(!fh){
		printk("dev/video:Memory allocation for file failed\n");
		goto open_unlock_and_return;
	}
	file->private_data = fh;
	fh->bfn = bfn;
	fh->buffer = (char *)kmalloc(GENERIC_BUFFER_SIZE, GFP_KERNEL) ;
	if(!fh->buffer){
		printk("dev/vout: memory allocation failed\n") ;
		goto open_unlock_and_return;
	}

#if 0 		//perhaps this portion of code is not needed
		//but lets leave it and remove at some later
		//stage.
	if((minor -192) == 0)		// dev/vout device. 192->base for vout
	{
		pre_ycrcb_buffer_out = fh->buffer ;	
	}
#endif

	if (bfn->user++ == 0)
		first_open = 1;

	if (first_open) {	/* First device open */
		ycrcb_buffer_out = (char *)kmalloc(GENERIC_BUFFER_SIZE, GFP_KERNEL) ;
		if(!ycrcb_buffer_out) {
			printk("dev/vout: ycrcb_buffer_out memory allocation failed \n");
			goto open_unlock_and_return;
		}
			
		
		init_device_bfin_v4l2();

	}
printk("dev/video: opened\n");
	return 0;

open_unlock_and_return:
	/* if we grabbed locks, release them accordingly */
	if (have_module_locks) {
		module_put(THIS_MODULE);
	}

	return res;
}

static int
bfin_v4l2_close (struct inode *inode,
	     struct file  *file)
{
	struct bfin_v4l2_fh *fh = file->private_data;
	struct bfin_v4l2 *bfn = fh->bfn;

	/* kernel locks (fs/device.c), so don't do that ourselves
	 * (prevents deadlocks) */
	/*down(&zr->resource_lock);*/

	if (bfn->user-- == 1) {	/* Last process */
		device_bfin_close();	//Reset the video
					//hardware, PPI 	
					//and DMA as well

		kfree(ycrcb_buffer_out) ;  //free the buffer
					   //from which output
					   //to PPI taking
					   //place		
	}

	file->private_data = NULL;
	kfree(fh->buffer);
	kfree(fh);
	module_put(THIS_MODULE);

	return 0;
}


static ssize_t
bfin_v4l2_read (struct file *file,
	    char        __user *data,
	    size_t       count,
	    loff_t      *ppos)
{
	struct bfin_v4l2_fh *fh ;
	fh = file->private_data;
	memcpy(data, fh->buffer, count);
	fh->read_flag = 1 ;
	return 0;
}

static ssize_t
bfin_v4l2_write (struct file *file,
	     const char  __user *data,
	     size_t       count,
	     loff_t      *ppos)
{
/* As only vout is implemented currently
 * and single open is supported per device,
 * we can go for very simple implementation
 * i.e. simply copy the required no. of
 * bytes(count) in the desired buffer.
 * But as no. of devices shall increase
 * this ll need to be reorganised in more 
 * elegent way.
 */

	struct bfin_v4l2_fh *fh ;
	fh = file->private_data;
//	memcpy(fh->buffer, data, count);
	fh->write_flag = 1 ;
	pre_ycrcb_buffer_out = (int *)data ;	
	bfin_v4l2_update_video() ;
	return 0;
}


/*
 *   ioctl routine
 */

static int
do_bfin_v4l2_ioctl (struct inode *inode,
	        struct file  *file,
	        unsigned int  cmd,
	        void         *arg)
{
	struct bfin_v4l2_fh *fh = file->private_data;

/* This declartion is currently
 * useless, but once we ll start
 * working on capture this will
 * be needed.
 */
	struct bfin_v4l2 *bfn = fh->bfn;


	switch (cmd) {


		/* The new video4linux2 capture interface - much nicer than video4linux1, since
		 * it allows for integrating the JPEG capturing calls inside standard v4l2
		 */

	case VIDIOC_QUERYCAP:
	{
		struct v4l2_capability *cap = arg;

		printk("VIDEOC_QUERYCAP called\n");
		memset(cap, 0, sizeof(*cap));

/* Currently only vout is being implemented 
 * so we will not go for checking of device
 * i.e. whether it is input or output device,
 * but once capture device is up we will need
 * check and set capability accordingly.
 */

		cap->capabilities = BFIN_V4L2_VID_FLAGS;

		return 0;
	}
		break;

	case VIDIOC_ENUMINPUT:
	{
		printk("VIDIOC_ENUMINPUT called\n");
		return 0;
	}
		break;
 

	case VIDIOC_G_INPUT:
	{

		printk("VIDIOC_G_INPUT called\n");
		return 0;
	}
		break;


	case VIDIOC_S_INPUT:
	{
		printk("VIDIOC_S_INPUT called not implemented\n");
		return 0;
	}
		break;

	case VIDIOC_G_STD:
	{
		printk("VIDIOC_G_STD called not implemented\n");
		return 0;
	}
		break;

	case VIDIOC_S_STD:
	{
		printk("VIDIOC_C_STD called not implemented\n");
		return 0;
	}
		break;
	

	case VIDIOC_ENUMSTD:
	{
		struct v4l2_standard *std = arg;
		printk("VIDIOC_ENUMSTD called\n");

		if (std->index < 0)
			return -EINVAL;
		else {
			int id = std->index;
			memset(std, 0, sizeof(*std));
			std->index = id;
		}
		switch (std->index) {


#if 0		//Once the support for PAL is up 
		//we will enable this piece of
		//code.
		case 0:
			std->id = V4L2_STD_PAL;
			strncpy(std->name, "PAL", 31);
			std->frameperiod.numerator = 1;
			std->frameperiod.denominator = 25;
			std->framelines = 625 ; 
			break;
#endif


		case 0:
			std->id = V4L2_STD_NTSC;
			strncpy(std->name, "NTSC", 31);
			std->frameperiod.numerator = 1001;	//i.e. nearly 30 frames
			std->frameperiod.denominator = 30000;	//per sec.
			std->framelines = 624 ; 
			break;
		default:
			return -EINVAL;
		}
		return 0;
	}
		break;

	case VIDIOC_G_FMT:
	{

		struct v4l2_format *fmt = arg;
		int type = fmt->type;

		printk("VIDIOC_G_FMT called not implemented\n");

		memset(fmt, 0, sizeof(*fmt));
		fmt->type = type;

		switch (fmt->type) {

		case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		case V4L2_BUF_TYPE_VIDEO_OUTPUT:



			fmt->fmt.pix.width 		= 320;
			fmt->fmt.pix.height 		= 360;
			fmt->fmt.pix.sizeimage 		= 115200;
			fmt->fmt.pix.pixelformat 	= V4L2_PIX_FMT_UYVY ;
			fmt->fmt.pix.field 		= V4L2_FIELD_INTERLACED ;

			fmt->fmt.pix.bytesperline 	= 0;
			fmt->fmt.pix.colorspace 	= V4L2_COLORSPACE_SMPTE170M;

			break;

		default:
			printk( "dev/vout: VIDIOC_G_FMT - unsupported type \n");
			return -EINVAL;
		}
		return 0;
	}
		break;

	case VIDIOC_S_FMT:
	{

		struct v4l2_format *fmt = arg;
		int res = 0;

		switch (fmt->type) {
		case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		case V4L2_BUF_TYPE_VIDEO_OUTPUT:


			if (!(fmt->fmt.pix.pixelformat == V4L2_PIX_FMT_UYVY
 			     || fmt->fmt.pix.width 		== 320
			      || fmt->fmt.pix.height 		 == 360
			       || fmt->fmt.pix.sizeimage 	  == 115200
			    	|| fmt->fmt.pix.pixelformat 	   == V4L2_PIX_FMT_UYVY 
			     	 || fmt->fmt.pix.field 		    == V4L2_FIELD_INTERLACED 
			       	  || fmt->fmt.pix.bytesperline 	     == 0
				   || fmt->fmt.pix.colorspace 	      == V4L2_COLORSPACE_SMPTE170M
			  )){
				printk("ERROR:DEV/VOUT:Application is trying to set unacceptable parameters\n");
				return -EINVAL;
			}

		default:
			printk("dev/vout: VIDIOC_S_FMT - unsupported type\n");
			return -EINVAL;
		}

		return res;
	}
		break;

	case VIDIOC_ENUMOUTPUT:
	{
		struct v4l2_output *outp = arg;

		printk("VIDEO_ENUMOUTPUT called\n");

		if (outp->index != 0)
			return -EINVAL;

		memset(outp, 0, sizeof(*outp));
		outp->index = 0;
		outp->type = V4L2_OUTPUT_TYPE_ANALOG;
		strncpy(outp->name, "Autodetect", 31);
		return 0;
	}
		break;

	case VIDIOC_G_OUTPUT:
	{
		int *output = arg;

		*output = 0;
		printk("VIDIOC_G_OUTPUT called\n");

		return 0;
	}
		break;

	case VIDIOC_S_OUTPUT:
	{

		int *output = arg;
		printk("VIDIOC_S_OUTPUT called\n");

		if (*output != 0)
			return -EINVAL;
		return 0;
	}
		break;

	case VIDIOC_TRY_FMT:
	{

		printk("VIDIOC_TRY_FMT called not implemented\n");
		return 0;
	}
		break;

	default:
		printk("unknown/unsupported ioctl command\n");
		return -ENOIOCTLCMD;
		break;

	}
	return 0;
}

static int
bfin_v4l2_ioctl (struct inode *inode,
	     struct file  *file,
	     unsigned int  cmd,
	     unsigned long arg)
{
	return video_usercopy(inode, file, cmd, arg, do_bfin_v4l2_ioctl);
}


static unsigned int
bfin_v4l2_poll (struct file *file,
	    poll_table  *wait)
{
	printk("bfin_v4l2_poll called not implemented yet\n");
	return 0;
}


/* It is for sure this mmap() implementation 
 * has to more elaborate and more cautious about 
 * inadvertant accesses. But lets come to this 
 * issue later and lets assume 
 * the application writer using this driver is 
 * not doing something unexpected. 
 */
static char *
bfin_v4l2_mmap (struct file           *file,
	    struct vm_area_struct *vma)
{

	return 0;
}


static void
bfin_v4l2_vdev_release (struct video_device *vdev)
{
	kfree(vdev);
}


static struct file_operations v4l2_bfin_v4l2_fops = {
	.owner 		= THIS_MODULE,
	.open 		= (void *)bfin_v4l2_open,
	.release	= (void *)bfin_v4l2_close,
	.ioctl 		= (void *)bfin_v4l2_ioctl,
	.llseek 	= (void *)no_llseek,
	.read 		= (void *)bfin_v4l2_read,
	.write 		= (void *)bfin_v4l2_write,
	.mmap 		= (void *)bfin_v4l2_mmap,
	.poll 		= (void *)bfin_v4l2_poll,
};

static struct video_device bfin_v4l2_template = {
	.name 		= "V4L2_BFIN_VIDEO_DRIVER",
	.type 		= BFIN_VID_TYPE,
	.type2 		= BFIN_V4L2_VID_FLAGS,
	.hardware 	= BFIN_V4L2_HARDWARE,
	.fops 		= &v4l2_bfin_v4l2_fops,
	.release 	= &bfin_v4l2_vdev_release,
	.minor 		= 0, 
};



static int __devinit
bfin_v4l2_register_device(struct bfin_v4l2 *bfn)
{
printk("bfin_v4l2_register_device called\n") ;
	bfn->videodev = (void *) kmalloc(sizeof(struct video_device), GFP_KERNEL);
	memcpy(bfn->videodev, &bfin_v4l2_template, sizeof(bfin_v4l2_template));
	strcpy(bfn->videodev->name, bfin_v4l2_template.name);

	if (video_register_device(bfn->videodev, VFL_TYPE_VTX, 0) < 0) {
		printk("unable to register v4l2 driver for bfin_v4l2\n");
		return -1;
	}
	bfn->initialized = 1 ;
printk("V4L2 registration for BFIN video card completed\n");
		return 0;
}

static void __devinit
bfin_v4l2_unregister_device(struct bfin_v4l2 *bfn)
{
	if(!bfn->initialized)
		return ;
	video_unregister_device(bfn->videodev);
}
static int __init
init_bfin_v4l2()
{
	int i, j ;
	struct bfin_v4l2 *bfn ;
	for(i =0; i<NO_OF_DEVICES ;i++) {
		bfn = &bfin_v4l2[i] ; 
		if(bfin_v4l2_register_device(bfn)<0){
			for(j=i;j>=0;j--)
				bfin_v4l2_unregister_device(&bfin_v4l2[i]);
			return -EIO;
		}	
	}
	return 0;
}
static void __exit
unload_bfin_v4l2_module()
{
	int i;
	for(i=0; i<NO_OF_DEVICES;i++)
	bfin_v4l2_unregister_device(&bfin_v4l2[i]);
}
		

module_init(init_bfin_v4l2);
module_exit(unload_bfin_v4l2_module);
