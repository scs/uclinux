/*      $Id: hw_creative_infracd.c,v 5.4 2005/07/10 08:34:11 lirc Exp $      */

/*
 * Remote control driver for the Creative iNFRA CDrom
 *
 *  by Leonid Froenchenko <lfroen@il.marvell.com>
 *    thnx Kira Langerman for donated hardware
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <scsi/sg.h>
#include <scsi/scsi.h>

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "hw_creative_infracd.h"

struct hardware hw_creative_infracd = {
	0,	        	/* determine device by probing */
	-1,			/* fd */
	LIRC_CAN_REC_CODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,	/* rec_mode */
	8,			/* code_length */
	creative_infracd_init,	/* init_func */
	NULL,			/* config_func */
	creative_infracd_deinit,/* deinit_func */
	NULL,			/* send_func */
	creative_infracd_rec,	/* rec_func */
	creative_infracd_decode,/* decode_func */
	NULL,                   /* ioctl_func */
	NULL,
	"creative_infracd"
};

/*
 opened /dev/sg<x>. I'm not using hw.fd for reasons of lirc design
*/
static int int_fd = 0;

/* last code seen from remote */
static ir_code code;

static char dev_name[32];

int is_my_device(int fd,char *name)
{
	sg_io_hdr_t io_hdr;
	int k;
	unsigned char inqCmdBlk [SCSI_INQ_CMD_LEN] = 
		{INQUIRY, 0, 0, 0, MAX_SCSI_REPLY_LEN, 0};
	unsigned char Buff[MAX_SCSI_REPLY_LEN];
	unsigned char sense_buffer[32];

	/* Just to be safe, check we have a sg device wigh version > 3 */
	if ((ioctl(fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
		LOGPRINTF(LOG_ERR, "%s isn't sg device version > 3",name);
		return 0;
	} else {
		usleep(10);
		LOGPRINTF(1,"%s is valid sg device - checking what it is",
			  name);
	}

	/* Prepare INQUIRY command */
	memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof(inqCmdBlk);
	io_hdr.mx_sb_len = sizeof(sense_buffer);
	io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	io_hdr.dxfer_len = MAX_SCSI_REPLY_LEN;
	io_hdr.dxferp = Buff;
	io_hdr.cmdp = inqCmdBlk;
	io_hdr.sbp = sense_buffer;
	io_hdr.timeout = 2000;

	if (ioctl(fd, SG_IO, &io_hdr) < 0) {
		LOGPRINTF(LOG_ERR, "INQUIRY SG_IO ioctl error");
		return 0;
	} else {
		usleep(10);
	}
	if ( (io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
		LOGPRINTF(LOG_ERR,
			  "INQUIRY: SCSI status=0x%x host_status=0x%x "
			  "driver_status=0x%x",io_hdr.status,
			  io_hdr.host_status,io_hdr.driver_status);
		return 0;
	}
	/* check INQUIRY returned string */
	if ( strncmp(Buff+8,"CREATIVE",8) > 0 ) {
		LOGPRINTF(LOG_ERR, "%s is %s (vendor isn't Creative)",
			  name,Buff+8);
	}

	/* now run sense_mode_10 for page 0 to see if this is really it */
	if ( test_device_command(fd) < 0 ) {
		return 0;
	}
	return 1;
}

/* actually polling function */
int test_device_command(int fd)
{
	sg_io_hdr_t io_hdr;
	unsigned char senCmdBlk[SCSI_SEN_CMD_LEN] = 
		{ MODE_SENSE_10, 0, 0, 0, 0, 0, 0, 0, MAX_SCSI_REPLY_LEN, 0 };

	unsigned char sense_buffer[255];
	unsigned char Buff[MAX_SCSI_REPLY_LEN];
        unsigned int *i_Buff = (unsigned int *)Buff;

	memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
	io_hdr.interface_id = 'S';
	io_hdr.cmd_len = sizeof(senCmdBlk);
	io_hdr.mx_sb_len = sizeof(sense_buffer);
	io_hdr.dxfer_direction = SG_DXFER_TO_FROM_DEV;
	io_hdr.dxfer_len = MAX_SCSI_REPLY_LEN;
	io_hdr.dxferp = Buff;
	io_hdr.cmdp = senCmdBlk;
	io_hdr.sbp = sense_buffer;
	io_hdr.timeout = 2000;

	memset(Buff,0,MAX_SCSI_REPLY_LEN);

	if (ioctl(fd, SG_IO, &io_hdr) < 0) {
		LOGPRINTF(LOG_ERR, "MODE_SENSE_10 SG_IO ioctl error");
		return -1;
	}

	if ( (io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
		LOGPRINTF(LOG_ERR, 
			  "MODE_SENSE_10: status=0x%x host=0x%x driver=0x%x",
			  io_hdr.status,io_hdr.host_status,
			  io_hdr.driver_status);
		return -1;
	}
	if ( i_Buff[2] & MASK_COMMAND_PRESENT ) {
		// when command present - opcode is found on bits [15:8]
		return (i_Buff[3] >> 8) & 0xff;
	}
	// device ok, but no command
	return 0;
}


char *creative_infracd_rec(struct ir_remote *remotes)
{
	int cmd;

	while ( (cmd = test_device_command(int_fd)) == 0 ) {
		usleep(40);
	};
	if ( cmd == -1 ) {
		return 0;
	}
	
	code = (reverse(cmd,8) << 8) | (~reverse(cmd,8) & 0xff);
	return decode_all(remotes);
}

int creative_infracd_decode(struct ir_remote *remote,
			    ir_code *prep,ir_code *codep,ir_code *postp,
			    int *repeat_flagp,lirc_t *remaining_gapp)
{
	if(!map_code(remote,prep,codep,postp,16,0x8435,16,code,0,0))
	{
		return 0;
	}
	
	return 1;
}

int init_device()
{
	char c;
	int fd;
	
	/* user overriding autoprobing */
	if ( hw.device ) {
		fd = open(hw.device,O_RDWR);
		if ( fd < 0 ) {
			LOGPRINTF(1, "Init: open of %s failed", hw.device);
			return 0;
		}
		/* open ok, test device */
		if ( is_my_device(fd,hw.device) ) {
			return fd;
		}
		return 0;
	}
	for(c = 'a';c < 'z';c++) {
		sprintf(dev_name,"/dev/sg%c",c);
		fd = open(dev_name,O_RDWR);
		if ( fd < 0 ) {
			LOGPRINTF(1, "Probing: open of %s failed", dev_name);
			continue;
		}
		/* open ok, test device */
		if ( is_my_device(fd,dev_name) ) {
			hw.device = dev_name;
			return fd;
		}
	}
	return 0;
}

int creative_infracd_init(void)
{
	int fd;

	LOGPRINTF(1, "Creative iNFRA driver: begin search for device");

	if ( (fd = init_device()) ) {
		/*
		  lircd making "select" for device we open. However,
		  /dev/sg<x> does not behave like /dev/ttyS<x>, i.e. it
		  never asserted untill we explicitly send some scsi
		  command. So, make lircd think that device always
		  has data, and make polling loops myself
		*/
		hw.fd = open("/dev/null",O_RDONLY);
		if(hw.fd == -1)
		{
			close(fd);
			return 0;
		}
		int_fd = fd;
		LOGPRINTF(1, "Probing: %s is my device", hw.device);
		return 1;
	}
	
	/* probing failed - simple sanity check why */
	fd = open("/proc/scsi/scsi",O_RDONLY);
	if ( fd < 0 ) {
		LOGPRINTF(LOG_ERR, "Probing: unable to open /proc/scsi/scsi");
	} else {
		close(fd);
		fd = open("/proc/scsi/ide-scsi/0",O_RDONLY);
		if ( fd < 0 ) {
			LOGPRINTF(LOG_ERR, "Probing: scsi support present "
				  "but ide-scsi is not loaded");
		} else {
			close(fd);
			LOGPRINTF(LOG_ERR, "Probing: scsi in kernel, "
				  "ide-scsi is loaded. Bad configuration or "
				  "device not present");
		}
	}
	return 0;
}

int creative_infracd_deinit(void)
{
	close(hw.fd);
	close(int_fd);
	return 1;
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-basic-offset: 8
 * End:
 */
