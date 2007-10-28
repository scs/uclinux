/*      $Id: hw_creative_infracd.h,v 5.1 2003/05/07 17:30:40 lirc Exp $      */

/****************************************************************************
 ** hw_creative_infra.h *****************************************************
 ****************************************************************************
 *
 * routines for Creative iNFRA CDROM
 *
 * Copyright (C) 2003 Froenchenko Leonid <lfroen@il.marvell.com>
 */

#ifndef HW_CREATIVE_INFRA
#define HW_CREATIVE_INFRA

#define MAX_SCSI_REPLY_LEN     96
#define SCSI_INQ_CMD_LEN       6
#define SCSI_TUR_CMD_LEN       6
#define SCSI_SEN_CMD_LEN       10

int creative_infracd_init(void);
int creative_infracd_deinit(void);
int creative_infracd_decode(struct ir_remote *remote,
			    ir_code *prep,ir_code *codep,ir_code *postp,
			    int *repeat_flagp,lirc_t *remaining_gapp);
char *creative_infracd_rec(struct ir_remote *remotes);

/* private stuff */
#define MASK_COMMAND_PRESENT 0x00f00000

int test_device_command(int fd);

#endif
