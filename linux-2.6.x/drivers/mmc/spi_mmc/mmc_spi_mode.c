/**************************************************************
*
* Copyright (C) 2005, Rubico AB. All Rights Reserve.
*
* Developed as a part the CDT project C4(www.cdt.ltu.se).
*
* FILE mmc_spi_mode.c
*
* PROGRAMMER: Hans Eklund (Rubico AB)
*
* DATE OF CREATION: April, 2006.
*
* SYNOPSIS:
*
* DESCRIPTION: SPI-MMC/SD Protocol.
*
* DEPENDENCIES: Independent.
*	(well, one, for printing debug text on the target, (kernel.h for linux))
*
* TODO: Correct Multiple block read and write functions. Didnt have time
*	to make them all failsafe. Will be done soon.
*
**************************************************************
*
* This program is free software; you can distribute it and/or modify it
* under the terms of the GNU General Public License (Version 2) as
* published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
*
**************************************************************/
#include "mmc_spi_mode.h"
#include <linux/kernel.h>	/* for printk() only*/
#include <linux/poll.h>

//#define DEBUG_MMC_SPI_MODE
#define DEBUG_MMC_SPI_STATUS
//#define USE_MULT_BLOCK_READS

#ifdef DEBUG_MMC_SPI_MODE
#define DPRINTK(x...)   printk("%lu, %s(): %d ", jiffies, __PRETTY_FUNCTION__, __LINE__);printk(x);
#else
#define DPRINTK(x...)   do { } while (0)
#endif

#ifdef DEBUG_MMC_SPI_STATUS
#define DPRINT_STAT(x...)   printk("%s(): %d ", __PRETTY_FUNCTION__, __LINE__);printk(x);
#else
#define DPRINT_STAT(x...)   do { } while (0)
#endif

static unsigned char mmc_cmd[6] = {0x40,0x00,0x00,0x00,0x00,0x95};
static unsigned char Null_Word[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static short read_mmc_reg(struct mmc_spi_dev *pdev, short csd);
static unsigned char mmc_wait_response(struct mmc_spi_dev *pdev, unsigned int timeout);


/**********************************************************************\
*
* MMC CSD/CID related, could be somewhat trimmed and cleaned
*
\**********************************************************************/
typedef unsigned char BOOL;
BOOL getbit(void* ptr, unsigned int n) {
	unsigned int byte_nr;
	unsigned int bit_nr;

	byte_nr = n/8;
	bit_nr = n % 8;

	return (BOOL)(((unsigned char*)ptr)[byte_nr] >> bit_nr) & 1;
}

unsigned int getvalue(void* ptr, unsigned int n, unsigned int len) {
	unsigned int value=0;
	int i=0;

	for(i=0;i<len; i++) {	
		value += ((unsigned int)getbit(ptr, n+i))<<i;
	}
	return value;
}

void mmc_spi_fill_card_struct(struct mmc_spi_dev *pdev)
{
	unsigned short c_size_mult=0;
	unsigned short c_size=0;
	
	unsigned char *raw_csd;
	unsigned char *raw_cid;

	// local, shorter names, just to keep lines below shorter
	raw_csd = pdev->raw_csd;
	raw_cid = pdev->raw_cid;
	
	pdev->csd.mmca_vsn = (raw_csd[0] & 0x3c) >> 2;
	pdev->csd.cmdclass = (((u16)raw_csd[4]) << 4) | ((raw_csd[5] & 0xf0) >> 4);
	pdev->csd.tacc_clks = raw_csd[1];
	pdev->csd.tacc_ns = raw_csd[2];
	pdev->csd.max_dtr = raw_csd[3];
	pdev->csd.read_blkbits = raw_csd[5] & 0x0f;
	
	// for calculating capacity(in blocks)
	c_size = ((((u16)raw_csd[6]) & 0x03) << 10) | (((u16)raw_csd[7]) << 2) | (((u16)raw_csd[8]) & 0xc0) >> 6;
	c_size_mult = ((raw_csd[9] & 0x03) << 1) | ((raw_csd[10] & 0x80) >> 7);
	pdev->csd.capacity = (c_size+1) * (1 << (c_size_mult + 2));
		
	pdev->cid.manfid = getvalue(raw_cid, 127-127, 8);
	memcpy(pdev->cid.prod_name, raw_cid+3, 7);
	pdev->cid.serial = getvalue(raw_cid, 127-47, 32);
	pdev->cid.oemid = getvalue(raw_cid, 127-119, 16);
	pdev->cid.year = 1997 + (getvalue(raw_cid, 127-15, 8) & 0x0F);
	pdev->cid.hwrev = (getvalue(raw_cid, 127-55, 8) & 0xF0) >> 4;
	pdev->cid.fwrev = getvalue(raw_cid, 127-55, 8) & 0x0F;
	pdev->cid.month = (getvalue(raw_cid, 127-15, 8) & 0xF0) >> 4;	
}

short mmc_spi_get_card(struct mmc_spi_dev *pdev)
{	
	//memset(pdev->raw_cid, 0, 18);
	//memset(pdev->raw_csd, 0, 18);
	
	if(read_mmc_reg(pdev, 0)) {
		DPRINTK("CSD register read failed.\n");
		return 1;
	}
	if(read_mmc_reg(pdev, 1)) {
		DPRINTK("CID register read failed.\n");
		return 1;
	}

	// Parse CSD and CID data
	mmc_spi_fill_card_struct(pdev);

	return 0;
}


static short send_cmd_and_wait(struct mmc_spi_dev *pdev, 
			       unsigned char command, 
			       unsigned int argument, 
			       unsigned short cmd_resp, 
			       unsigned int timeout)
{
	unsigned short resp=0xff;
	
	// Build command string
	mmc_cmd[0] = 0x40 + command;
	mmc_cmd[1] = (unsigned char)(argument >> 24 & 0xff);
	mmc_cmd[2] = (unsigned char)(argument >> 16 & 0xff);
	mmc_cmd[3] = (unsigned char)(argument >> 8 & 0xff);
	mmc_cmd[4] = (unsigned char)(argument & 0xff);
	mmc_cmd[5] = 0x95;	// CRC form CMD0 actually, but valid for all since SPI dont care

	if(pdev->write(Null_Word, SD_PRE_CMD_ZEROS, pdev->priv_data)<0) {
		DPRINTK("sending SD_PRE_CMD_ZEROS failed\n");
		return ERR_SPI_TIMEOUT;
	}
	if(pdev->write(mmc_cmd, 6, pdev->priv_data) < 0) {
		DPRINTK("sending command %d failed\n", command);
		return ERR_SPI_TIMEOUT;
	}
	if((resp=mmc_wait_response(pdev, timeout)) != cmd_resp) {
		DPRINTK("unexpected response to command %d, wanted 0x%x, got 0x%x)\n", command, cmd_resp, resp);
		return ERR_MMC_TIMEOUT;
	}
	return 0;
}

/**
* read_mmc_reg - reads the 128 bit CSD or CID register data + 2 byte CRC
*
*/
static short read_mmc_reg(struct mmc_spi_dev *pdev, short csd)
{
	unsigned char resp=0xff;
	unsigned char* buf;
	
	if(csd) {
		if(send_cmd_and_wait(pdev, SEND_CSD, 0, R1_OK, MMC_COMMAND_TIMEOUT)) {
			return 1;
		}
		buf = pdev->raw_csd;
	} else {
		if(send_cmd_and_wait(pdev, SEND_CID, 0, R1_OK, MMC_COMMAND_TIMEOUT)) {
			return 1;
		}
		buf = pdev->raw_cid;
	}
			
	// start block token
	if((resp=mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT)) != SBT_S_BLOCK_READ) {
        	DPRINTK("mmc did not send 0xFE(got 0x%x)\n",resp);
		return ERR_SPI_TIMEOUT;
        }
        if(pdev->read(buf, 18, pdev->priv_data) < 18) {
                DPRINTK("reading 18 bytes of data failed\n");
		return ERR_SPI_TIMEOUT;
        }
	return 0;
}

short mmc_spi_read_status(struct mmc_spi_dev *pdev)
{
	unsigned char b1=0;
	unsigned char b2=0;
	unsigned short r2=0xffff;
	static unsigned char status_cmd[6] = {0x4D,0x00,0x00,0x00,0x00,0x95};

	if(pdev->sd) {
		if(pdev->write(Null_Word, SD_PRE_CMD_ZEROS, pdev->priv_data)<0) {
			DPRINTK("sending SD_PRE_CMD_ZEROS failed\n");
			return ERR_SPI_TIMEOUT;
		}
	}
	if(pdev->write(status_cmd, 6, pdev->priv_data)<0) {
                DPRINTK("sending of SEND_STATUS command failed\n");
		return ERR_SPI_TIMEOUT;
		goto out;
	}	
	b1=mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT);
	b2=mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT);

	if(b1 == ERR_MMC_TIMEOUT || b2 == ERR_MMC_TIMEOUT) {
		return ERR_MMC_TIMEOUT;
	}

	r2 = b2 + (b1 << 8);
	
	if(r2) {
		DPRINT_STAT("r2: 0x%04x\n", r2);
	}
	return r2;
	
	// TODO: Implement in a finer way
	switch(b1) {
		case R1_OK:
			break;
		case R1_IDLE_STATE:
			DPRINT_STAT("R1_IDLE_STATE\n");
			break;
		case R1_ERASE_STATE:
			DPRINT_STAT("R1_ERASE_STATE\n");
			break;
		case R1_ILLEGAL_COMMAND:
			DPRINT_STAT("R1_ILLEGAL_COMMAND\n");
			break;
		case R1_COM_CRC_ERROR:
			DPRINT_STAT("R1_COM_CRC_ERROR\n");
			break;
		case R1_ERASE_SEQ_ERROR:
			DPRINT_STAT("R1_ERASE_SEQ_ERROR\n");
			break;
		case R1_ADDRESS_ERROR:
			DPRINT_STAT("R1_ADDRESS_ERROR\n");
			break;
		case R1_PARAMETER_ERROR:
			DPRINT_STAT("R1_PARAMETER_ERROR\n");
			break;
		case 0xFF:
			DPRINT_STAT("b1: STATUS RESPONSE TIMEOUT\n");
			break;
		default:
			DPRINT_STAT("b1: INVALID STATUS RESPONSE(0x%02x)\n", b1);
			break;
	}
		
	switch(b2) {
		case R2_OK:
			break;
		case R2_CARD_LOCKED:
			DPRINT_STAT("R2_CARD_LOCKED\n");
			break;
		case R2_WP_ERASE_SKIP:
			DPRINT_STAT("R2_WP_ERASE_SKIP/Unlock command failed\n");
			break;
		case R2_ERROR:
			DPRINT_STAT("R2_ERROR\n");
			break;
		case R2_CC_ERROR:
			DPRINT_STAT("R2_CC_ERROR\n");
			break;
		case R2_CARD_ECC_FAILED:
			DPRINT_STAT("R2_CARD_ECC_FAILED\n");
			break;
		case R2_WP_VIOLATION:
			DPRINT_STAT("R2_WP_VIOLATION\n");
			break;
		case R2_ERASE_PARAM:
			DPRINT_STAT("R2_ERASE_PARAM\n");
			break;
		case R2_OUT_OF_RANGE:
			DPRINT_STAT("R2_OUT_OF_RANGE, CSD_Overwrite\n");
			break;
		case 0xFF:
			DPRINT_STAT("b2: STATUS RESPONSE TIMEOUT\n");
			break;
		default:
			DPRINT_STAT("b2: INVALID STATUS RESPONSE(0x%02x)\n", b2);
			break;
	}

	out:

	return r2;
}

short mmc_spi_read_mmc_block(struct mmc_spi_dev *pdev, unsigned char* buf, unsigned int address)
{
        unsigned char resp=0xff;
	unsigned short rval = 0;
	//unsigned short status = 0;

	//DPRINTK("adr(r): %08x\n", address);
	if((rval=send_cmd_and_wait(pdev, READ_SINGLE_BLOCK, address, R1_OK, MMC_COMMAND_TIMEOUT))) {
		goto out;
	}

	// Poll for start block token
        if((resp=mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT)) != SBT_S_BLOCK_READ) {
        	DPRINTK("mmc did not send 0xFE(got 0x%x)\n",resp);
		rval= resp;
		goto out;

        }
	// Read data
        if(pdev->read(buf, 512, pdev->priv_data) < 512) {
                DPRINTK("reading 512 bytes of data failed\n");
		rval= ERR_SPI_TIMEOUT;
		goto out;
	}
	//  TODO: read CRC
	out:;
	switch(rval) {
		case ERR_SPI_TIMEOUT:
			DPRINTK("ERR_SPI_TIMEOUT\n");
			return RVAL_CRITICAL;
		case ERR_MMC_TIMEOUT:
			DPRINTK("ERR_MMC_TIMEOUT\n");
			return RVAL_ERROR;	
		case ERR_UNKNOWN_TOK:
		case DR_CRC_ERROR:
		case DR_WRITE_ERROR:
		default:
			if(mmc_spi_read_status(pdev)) {
				return RVAL_ERROR;
			} else {
				// NOTE: could use status to determine what to do better
				return RVAL_OK;
			}
	}
}

// Not implemented on Blackfin since DMA reads are a bit troublesome(512 bytes
//   requested could be 514 bytes read.. this could be solved with some hacks though)
#ifdef USE_MULT_BLOCK_READS
short mmc_spi_read_mult_mmc_block(struct mmc_spi_dev *pdev, unsigned char* buf, unsigned int address, int nblocks) 
{
	unsigned char resp=0xff;
	int rval=0;
	int i=0;

	if((rval=send_cmd_and_wait(pdev, READ_MULTIPLE_BLOCK, address, R1_OK, MMC_COMMAND_TIMEOUT))) {
		goto out;
	}
			
	/* idea: read n blocks in one swoop, Data, Garbage and Tokens
	* GGGGGTDDD..512..DDDGGGGTDDDD..512..DDDGGGGT - - - 
	*-------'''''''''''''.....''''''''''''''
	* Then memcpy data to the real buffer, may need a few pages of memory for this
	*/
	for(i=0; i<nblocks; i++) {
		//printk("varv: %d\n",i); 
		// Poll for start block token
		if((resp=mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT)) != SBT_M_BLOCK_READ) {
			DPRINTK("mmc did not send 0xFE(got 0x%x)\n",resp);
			rval= 1;	
			goto out;
		}
		// Read data	
		if(pdev->read(buf+i*MMC_SECTOR_SIZE, MMC_SECTOR_SIZE, pdev->priv_data) < MMC_SECTOR_SIZE) {	
			DPRINTK("reading 512 bytes of data failed\n");
			rval= 1;
			goto out;
		}
	}
	rval = 0;
	out:
	// send stop command
	rval=send_cmd_and_wait(pdev, STOP_TRANSMISSION, address, R1_OK, MMC_COMMAND_TIMEOUT))) {
	if(rval) {
		mmc_spi_read_status(pdev);
	}
	return rval;
}
#endif

short mmc_spi_write_mmc_block(struct mmc_spi_dev *pdev, unsigned char* buf, unsigned int address)
{
	unsigned short rval = 0;
	unsigned char resp=0xff;
        unsigned char token;
	static unsigned int n;

	n++;
	if((rval=send_cmd_and_wait(pdev, WRITE_BLOCK, address, R1_OK, MMC_COMMAND_TIMEOUT))) {
		DPRINTK("write error at %08x after %d blocks\n", address, n);
		goto out;
	}
	
        // send start block token
        token = SBT_S_BLOCK_WRITE;
        if(pdev->write(&token, 1, pdev->priv_data)<0) {
                DPRINTK("sending START_BLOCK_TOKEN failed\n");
		rval= ERR_SPI_TIMEOUT;
		goto out;

        }
        // transmit data block
	if(pdev->write(buf, MMC_SECTOR_SIZE, pdev->priv_data) < MMC_SECTOR_SIZE) {
                DPRINTK("transmission of 512 bytes failed\n");
		rval= ERR_SPI_TIMEOUT;
		goto out;

        }
        // wait for data response token
	if((resp = (mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT) & DR_MASK)) != DR_ACCEPTED) {
                DPRINTK("mmc did not send data_response_token(got R1=0x%x)\n",resp);
		rval = ERR_MMC_TIMEOUT;
		goto out;

        }
	pdev->reset_time(MMC_PROG_TIMEOUT);
	while(1) {
		// NOTE, could read response block-wise(effecive if DMA is utilized) to buffer
		// and check for tokens.
		if(pdev->read(&resp, 1, pdev->priv_data) < 0) {
			DPRINTK("busy token read polling failed\n");
			rval = resp;
			goto out;
		}
		if(pdev->elapsed_time()) {
			rval = ERR_MMC_TIMEOUT;
			goto out;
		}
		switch(resp & DR_MASK) {
			case BUSY_TOKEN:
				break;
			case DR_ACCEPTED:
				goto out;
			case DR_CRC_ERROR:
				rval = DR_CRC_ERROR;
				goto out;
			case DR_WRITE_ERROR:
				rval = DR_WRITE_ERROR;
				goto out;
			default:
				// If any other token is found, return.
				//   status will tell the story.
				goto out;
		}
	}
	out:;
	switch(rval) {
		case ERR_SPI_TIMEOUT:
			DPRINTK("ERR_SPI_TIMEOUT\n");
			return RVAL_CRITICAL;
		case ERR_MMC_TIMEOUT:
			DPRINTK("ERR_MMC_TIMEOUT\n");
			return RVAL_ERROR;	
		case ERR_UNKNOWN_TOK:
		case DR_CRC_ERROR:
		case DR_WRITE_ERROR:
		default:
			if(mmc_spi_read_status(pdev)) {
				return RVAL_ERROR;
			} else {
				// NOTE: could use status to determine what to do better
				return RVAL_OK;
			}
	}
}

short mmc_spi_write_mult_mmc_block(struct mmc_spi_dev *pdev, unsigned char* buf, unsigned int address, int nblocks)
{
	unsigned short rval = 0;
	unsigned char resp=0xff;
	//static unsigned char resp_buf[BUSY_BLOCK_LEN];
	unsigned int tc=0;
	int i=0;
	unsigned char token;
		
	if((rval=send_cmd_and_wait(pdev, WRITE_MULTIPLE_BLOCK, address, R1_OK, MMC_COMMAND_TIMEOUT))) {
		goto out;
	}

	for(i=0; i<nblocks; i++) {
		
		//DPRINTK("block_nr: %d of %d at address %u\n", i, nblocks, address);
		// send start block token
		token = SBT_M_BLOCK_WRITE;
		if(pdev->write(&token, 1, pdev->priv_data)<0) {
			DPRINTK("sending START_BLOCK_TOKEN failed\n");
			rval= ERR_SPI_TIMEOUT;
			goto stop;
	
		}
	        // transmit data block
		if(pdev->write(buf+i*MMC_SECTOR_SIZE, MMC_SECTOR_SIZE, pdev->priv_data) < MMC_SECTOR_SIZE) {
			DPRINTK("transmission of 512 bytes failed\n");
			rval= ERR_SPI_TIMEOUT;
			goto stop;
	
		}
        	// wait for data response token
		if((resp = (mmc_wait_response(pdev, MMC_COMMAND_TIMEOUT) & DR_MASK)) != DR_ACCEPTED) {
			DPRINTK("mmc did not send correct DR token(got R1=0x%x)\n",resp);
			rval= ERR_MMC_TIMEOUT;
			goto stop;

		}
	        // wait on busy/error token while MMC is programming new data
		tc=0;
		pdev->reset_time(MMC_PROG_TIMEOUT);
		while(1) {
			// read response byte-wise(take one or two reads only)
			if(pdev->read(&resp, 1, pdev->priv_data) < 0) {
				DPRINTK("busy token read polling failed\n");
				rval= ERR_SPI_TIMEOUT;
				goto stop;
			}
			//printk("0x%02x\n", resp);
			//printk("0x%02x\n", resp & DR_MASK);
			switch(resp & DR_MASK) {
				case BUSY_TOKEN:
					break;
				case DR_ACCEPTED:
					goto next;
				case DR_CRC_ERROR:
					rval = DR_CRC_ERROR;
					goto stop;
				case DR_WRITE_ERROR:
					rval = DR_WRITE_ERROR;
					goto stop;
				default:
					//rval = ERR_UNKNOWN_TOK;
					goto next;
			}
			if(pdev->elapsed_time()) {
				rval = ERR_MMC_TIMEOUT;
				goto stop;
			}
		}
		next:;
	}

	stop:
	// send stop tran token (STT_M_BLOCK_WRITE)
	token = STT_M_BLOCK_WRITE;
	if(pdev->write(&token, 1, pdev->priv_data)<0) {
		DPRINTK("sending STT_M_BLOCK_WRITE failed\n");
		rval = ERR_SPI_TIMEOUT;
		goto out;
	}
	// wait on final busy/error token while MMC is programming new data
	tc=0;
	pdev->reset_time(MMC_PROG_TIMEOUT);
	while(1 && !rval) {
		// read response 
		if(pdev->read(&resp, 1, pdev->priv_data) < 0) {
			DPRINTK("busy token read polling failed\n");
			rval= ERR_SPI_TIMEOUT;
			goto out;
		}
		// Exit when response goes high again
		if(resp == 0xff) {
			//DPRINTK("Got final MBW busy wait done after %d reads...\n", tc);
			goto out;
		}
		if(pdev->elapsed_time()) {
			rval = ERR_MMC_TIMEOUT;
			goto out;
		}
	}
	out:
	switch(rval) {
		case ERR_SPI_TIMEOUT:
			return RVAL_CRITICAL;
		case ERR_MMC_TIMEOUT:
			return RVAL_ERROR;	
		case ERR_UNKNOWN_TOK:
		case DR_CRC_ERROR:
		case DR_WRITE_ERROR:
		default:
			if(mmc_spi_read_status(pdev)) {
				return RVAL_ERROR;
			} else {
				// NOTE: could use status to determine what to do better
				return RVAL_OK;
			}
	}
}

short mmc_spi_init_card(struct mmc_spi_dev *pdev)
{
        unsigned short cntr=0;
	//unsigned char resp=0;
        int i=0;

	unsigned char wa[8] = {0xaa, 0x11,0xaa, 0x11,0xaa, 0x11,0xaa, 0x11};
	unsigned char rb[8] = {0xaa, 0x11,0xaa, 0x11,0xaa, 0x11,0xaa, 0x11};

	// For testing SPI drivers
	while(0) {
		pdev->write(wa, 1, pdev->priv_data);
		pdev->read(rb, 1, pdev->priv_data);
		//DPRINTK("rb: 0x%02x\n", rb[0]);
	}

        // Send 80 zeros to make card wake up
        for(i=0; i<8; i++) {
                if(pdev->write(Null_Word, 10, pdev->priv_data)<0) {
                        return 1;
                }
        }
	
	if(send_cmd_and_wait(pdev, GO_IDLE_STATE, 0, R1_IDLE_STATE, MMC_INIT_TIMEOUT)) {
		return 1;
	}

	// Look for SD card
	for(cntr=0; cntr< 60; cntr++) {
		if(send_cmd_and_wait(pdev, APP_CMD, 0, R1_OK, MMC_INIT_TIMEOUT) == 0) {
			goto next;
		}
		if(send_cmd_and_wait(pdev, APP_CMD, 0, R1_IDLE_STATE, MMC_INIT_TIMEOUT)) {
			continue;
		}
		next:
		if(send_cmd_and_wait(pdev, SD_SEND_OP_COND, 0, R1_OK, MMC_INIT_TIMEOUT) == 0) {
 			// Send One Byte Delay and return
			if(pdev->write(Null_Word, 1, pdev->priv_data)<0) {
				return 1;
			}
			pdev->sd = 1;
			DPRINTK("SD card found!\n");
			return 0;
		}
	}
			
	// poll card by sending CMD1 and wait for card initialization complete
        //DPRINTK("Looking for MMC card...\n");
        for(cntr=0; cntr< 60; cntr++ ) {
        	// Send One Byte Delay
                if(pdev->write(Null_Word, 1, pdev->priv_data)<0) {
                        return 1;
                }
                // Send CMD1
		if(send_cmd_and_wait(pdev, SEND_OP_COND, 0, R1_OK, MMC_INIT_TIMEOUT) == 0) {
 			// Send One Byte Delay and return
			if(pdev->write(Null_Word, 1, pdev->priv_data)<0) {
				return 1;
			}
			pdev->sd = 0;
			DPRINTK("MMC card found!\n");
			return 0;
		}
	}
        return 1;
}

static unsigned char mmc_wait_response(struct mmc_spi_dev *pdev, unsigned int timeout)
{
        unsigned char card_resp = 0xFF;
	
	// reset time and set to timeout ms
	pdev->reset_time(timeout);
	while(1) {
		if(pdev->read(&card_resp, 1, pdev->priv_data) < 0) {
			DPRINTK("error: mmc_wait_response read error\n");
			return ERR_SPI_TIMEOUT;
		}
		if(card_resp != 0xFF) {
 			return card_resp;
		}
		if(pdev->elapsed_time()) {
			// timeout
			DPRINTK("hey! timed out\n");
			return ERR_MMC_TIMEOUT;
		}
	}
	/*
	for(tc=0; tc<timeout; tc++) {
                if(pdev->read(&card_resp, 1, pdev->priv_data) < 0) {
                        DPRINTK("error: mmc_wait_response read error\n");
                        return 0xFF;
                }
                if(card_resp != 0xFF) {
                        //DPRINTK("CMD0: Got response from MMC as: 0x%x after %d bytes read\n", card_resp, tc);
                        return card_resp;
                }
        }
        DPRINTK("error: mmc_wait_response timeout\n");
        return 0xFF;
	*/
}


#ifdef DEBUG_REGS
short mmc_spi_mmc_spi_get_card_old(struct mmc_spi_dev *pdev)
{
	int i;
	
	struct mmc_card *card = pdev->private_data->card;
	
	unsigned char raw_csd[18]; // 16 byte + 2 byte CRC
	unsigned char raw_cid[18]; // 16 byte + 2 byte CRC
	unsigned short c_size_mult=0;
	unsigned short c_size=0;
	unsigned short read_bl_len=0;
	unsigned int cap = 0;
	
	/*
	unsigned int value=0;
	unsigned int n=0;
	unsigned int cumm_step=127;
	unsigned short csd_step[] = {2,4,2,8,8,8,12,4,1,1,1,1,2,12,3,3,3,3,3,5,5,5,1,2,3,4,1,5,1,1,1,1,2,2,7,1};
	unsigned short cid_step[] = {8,16,8,8,8,8,8,8,8,32,8,7,1};
	BOOL bit=0;
	unsigned char tmp=0;
	*/
	*/	
	memset(raw_cid, 0, 18);
	memset(raw_csd, 0, 18);
	//memset(card.raw_csd, 0, sizeof(card.raw_csd));
	if(read_mmc_reg(pdev, raw_cid, 0)) {
		DPRINTK("CSD register read failed.\n");
		return 1;
	};
	if(read_mmc_reg(pdev, raw_csd, 1)) {
		DPRINTK("CID register read failed.\n");
		return 1;
	}
	/*
	for(i=0;i<128;i++) {
		printk("%d:  %d\n", i, getbit(raw_cid, i));
	}
	printk("\n");
	for(i=0;i<128;i++) {
		printk("%d:  %d\n", i, getbit(raw_csd, i));
	}
	
	for(i=0;i<16;i++) {
		printk("%02x ", raw_cid[i]);
	}
	printk("\n");
	
	for(i=0;i<16;i++) {
		printk("%02x ", raw_csd[i]);
	}
	printk("\n\n CID_REGISTER\n");
	
	while(n<13) {
		value = getvalue(raw_cid, 127-cumm_step, cid_step[n]);
		printk("%d\t%x\t%u\n",cid_step[n], value, value);
		cumm_step=cumm_step-cid_step[n];
		n++;
	}
	n=0;
	cumm_step=127;
	printk("\n\n CSD_REGISTER\n");
	while(n<36) {
		value = getvalue(raw_csd, 127-cumm_step, csd_step[n]);
		printk("%d\t%x\t%u\n",csd_step[n], value, value);
		cumm_step=cumm_step-csd_step[n];
		n++;
	}
	*/
	
	// ********* NO DEBUG CODE FROM HERE ********************* 
	card->csd.mmca_vsn = (raw_csd[0] & 0x3c) >> 2;
	card->csd.cmdclass = (((u16)raw_csd[4]) << 4) | ((raw_csd[5] & 0xf0) >> 4);
	card->csd.tacc_clks = raw_csd[1];
	card->csd.tacc_ns = raw_csd[2];
	card->csd.max_dtr = raw_csd[3];
	card->csd.read_blkbits = raw_csd[5] & 0x0f;
	
	// for calculating capacity(in blocks)
	c_size = ((((u16)raw_csd[6]) & 0x03) << 10) | (((u16)raw_csd[7]) << 2) | (((u16)raw_csd[8]) & 0xc0) >> 6;
	c_size_mult = ((raw_csd[9] & 0x03) << 1) | ((raw_csd[10] & 0x80) >> 7);
	read_bl_len = raw_csd[5] & 0x0f;	
	card->csd.capacity = (c_size+1) * (1 << (c_size_mult + 2));
	
	// for printing capacity in bytes
	cap = (c_size+1) * (1 << (c_size_mult + 2)) * (1 << read_bl_len);
	
	card->cid.manfid = getvalue(raw_cid, 127-127, 8);
	memcpy(card.cid.prod_name, raw_cid+3, 7);
	card->cid.serial = getvalue(raw_cid, 127-47, 32);
	card->cid.oemid = getvalue(raw_cid, 127-119, 16);
	card->cid.year = 1997 + (getvalue(raw_cid, 127-15, 8) & 0x0F);
	card->cid.hwrev = (getvalue(raw_cid, 127-55, 8) & 0xF0) >> 4;
	card->cid.fwrev = getvalue(raw_cid, 127-55, 8) & 0x0F;
	card->cid.month = (getvalue(raw_cid, 127-15, 8) & 0xF0) >> 4;
	
	printk("MMC found:\n\t Capacity: %dM\n\t Name: %s \n\t Rev: %d.%d \n\t Date: %d/%d \n\t Serial: 0x%x (%u)\n", cap/(1024*1024), card.cid.prod_name, card.cid.hwrev, card.cid.fwrev, card.cid.year, card.cid.month, card.cid.serial, card.cid.serial);
	return 0;	
}
#endif
