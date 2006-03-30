/****************************************************************
 * $ID: i2c-bfin-twi.c      12 Aug 2005 13:29:10 -0800        $ *
 *                                                              *
 * Description:                                                 *
 *                                                              *
 * Maintainer:  sonicz  <sonic.zhang@analog.com>                *
 *                                                              *
 * CopyRight (c)  2005  Analog Device                           *
 * All rights reserved.                                         *
 *                                                              *
 * This file is free software;                                  *
 *   you are free to modify and/or redistribute it   	        *
 *   under the terms of the GNU General Public Licence (GPL).   *
 *                                                              *
 ****************************************************************/

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/interrupt.h>

#include <asm/blackfin.h>
#include <asm/irq.h>

#define I2C_BFIN_TWI 0x00
#define POLL_TIMEOUT		(2*HZ)
#ifndef CONFIG_TWICLK_KHZ
#define CONFIG_TWICLK_KHZ	400
#endif

/* SMBus mode*/
#define TWI_I2C_MODE_STANDARD		0x01
#define TWI_I2C_MODE_STANDARDSUB	0x02
#define TWI_I2C_MODE_COMBINED		0x04

struct bfin_twi_iface
{
	struct semaphore 	twi_lock;
	int			irq;
	spinlock_t		lock;
	char			read_write;
	u8			command;
	u8			*transPtr;
	int			readNum;
	int			writeNum;
	int			cur_mode;
	int			manual_stop;
	int			result;
	int			timeout_count;
	struct timer_list	timeout_timer;
	struct i2c_adapter	adap;
	struct completion	complete;
};

static struct bfin_twi_iface twi_iface;

static void bfin_twi_handle_interrupt(struct bfin_twi_iface *iface)
{
	unsigned short twi_int_stat = *pTWI_INT_STAT;
	unsigned short mast_stat = *pTWI_MASTER_STAT;

	if ( XMTSERV & twi_int_stat ){
		/* Transmit next data */
		if(iface->writeNum>0) {
			*pTWI_XMT_DATA8 = *(iface->transPtr++);
			iface->writeNum--;
		}
		/* start receive immediately after complete sending in combine mode. */
		else if(iface->cur_mode == TWI_I2C_MODE_COMBINED) {
			*pTWI_MASTER_CTL |= MDIR | RSTART;
		}
		else if(iface->manual_stop)
			*pTWI_MASTER_CTL |= STOP;
		__builtin_bfin_ssync();
		/* Clear status */
		*pTWI_INT_STAT = XMTSERV;
		__builtin_bfin_ssync();
	}
	if ( RCVSERV & twi_int_stat ){
		if(iface->readNum>0) {
			/* Receive next data */
			*iface->transPtr = *pTWI_RCV_DATA8;
			if(iface->cur_mode == TWI_I2C_MODE_COMBINED) {
				/* Change combine mode into sub mode after read first data. */
				iface->cur_mode = TWI_I2C_MODE_STANDARDSUB;
				/* Get read number from first byte in block combine mode. */
				if(iface->readNum == 1 && iface->manual_stop)
					iface->readNum = *iface->transPtr+1;
			}
			iface->transPtr++;
			iface->readNum--;
		}
		else if(iface->manual_stop) {
			*pTWI_MASTER_CTL |= STOP;
			__builtin_bfin_ssync();
		}
		/* Clear interrupt source */
		*pTWI_INT_STAT = RCVSERV;
		__builtin_bfin_ssync();
	}
	if( MERR & twi_int_stat ) {
		*pTWI_INT_STAT = MERR;
		*pTWI_INT_MASK = 0;
		*pTWI_MASTER_STAT = 0x3e;
		*pTWI_MASTER_CTL = 0;
		__builtin_bfin_ssync();
		iface->result = -1;
		/* if both err and complete int stats are set, return proper results. */
		if ( MCOMP & twi_int_stat ){
			*pTWI_INT_STAT = MCOMP;
			*pTWI_INT_MASK = 0;
			*pTWI_MASTER_CTL = 0;
			__builtin_bfin_ssync();
			/* If it is a quick transfer, only address bug no data, not an err, return 1. */
			if(iface->writeNum==0 && mast_stat&BUFRDERR)
				iface->result = 1;
			/* If address not acknowledged return -1, else return 0. */
			else if(!(mast_stat&ANAK))
				iface->result = 0;
		}
		complete(&iface->complete);
		return;
	}
	if ( MCOMP & twi_int_stat ){
		*pTWI_INT_STAT = MCOMP;
		__builtin_bfin_ssync();
		if(iface->cur_mode == TWI_I2C_MODE_COMBINED) {
			if(iface->readNum == 0) {
				/* set the read number to 1 and ask for manual stop in block combine mode */
				iface->readNum = 1;
				iface->manual_stop = 1;
				*pTWI_MASTER_CTL |= (0xff << 6);
			}
			else {
				/* set the readd number in other combine mode. */
				*pTWI_MASTER_CTL = (*pTWI_MASTER_CTL&(~(0xff << 6)))|( iface->readNum << 6 );
			}
			/* remove restart bit and enable master receive */
			*pTWI_MASTER_CTL &= ~RSTART;
			*pTWI_MASTER_CTL |= MEN | MDIR;
			__builtin_bfin_ssync();
		}
		else {
			iface->result = 1;
			*pTWI_INT_MASK = 0;
			*pTWI_MASTER_CTL = 0;
			__builtin_bfin_ssync();
			complete(&iface->complete);
		}
	}
}


/* Interrupt handler */
static irqreturn_t bfin_twi_interrupt_entry(int irq, void *dev_id, struct pt_regs *regs)
{
	struct bfin_twi_iface *iface = (struct bfin_twi_iface *)dev_id;
	unsigned long flags;

	spin_lock_irqsave(&iface->lock, flags);
	del_timer(&iface->timeout_timer);
	bfin_twi_handle_interrupt(iface);
	spin_unlock_irqrestore(&iface->lock, flags);
	return IRQ_HANDLED;
}

static void bfin_twi_timeout(unsigned long data)
{
	struct bfin_twi_iface *iface = (struct bfin_twi_iface *)data;
	unsigned long flags;

	spin_lock_irqsave(&iface->lock, flags);
	bfin_twi_handle_interrupt(iface);
	if (iface->result == 0) {
		iface->timeout_count--;
		if(iface->timeout_count>0) {
			iface->timeout_timer.expires = jiffies + POLL_TIMEOUT;
			add_timer(&iface->timeout_timer);
		}
		else {
			iface->result = -1;
			complete(&iface->complete);
		}
	}
	spin_unlock_irqrestore(&iface->lock, flags);
}


/*
 * Generic i2c master transfer entrypoint
 */
static int bfin_twi_master_xfer(struct i2c_adapter *adap, struct i2c_msg msgs[], int num)
{
	struct bfin_twi_iface* iface = (struct bfin_twi_iface*)adap->algo_data;
	struct i2c_msg *pmsg;
	int i, ret;
	int rc = 0;

	if ( !(*pTWI_CONTROL & TWI_ENA) )
		return -ENXIO;

	down(&iface->twi_lock);

	while(*pTWI_MASTER_STAT&BUSBUSY) {
		up(&iface->twi_lock);
		schedule();
		down(&iface->twi_lock);
	}

	ret = 0;
	for (i = 0; rc >= 0 && i < num;) {
		pmsg = &msgs[i++];
		if (pmsg->flags & I2C_M_TEN) {
			printk(KERN_ERR "i2c-bfin-twi: 10 bits addr not supported !\n");
			rc = -EINVAL;
			break;
		}

		iface->cur_mode |= TWI_I2C_MODE_STANDARD;
		iface->transPtr = pmsg->buf;
		iface->writeNum = pmsg->len;
		iface->result = 0;
		iface->timeout_count = 10;
		/* Set Transmit device address */
		*pTWI_MASTER_ADDR = pmsg->addr;

		if (pmsg->flags & I2C_M_RD)
			iface->read_write = I2C_SMBUS_READ;
		else {
			iface->read_write = I2C_SMBUS_WRITE;
			/* Transmit first data */
			if(iface->writeNum>0) {
				*pTWI_XMT_DATA8 = *(iface->transPtr++);
				iface->writeNum--;
				__builtin_bfin_ssync();
			}
		}
	
		/* FIFO Initiation */
		*pTWI_FIFO_CTL = 0;

		/* clear int stat */
		*pTWI_INT_STAT = MERR|MCOMP|XMTSERV|RCVSERV;

		/* Interrupt mask . Enable XMT, RCV interrupt */
		*pTWI_INT_MASK = MCOMP | MERR | ((iface->read_write == I2C_SMBUS_READ)? RCVSERV : XMTSERV);
		__builtin_bfin_ssync();

		iface->timeout_timer.expires = jiffies + POLL_TIMEOUT;
		add_timer(&iface->timeout_timer);

		if(pmsg->len<=256)
			*pTWI_MASTER_CTL = ( pmsg->len << 6 );
		else
			*pTWI_MASTER_CTL = ( 0xff << 6 );
		/* Master enable */
		*pTWI_MASTER_CTL |= MEN | ((iface->read_write == I2C_SMBUS_READ) ? MDIR : 0)
			 | ((CONFIG_TWICLK_KHZ>100) ? FAST : 0);
		__builtin_bfin_ssync();

		wait_for_completion(&iface->complete);	

		rc = iface->result;
		if (rc == 1)
			ret++;
		else if(rc == -1)
			break;
	}

	/* Release sem */
	up(&iface->twi_lock);

	return ret;
}

/*
 * SMBus type transfer entrypoint
 */

int bfin_twi_smbus_xfer(struct i2c_adapter *adap, u16 addr, 
			unsigned short flags, char read_write,
			u8 command, int size, union i2c_smbus_data * data)
{
	struct bfin_twi_iface* iface = (struct bfin_twi_iface*)adap->algo_data;
	int rc = 0;

	if ( !(*pTWI_CONTROL & TWI_ENA) )
		return -ENXIO;

	down(&iface->twi_lock);

	while(*pTWI_MASTER_STAT&BUSBUSY) {
		up(&iface->twi_lock);
		schedule();
		down(&iface->twi_lock);
	}

	iface->writeNum = 0;
	iface->readNum = 0;

	/* Prepare datas & select mode */
	switch (size) {
	case I2C_SMBUS_QUICK:
		iface->transPtr = NULL;
		iface->cur_mode = TWI_I2C_MODE_STANDARD;
		break;
	case I2C_SMBUS_BYTE:
		if (read_write == I2C_SMBUS_READ)
			iface->readNum = 1;
		else
			iface->writeNum = 1;
		iface->transPtr = &data->byte;
		iface->cur_mode = TWI_I2C_MODE_STANDARD;
		break;
	case I2C_SMBUS_BYTE_DATA:
		if (read_write == I2C_SMBUS_READ) {
			iface->readNum = 1;
			iface->cur_mode = TWI_I2C_MODE_COMBINED;
		}
		else {
			iface->writeNum = 1;
			iface->cur_mode = TWI_I2C_MODE_STANDARDSUB;
		}
		iface->transPtr = &data->byte;
		break;
	case I2C_SMBUS_WORD_DATA:
		if (read_write == I2C_SMBUS_READ) {
			iface->readNum = 2;
			iface->cur_mode = TWI_I2C_MODE_COMBINED;
		}
		else {
			iface->writeNum = 2;
			iface->cur_mode = TWI_I2C_MODE_STANDARDSUB;
		}
		iface->transPtr = (u8 *)&data->word;
		break;
	case I2C_SMBUS_PROC_CALL:
		iface->writeNum = 2;
		iface->readNum = 2;
		iface->cur_mode = TWI_I2C_MODE_COMBINED;
		iface->transPtr = (u8 *)&data->word;
		break;
	case I2C_SMBUS_BLOCK_DATA:
		if (read_write == I2C_SMBUS_READ) {
			iface->readNum = 0;
			iface->cur_mode = TWI_I2C_MODE_COMBINED;
		}
		else {
			iface->writeNum = data->block[0]+1;
			iface->cur_mode = TWI_I2C_MODE_STANDARDSUB;
		}
		iface->transPtr = data->block;
		break;
	default:
		return -1;
	}

	iface->result = 0;
	iface->manual_stop = 0;
	iface->read_write = read_write;
	iface->command = command;
	iface->timeout_count = 10;

	/* FIFO Initiation */
	*pTWI_FIFO_CTL = 0;

	/* clear int stat */
	*pTWI_INT_STAT = MERR|MCOMP|XMTSERV|RCVSERV;

	/* Set Transmit device address */
	*pTWI_MASTER_ADDR = addr;
	__builtin_bfin_ssync();

	iface->timeout_timer.expires = jiffies + POLL_TIMEOUT;
	add_timer(&iface->timeout_timer);

	switch(iface->cur_mode) {
	case TWI_I2C_MODE_STANDARDSUB:
		*pTWI_XMT_DATA8 = iface->command;
		*pTWI_INT_MASK = MCOMP | MERR | ((iface->read_write == I2C_SMBUS_READ)? RCVSERV : XMTSERV);
		__builtin_bfin_ssync();

		if(iface->writeNum+1<=255)
			*pTWI_MASTER_CTL = ((iface->writeNum+1) << 6);
		else {
			*pTWI_MASTER_CTL = ( 0xff << 6 );
			iface->manual_stop = 1;
		}
		/* Master enable */
		*pTWI_MASTER_CTL |= MEN | ((CONFIG_TWICLK_KHZ>100) ? FAST : 0);
		break;
	case TWI_I2C_MODE_COMBINED:
		*pTWI_XMT_DATA8 = iface->command;
		*pTWI_INT_MASK = MCOMP | MERR | RCVSERV | XMTSERV;
		__builtin_bfin_ssync();

		if(iface->writeNum > 0)
			*pTWI_MASTER_CTL = ((iface->writeNum+1) << 6);
		else
			*pTWI_MASTER_CTL = ( 0x1 << 6 );
		/* Master enable */
		*pTWI_MASTER_CTL |= MEN | ((CONFIG_TWICLK_KHZ>100) ? FAST : 0);
		break;
	default:
		*pTWI_MASTER_CTL = 0;
		if(iface->writeNum>0) {
			*pTWI_XMT_DATA8 = *(iface->transPtr++);
			if(iface->writeNum<=255)
				*pTWI_MASTER_CTL = ( iface->writeNum << 6 );
			else {
				*pTWI_MASTER_CTL = ( 0xff << 6 );
				iface->manual_stop = 1;
			}
			iface->writeNum--;
		}

		if(iface->readNum>0 && iface->readNum<=255)
			*pTWI_MASTER_CTL = ( iface->readNum << 6 );
		else {
			*pTWI_MASTER_CTL = ( 0xff << 6 );
			iface->manual_stop = 1;
		}

		*pTWI_INT_MASK = MCOMP | MERR | ((iface->read_write == I2C_SMBUS_READ)? RCVSERV : XMTSERV);
		__builtin_bfin_ssync();

		/* Master enable */
		*pTWI_MASTER_CTL |= MEN | ((iface->read_write == I2C_SMBUS_READ) ? MDIR : 0) 
			| ((CONFIG_TWICLK_KHZ>100) ? FAST : 0);
		break;
	}
	__builtin_bfin_ssync();

	wait_for_completion(&iface->complete);

	rc = (iface->result >= 0) ? 0 : -1;

	/* Release sem */
	up(&iface->twi_lock);

	return rc;
}


/*
 * Return what the adapter supports
 */
static u32 bfin_twi_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_SMBUS_QUICK | I2C_FUNC_SMBUS_BYTE |
	       I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA |
	       I2C_FUNC_SMBUS_BLOCK_DATA | I2C_FUNC_SMBUS_PROC_CALL|
	       I2C_FUNC_I2C;
}


static struct i2c_algorithm bfin_twi_algorithm = {
	.master_xfer	= bfin_twi_master_xfer,
	.smbus_xfer     = bfin_twi_smbus_xfer,
	.functionality  = bfin_twi_functionality,
};

static int __init i2c_bfin_twi_init(void)
{
	struct i2c_adapter *p_adap;
	int rc;

	init_MUTEX(&(twi_iface.twi_lock));
	spin_lock_init(&twi_iface.lock);
	init_completion(&twi_iface.complete);
	twi_iface.irq = IRQ_TWI;

	init_timer(&twi_iface.timeout_timer);
	twi_iface.timeout_timer.function = bfin_twi_timeout;
	twi_iface.timeout_timer.data = (unsigned long)&twi_iface;

	p_adap = &twi_iface.adap;
	p_adap->id = I2C_BFIN_TWI;
	p_adap->algo = &bfin_twi_algorithm;
	p_adap->algo_data = &twi_iface;
	p_adap->client_register = NULL;
	p_adap->client_unregister = NULL;

	rc = request_irq(twi_iface.irq, bfin_twi_interrupt_entry, SA_INTERRUPT, "bfin twi i2c", &twi_iface);
	if (rc) {
		printk(KERN_ERR "i2c-bfin-twi: can't get IRQ %d !\n", twi_iface.irq);
		return -ENODEV;
	}

	/* Set TWI internal clock as 10MHz */
	*pTWI_CONTROL = ((get_sclk() / 1024 / 1024 + 5) / 10) & 0x7F;

	/* Set Twi interface clock as specified */
	if(CONFIG_TWICLK_KHZ>400)
		*pTWI_CLKDIV = (( 5*1024 / 400 ) << 8) | (( 5*1024 / 400 ) & 0xFF);
	else
		*pTWI_CLKDIV = (( 5*1024 / CONFIG_TWICLK_KHZ ) << 8) | (( 5*1024 / CONFIG_TWICLK_KHZ ) & 0xFF);

	/* Enable TWI */
	*pTWI_CONTROL |= TWI_ENA;
	__builtin_bfin_ssync();


	return i2c_add_adapter(p_adap);
}

static void __exit i2c_bfin_twi_exit(void)
{
	i2c_del_adapter(&twi_iface.adap);
}

MODULE_AUTHOR("Sonic Zhang <sonic.zhang@analog.com>");
MODULE_DESCRIPTION("I2C-Bus adapter routines for Blackfin TWI");
MODULE_LICENSE("GPL");

module_init(i2c_bfin_twi_init);
module_exit(i2c_bfin_twi_exit);

