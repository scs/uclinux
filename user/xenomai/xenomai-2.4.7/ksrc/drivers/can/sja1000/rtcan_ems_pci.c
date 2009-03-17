/*
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Register definitions and descriptions are taken from LinCAN 0.3.3.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <asm/io.h>

#include <rtdm/rtdm_driver.h>

/* CAN device profile */
#include <rtdm/rtcan.h>
#include <rtcan_dev.h>
#include <rtcan_raw.h>
#include <rtcan_internal.h>
#include <rtcan_sja1000.h>
#include <rtcan_sja1000_regs.h>

#define RTCAN_DEV_NAME    "rtcan%d"
#define RTCAN_DRV_NAME    "EMS-CPC-PCI-CAN"

static char *ems_pci_board_name = "EMS-CPC-PCI";

MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");
MODULE_DESCRIPTION("RTCAN board driver for EMS CPC-PCI cards");
MODULE_SUPPORTED_DEVICE("EMS CPC-PCI card CAN controller");
MODULE_LICENSE("GPL");

struct rtcan_ems_pci
{
	struct pci_dev *pci_dev;
	struct rtcan_device *slave_dev;
	int channel;
	volatile void __iomem *base_addr;
	volatile void __iomem *conf_addr;
};

#define EMS_PCI_MASTER 1 /* multi channel device, this device is master */
#define EMS_PCI_SLAVE  2 /* multi channel device, this is slave */

/*
 * PSB4610 PITA-2 bridge control registers
 */
#define PITA2_ICR           0x00	/* Interrupt Control Register */
#define PITA2_ICR_INT0      0x00000002	/* [RC] INT0 Active/Clear */
#define PITA2_ICR_INT0_EN   0x00020000	/* [RW] Enable INT0 */

#define PITA2_MISC          0x1c	/* Miscellaneous Register */
#define PITA2_MISC_CONFIG   0x04000000	/* Multiplexed Parallel_interface_model */

/*
 * The board configuration is probably following:
 * RX1 is connected to ground.
 * TX1 is not connected.
 * CLKO is not connected.
 * Setting the OCR register to 0xDA is a good idea.
 * This means  normal output mode , push-pull and the correct polarity.
 */
#define EMS_PCI_OCR_STD     0xda	/* Standard value: Pushpull */

/*
 * In the CDR register, you should set CBP to 1.
 * You will probably also want to set the clock divider value to 7
 * (meaning direct oscillator output) because the second SJA1000 chip
 * is driven by the first one CLKOUT output.
 */
#define EMS_PCI_CDR_MASTER  (SJA_CDR_CAN_MODE | SJA_CDR_CBP | 0x07)
#define EMS_PCI_CDR_SLAVE   (SJA_CDR_CAN_MODE | SJA_CDR_CBP | 0x07 |	\
			     SJA_CDR_CLK_OFF)
#define EMS_PCI_CONF_SIZE   0x0100  /* Size of the config io-memory */
#define EMS_PCI_PORT_START  0x0400  /* Start of the channel io-memory */
#define EMS_PCI_PORT_SIZE   0x0200  /* Size of a channel io-memory */


#define EMS_PCI_PORT_BYTES  0x4     /* Each register occupies 4 bytes */

#define EMS_PCI_VENDOR_ID   0x110a  /* PCI device and vendor ID */
#define EMS_PCI_DEVICE_ID   0x2104

static struct pci_device_id ems_pci_tbl[] = {
	{EMS_PCI_VENDOR_ID, EMS_PCI_DEVICE_ID,
	 PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ }
};
MODULE_DEVICE_TABLE (pci, ems_pci_tbl);

#define EMS_PCI_CAN_SYS_CLOCK (16000000 / 2)

static u8 rtcan_ems_pci_read_reg(struct rtcan_device *dev, int port)
{
	struct rtcan_ems_pci *board = (struct rtcan_ems_pci *)dev->board_priv;
	return readb(board->base_addr + (port * EMS_PCI_PORT_BYTES));
}

static void rtcan_ems_pci_write_reg(struct rtcan_device *dev, int port, u8 data)
{
	struct rtcan_ems_pci *board = (struct rtcan_ems_pci *)dev->board_priv;
	writeb(data, board->base_addr + (port * EMS_PCI_PORT_BYTES));
}

static void rtcan_ems_pci_irq_ack(struct rtcan_device *dev)
{
	struct rtcan_ems_pci *board = (struct rtcan_ems_pci *)dev->board_priv;

	writel(PITA2_ICR_INT0_EN | PITA2_ICR_INT0,
	       board->conf_addr + PITA2_ICR);
}

static void rtcan_ems_pci_del_chan(struct rtcan_device *dev,
				   int init_step)
{
	struct rtcan_ems_pci *board;

	if (!dev)
		return;

	board = (struct rtcan_ems_pci *)dev->board_priv;

	switch (init_step) {
	case 0:			/* Full cleanup */
		RTCAN_DBG("Removing %s %s device %s\n",
			  ems_pci_board_name, dev->ctrl_name, dev->name);
		rtcan_sja1000_unregister(dev);
	case 5:
	case 4:
		iounmap((void *)board->base_addr);
	case 3:
		if (board->channel != EMS_PCI_SLAVE)
			iounmap((void *)board->conf_addr);
	case 2:
		rtcan_dev_free(dev);
	case 1:
		break;
	}
}

static int rtcan_ems_pci_add_chan(struct pci_dev *pdev, int channel,
				  struct rtcan_device **master_dev)
{
	struct rtcan_device *dev;
	struct rtcan_sja1000 *chip;
	struct rtcan_ems_pci *board;
	unsigned long addr;
	int err, init_step = 1;

	dev = rtcan_dev_alloc(sizeof(struct rtcan_sja1000),
			      sizeof(struct rtcan_ems_pci));
	if (dev == NULL)
		return -ENOMEM;
	init_step = 2;

	chip = (struct rtcan_sja1000 *)dev->priv;
	board = (struct rtcan_ems_pci *)dev->board_priv;

	board->pci_dev = pdev;
	board->channel = channel;

	if (channel != EMS_PCI_SLAVE) {

		addr = pci_resource_start(pdev, 0);
		board->conf_addr = ioremap(addr, EMS_PCI_CONF_SIZE);
		if (board->conf_addr == 0) {
			err = -ENODEV;
			goto failure;
		}
		init_step = 3;

		/* Configure PITA-2 parallel interface */
		writel(PITA2_MISC_CONFIG, board->conf_addr + PITA2_MISC);
		/* Enable interrupts from card */
		writel(PITA2_ICR_INT0_EN, board->conf_addr + PITA2_ICR);
	} else {
		struct rtcan_ems_pci *master_board =
			(struct rtcan_ems_pci *)(*master_dev)->board_priv;
		master_board->slave_dev = dev;
		board->conf_addr = master_board->conf_addr;
	}

	addr = pci_resource_start(pdev, 1) + EMS_PCI_PORT_START;
	if (channel == EMS_PCI_SLAVE)
		addr += EMS_PCI_PORT_SIZE;

	board->base_addr = ioremap(addr, EMS_PCI_PORT_SIZE);
	if (board->base_addr == 0) {
		err = -ENODEV;
		goto failure;
	}
	init_step = 4;

	dev->board_name = ems_pci_board_name;

	chip->read_reg = rtcan_ems_pci_read_reg;
	chip->write_reg = rtcan_ems_pci_write_reg;
	chip->irq_ack = rtcan_ems_pci_irq_ack;

	/* Clock frequency in Hz */
	dev->can_sys_clock = EMS_PCI_CAN_SYS_CLOCK;

	/* Output control register */
	chip->ocr = EMS_PCI_OCR_STD;

	/* Clock divider register */
	if (channel == EMS_PCI_MASTER)
		chip->cdr = EMS_PCI_CDR_MASTER;
	else
		chip->cdr = EMS_PCI_CDR_SLAVE;

	strncpy(dev->name, RTCAN_DEV_NAME, IFNAMSIZ);

	/* Register and setup interrupt handling */
	chip->irq_flags = RTDM_IRQTYPE_SHARED;
	chip->irq_num = pdev->irq;
	init_step = 5;

	printk("%s: base_addr=%p conf_addr=%p irq=%d\n", RTCAN_DRV_NAME,
	       board->base_addr, board->conf_addr, chip->irq_num);

	/* Register SJA1000 device */
	err = rtcan_sja1000_register(dev);
	if (err) {
		printk(KERN_ERR
		       "ERROR %d while trying to register SJA1000 device!\n",
		       err);
		goto failure;
	}

	if (channel != EMS_PCI_SLAVE)
		*master_dev = dev;

	return 0;

failure:
	rtcan_ems_pci_del_chan(dev, init_step);
	return err;
}

static int __devinit ems_pci_init_one (struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	struct rtcan_device *master_dev = NULL;
	int err;

	RTCAN_DBG("%s: initializing device %04x:%04x\n",
		  RTCAN_DRV_NAME,  pdev->vendor, pdev->device);

	if ((err = pci_enable_device (pdev)))
		goto failure;

	if ((err = pci_request_regions(pdev, RTCAN_DRV_NAME)))
		goto failure;

	if ((err = pci_write_config_word(pdev, 0x04, 2)))
		goto failure_cleanup;

	if ((err = rtcan_ems_pci_add_chan(pdev, EMS_PCI_MASTER,
					  &master_dev)))
		goto failure_cleanup;
	if ((err = rtcan_ems_pci_add_chan(pdev, EMS_PCI_SLAVE,
					  &master_dev)))
		goto failure_cleanup;

	pci_set_drvdata(pdev, master_dev);
	return 0;

failure_cleanup:
	if (master_dev)
		rtcan_ems_pci_del_chan(master_dev, 0);

	pci_release_regions(pdev);

failure:
	return err;

}

static void __devexit ems_pci_remove_one (struct pci_dev *pdev)
{
	struct rtcan_device *dev = pci_get_drvdata(pdev);
	struct rtcan_ems_pci *board = (struct rtcan_ems_pci *)dev->board_priv;

	/* Disable interrupts from card */
	writel(0x0, board->conf_addr + PITA2_ICR);

	if (board->slave_dev)
		rtcan_ems_pci_del_chan(board->slave_dev, 0);
	rtcan_ems_pci_del_chan(dev, 0);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver rtcan_ems_pci_driver = {
	.name		= RTCAN_DRV_NAME,
	.id_table	= ems_pci_tbl,
	.probe		= ems_pci_init_one,
	.remove		= __devexit_p(ems_pci_remove_one),
};

static int __init rtcan_ems_pci_init(void)
{
	return pci_register_driver(&rtcan_ems_pci_driver);
}

static void __exit rtcan_ems_pci_exit(void)
{
	pci_unregister_driver(&rtcan_ems_pci_driver);
}

module_init(rtcan_ems_pci_init);
module_exit(rtcan_ems_pci_exit);
