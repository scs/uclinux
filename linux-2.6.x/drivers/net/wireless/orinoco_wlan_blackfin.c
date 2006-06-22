/* orinoco_wlan_blackfin.c
 *
 * Driver for Prism II devices which would usually be driven by orinoco_cs,
 * but are connected to the Asynchronous Memory Bus.
 * This driver is based on orinoco_plx.c
 *
 * Modified by OKAZAKI Atsuya <okazaki@zd.wakwak.com>
 * Modified by Michael Hennerich <hennerich@blackfin.uclinux.org>
 *
 * orinoco_plx.c
 * Copyright (C) 2001 Daniel Barlow <dan@telent.net>
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License
 * at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License.
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License version 2 (the "GPL"), in
 * which case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use your
 * version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the MPL or the GPL.
 */

#include <linux/config.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/ioport.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/list.h>
#include <linux/wireless.h>
#include <linux/fcntl.h>
#include <linux/delay.h>

#include <pcmcia/cisreg.h>

#include "hermes.h"
#include "orinoco.h"

static char dev_info[] = "orinoco_wlan_blackfin";

#define WLAN_BLACKFIN_ATTR_ADDR		CONFIG_BFIN_CF_ATTR_ADDR
#define WLAN_BLACKFIN_IO_ADDR		CONFIG_BFIN_CF_IO_ADDR

#define BFIN_WLAN_IRQ_PFX   		(IRQ_PF0 + CONFIG_BFIN_CF_IRQ_PFX)

#if defined(CONFIG_IRQCHIP_DEMUX_GPIO)
#define WLAN_BLACKFIN_IRQ	BFIN_WLAN_IRQ_PFX		
#else
#define WLAN_BLACKFIN_IRQ	CONFIG_BFIN_CF_IRQ
#endif

#define WLAN_BLACKFIN_IRQ_VECTOR       (WLAN_BLACKFIN_IRQ)

#define COR_OFFSET    (0x3e0)	/* COR attribute offset of Prism2 PC card */
#define COR_VALUE     (COR_LEVEL_REQ | COR_FUNC_ENA) /* Enable PC card with interrupt in level trigger */


static const u8 cis_magic[] = {
	0x01, 0x03, 0x00, 0x00, 0xff, 0x17, 0x04, 0x67
};

static struct net_device *sdev;

static int orinoco_wlan_blackfin_init_one(void)
{
	int err = 0;
 	u8 *attr_mem = NULL;
	u8 reg;
	struct orinoco_private *priv = NULL;
	unsigned long pccard_ioaddr = 0;
	unsigned long pccard_iolen = 0;
	struct net_device *dev = NULL;
	int netdev_registered = 0;
	int i;

	/* Resource 2 is mapped to the PCMCIA space */
 	attr_mem = ioremap(WLAN_BLACKFIN_ATTR_ADDR, PAGE_SIZE);
	if (! attr_mem)
		goto fail;

	printk(KERN_DEBUG "orinoco_wlan_blackfin: CIS: ");
	for (i = 0; i < 16; i+=2) {
		printk("%02X:", (attr_mem[i]));
		/* Verify whether PC card is present */

		if (attr_mem[i] != cis_magic[i>>1]) {
			printk("\n" KERN_ERR "orinoco_wlan_blackfin: The CIS value of Prism2 PC card is invalid.\n");
			err = -EIO;
			goto fail;
		}
	}
	printk("\n");

	/* PCMCIA COR is the first byte following CIS: this write should
	 * enable I/O mode and select level-triggered interrupts */
	attr_mem[COR_OFFSET] = COR_VALUE;
	mdelay(1);
	reg = attr_mem[COR_OFFSET];
	if (reg != COR_VALUE) {
		printk(KERN_ERR "orinoco_wlan_blackfin: Error setting COR value (reg=%x)\n", reg);
		goto fail;
	}

	iounmap(attr_mem);
	attr_mem = NULL; /* done with this now, it seems */

	/* and 3 to the PCMCIA slot I/O address space */
	pccard_ioaddr = WLAN_BLACKFIN_IO_ADDR;
	pccard_iolen = 64;
	if (! request_region(pccard_ioaddr, pccard_iolen, dev_info)) {
		printk(KERN_ERR "orinoco_wlan_blackfin: I/O resource 0x%lx @ 0x%lx busy\n",
		       pccard_iolen, pccard_ioaddr);
		pccard_ioaddr = 0;
		err = -EBUSY;
		goto fail;
	}

	dev = alloc_orinocodev(0, NULL);
	if (! dev) {
		err = -ENOMEM;
		goto fail;
	}

	priv = dev->priv;
	dev->base_addr = pccard_ioaddr;
	SET_MODULE_OWNER(dev);
	dev->irq = WLAN_BLACKFIN_IRQ_VECTOR;

	printk(KERN_DEBUG
	       "Detected Orinoco/Prism2 WLAN BLACKFIN device at irq:%d, io addr:0x%lx\n",
	       dev->irq, pccard_ioaddr);

	hermes_struct_init(&(priv->hw), (void __iomem *)dev->base_addr, HERMES_16BIT_REGSPACING);

	bfin_gpio_interrupt_setup(dev->irq, BFIN_WLAN_IRQ_PFX, IRQT_LOW);

 	err = request_irq(dev->irq, orinoco_interrupt, SA_SHIRQ, dev_info, dev);

	if (err) {
		printk(KERN_ERR "orinoco_wlan_blackfin: Error allocating IRQ %d.\n", dev->irq);
		err = -EBUSY;
		goto fail;
	}

	err = register_netdev(dev);
	if (err)
		goto fail;
	netdev_registered = 1;

	sdev = dev;

	return 0;		/* succeeded */

 fail:
	printk(KERN_DEBUG "orinoco_wlan_blackfin: init_one(), FAIL!\n");

	if (priv) {
		if (netdev_registered)
			unregister_netdev(dev);

		if (dev->irq)
			free_irq(dev->irq, priv);

		kfree(priv);
	}

	if (pccard_ioaddr)
		release_region(pccard_ioaddr, pccard_iolen);

	if (attr_mem)
		iounmap(attr_mem);

	return err;
}

static char version[] __initdata = "orinoco_wlan_blackfin.c (Michael Hennerich <hennerich@blackfin.uclinux.org>)";
MODULE_AUTHOR("Michael Hennerich <hennerich@blackfin.uclinux.org>");
MODULE_DESCRIPTION("Driver for wireless LAN cards using wlan-blackfin");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual MPL/GPL");
#endif

static int __init orinoco_wlan_blackfin_init(void)
{
	printk(KERN_DEBUG "%s\n", version);
	return orinoco_wlan_blackfin_init_one();
}

void __exit orinoco_wlan_blackfin_exit(void)
{
	struct net_device *dev = sdev;

	BUG_ON(!dev);

	unregister_netdev(dev);

	if (dev->irq)
			free_irq(dev->irq, dev);

	kfree(dev->priv);

	release_region(WLAN_BLACKFIN_IO_ADDR, 64);
}

module_init(orinoco_wlan_blackfin_init);
module_exit(orinoco_wlan_blackfin_exit);

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
