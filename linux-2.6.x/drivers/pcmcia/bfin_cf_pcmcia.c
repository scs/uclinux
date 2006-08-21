/*
 * file: drivers/pcmcia/bfin_cf.c
 * author: Michael Hennerich (hennerich@blackfin.uclinux.org)
 *
 * based on: drivers/pcmcia/omap_cf.c
 * omap_cf.c -- OMAP 16xx CompactFlash controller driver
 *
 * Copyright (c) 2005 David Brownell
 * Copyright (c) 2006 Michael Hennerich Analog Devices Inc.
 *
 * bugs:         enter bugs at http://blackfin.uclinux.org/
 *
 * this program is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published by
 * the free software foundation; either version 2, or (at your option)
 * any later version.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program; see the file copying.
 * if not, write to the free software foundation,
 * 59 temple place - suite 330, boston, ma 02111-1307, usa.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/platform_device.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/interrupt.h>

#include <pcmcia/ss.h>
#include <pcmcia/cisreg.h>
#include <asm/io.h>

#define SZ_1K			0x00000400
#define SZ_8K			0x00002000
#define	SZ_2K			(2 * SZ_1K)

#define	POLL_INTERVAL	(2 * HZ)

#define CF_ATASEL_ENA 	0x20311802 /* Inverts RESET */
#define CF_ATASEL_DIS 	0x20311800

#define bfin_cf_present(pfx) (bfin_read_FIO_FLAG_D() & (1<<pfx))

/*--------------------------------------------------------------------------*/

static const char driver_name[] = "bfin_cf_pcmcia";

struct bfin_cf_socket {
	struct pcmcia_socket	socket;

	struct timer_list	timer;
	unsigned		present:1;
	unsigned		active:1;

	struct platform_device	*pdev;
	unsigned long		phys_cf_io;
	unsigned long		phys_cf_attr;
	u_int			irq;
	u_short			cd_pfx;
};

/*--------------------------------------------------------------------------*/
static int bfin_cf_reset(void)
{
	  outw(0, CF_ATASEL_ENA);
	  mdelay(200);
	  outw(0, CF_ATASEL_DIS);

	  return 0;

}

static int bfin_cf_ss_init(struct pcmcia_socket *s)
{
	return 0;
}

/* the timer is primarily to kick this socket's pccardd */
static void bfin_cf_timer(unsigned long _cf)
{
	struct bfin_cf_socket	*cf = (void *) _cf;
	unsigned short present = bfin_cf_present(cf->cd_pfx);

	if (present != cf->present) {
		cf->present = present;
		pr_debug("%s: card %s\n", driver_name,
			present ? "present" : "gone");
		pcmcia_parse_events(&cf->socket, SS_DETECT);
	}

	if (cf->active)
		mod_timer(&cf->timer, jiffies + POLL_INTERVAL);
}

/* This irq handler prevents "irqNNN: nobody cared" messages as drivers
 * claim the card's IRQ.  It may also detect some card insertions, but
 * not removals; it can't always eliminate timer irqs.
 */
static irqreturn_t bfin_cf_irq(int irq, void *_cf, struct pt_regs *r)
{
	bfin_cf_timer((unsigned long)_cf);
	return IRQ_HANDLED;
}

static int bfin_cf_get_status(struct pcmcia_socket *s, u_int *sp)
{
	struct bfin_cf_socket	*cf;

	if (!sp)
		return -EINVAL;

	cf = container_of(s, struct bfin_cf_socket, socket);

	if (bfin_cf_present(cf->cd_pfx)) {
		*sp = SS_READY | SS_DETECT | SS_POWERON | SS_3VCARD;
		s->irq.AssignedIRQ = 0;
		s->pci_irq = cf->irq;

	} else
		*sp = 0;
	return 0;
}

static int
bfin_cf_set_socket(struct pcmcia_socket *sock, struct socket_state_t *s)
{

	struct bfin_cf_socket	*cf;
	cf = container_of(sock, struct bfin_cf_socket, socket);

	switch (s->Vcc) {
	case 0:
	case 33:
		break;
	case 50:
		break;
	default:
		return -EINVAL;
	}

	if (s->flags & SS_RESET){
		disable_irq(cf->irq);
		bfin_cf_reset();
		enable_irq(cf->irq);
	}

	pr_debug("%s: Vcc %d, io_irq %d, flags %04x csc %04x\n",
		driver_name, s->Vcc, s->io_irq, s->flags, s->csc_mask);

	return 0;
}

static int bfin_cf_ss_suspend(struct pcmcia_socket *s)
{
	pr_debug("%s: %s\n", driver_name, __FUNCTION__);
	return bfin_cf_set_socket(s, &dead_socket);
}

/* regions are 2K each:  mem, attrib, io (and reserved-for-ide) */

static int bfin_cf_set_io_map(struct pcmcia_socket *s, struct pccard_io_map *io)
{ struct bfin_cf_socket	*cf;

	cf = container_of(s, struct bfin_cf_socket, socket);
	io->flags &= MAP_ACTIVE|MAP_ATTRIB|MAP_16BIT;
	io->start = cf->phys_cf_io;
	io->stop = io->start + SZ_2K - 1;
	return 0;
}

static int
bfin_cf_set_mem_map(struct pcmcia_socket *s, struct pccard_mem_map *map)
{
	struct bfin_cf_socket	*cf;

	if (map->card_start)
		return -EINVAL;
	cf = container_of(s, struct bfin_cf_socket, socket);
	map->static_start = cf->phys_cf_io;
	map->flags &= MAP_ACTIVE|MAP_ATTRIB|MAP_16BIT;
	if (map->flags & MAP_ATTRIB)
		map->static_start = cf->phys_cf_attr;

	return 0;
}

static struct pccard_operations bfin_cf_ops = {
	.init			= bfin_cf_ss_init,
	.suspend		= bfin_cf_ss_suspend,
	.get_status		= bfin_cf_get_status,
	.set_socket		= bfin_cf_set_socket,
	.set_io_map		= bfin_cf_set_io_map,
	.set_mem_map	= bfin_cf_set_mem_map,
};

/*--------------------------------------------------------------------------*/

static int __init bfin_cf_probe(struct device *dev)
{
	struct bfin_cf_socket	*cf;
	struct platform_device	*pdev = to_platform_device(dev);
	struct resource		*io_mem,*attr_mem;
	int			irq;
	unsigned short	irq_pfx,cd_pfx;
	int			status;

	printk(KERN_INFO "Blackfin CompactFlash/PCMCIA Socket Driver\n");

	irq = platform_get_irq(pdev, 0);
	if (!irq)
		return -EINVAL;

	irq_pfx = platform_get_irq(pdev, 1);
	if (irq_pfx > IRQ_PF15)
		return -EINVAL;

	cd_pfx = platform_get_irq(pdev, 2);
	if (cd_pfx > 15)
		return -EINVAL;


    bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~(1 << cd_pfx));   /* input */
    bfin_write_FIO_INEN(bfin_read_FIO_INEN() | (1 << cd_pfx));   /* enable pin */

	cf = kcalloc(1, sizeof *cf, GFP_KERNEL);
	if (!cf)
		return -ENOMEM;

	cf->cd_pfx = cd_pfx;

	init_timer(&cf->timer);
	cf->timer.function = bfin_cf_timer;
	cf->timer.data = (unsigned long) cf;

	cf->pdev = pdev;
	dev_set_drvdata(dev, cf);

	/* this primarily just shuts up irq handling noise */
	status = request_irq(irq, bfin_cf_irq, SA_SHIRQ,
			driver_name, cf);
	if (status < 0)
		goto fail0;
	cf->irq = irq;
	cf->socket.pci_irq = irq;

	io_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	attr_mem = platform_get_resource(pdev, IORESOURCE_MEM, 1);

	if (!io_mem || !attr_mem)
		goto fail0;

	cf->phys_cf_io = io_mem->start;
	cf->phys_cf_attr = attr_mem->start;

	bfin_gpio_interrupt_setup(irq, irq_pfx, IRQT_LOW);

	/* pcmcia layer only remaps "real" memory */
	cf->socket.io_offset = (unsigned long)
			ioremap(cf->phys_cf_io, SZ_2K);

	if (!cf->socket.io_offset)
		goto fail1;

	pr_info("%s: on irq %d\n", driver_name, irq);

	pr_debug("%s: %s\n", driver_name, bfin_cf_present(cf->cd_pfx) ? "present" : "(not present)");

	cf->socket.owner = THIS_MODULE;
	cf->socket.dev.dev = dev;
	cf->socket.ops = &bfin_cf_ops;
	cf->socket.resource_ops = &pccard_static_ops;
	cf->socket.features = SS_CAP_PCCARD | SS_CAP_STATIC_MAP
				| SS_CAP_MEM_ALIGN;
	cf->socket.map_size = SZ_2K;

	status = pcmcia_register_socket(&cf->socket);
	if (status < 0)
		goto fail2;

	cf->active = 1;
	mod_timer(&cf->timer, jiffies + POLL_INTERVAL);
	return 0;

fail2:
	iounmap((void __iomem *) cf->socket.io_offset);
	release_mem_region(cf->phys_cf_io, SZ_8K);
fail1:
	free_irq(irq, cf);
fail0:
	kfree(cf);
	return status;
}

static int __devexit bfin_cf_remove(struct device *dev)
{
	struct bfin_cf_socket *cf = dev_get_drvdata(dev);

	cf->active = 0;
	pcmcia_unregister_socket(&cf->socket);
	del_timer_sync(&cf->timer);
	iounmap((void __iomem *) cf->socket.io_offset);
	release_mem_region(cf->phys_cf_io, SZ_8K);
	free_irq(cf->irq, cf);
	kfree(cf);
	return 0;
}

static struct device_driver bfin_cf_driver = {
	.name		= (char *) driver_name,
	.bus		= &platform_bus_type,
	.probe		= bfin_cf_probe,
	.remove		= __devexit_p(bfin_cf_remove),
	.suspend 	= pcmcia_socket_dev_suspend,
	.resume 	= pcmcia_socket_dev_resume,
};

static int __init bfin_cf_init(void)
{
		driver_register(&bfin_cf_driver);
	return 0;
}

static void __exit bfin_cf_exit(void)
{
		driver_unregister(&bfin_cf_driver);
}

module_init(bfin_cf_init);
module_exit(bfin_cf_exit);

MODULE_DESCRIPTION("BFIN CF/PCMCIA Driver");
MODULE_LICENSE("GPL");
