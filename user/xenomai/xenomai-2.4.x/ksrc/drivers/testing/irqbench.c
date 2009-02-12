/*
 * Copyright (C) 2006 Jan Kiszka <jan.kiszka@web.de>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/ioport.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/pnp.h>
#endif /* Linux >= 2.6.0 */

#include <rtdm/rttesting.h>
#include <rtdm/rtdm_driver.h>
#include <nucleus/trace.h>

/* --- Serial port --- */

#define MSR_DCTS                0x01
#define MSR_DDSR                0x02
#define MSR_DDCD                0x08

#define MCR_RTS                 0x02
#define MCR_OUT2                0x08

#define IER_MODEM               0x08

#define RHR(ctx) (ctx->port_ioaddr + 0)		/* Receive Holding Buffer */
#define IER(ctx) (ctx->port_ioaddr + 1)		/* Interrupt Enable Register*/
#define IIR(ctx) (ctx->port_ioaddr + 2)		/* Interrupt Id Register */
#define LCR(ctx) (ctx->port_ioaddr + 3)		/* Line Control Register */
#define MCR(ctx) (ctx->port_ioaddr + 4)		/* Modem Control Register */
#define LSR(ctx) (ctx->port_ioaddr + 5)		/* Line Status Register */
#define MSR(ctx) (ctx->port_ioaddr + 6)		/* Modem Status Register */

/* --- Parallel port --- */

#define STAT_BUSY               0x80

#define CTRL_INIT               0x04
#define CTRL_STROBE             0x10

#define DATA(ctx) (ctx->port_ioaddr + 0)	/* Data register */
#define STAT(ctx) (ctx->port_ioaddr + 1)	/* Status register */
#define CTRL(ctx) (ctx->port_ioaddr + 2)	/* Control register */

struct rt_irqbench_context {
	int mode;
	int port_type;
	unsigned long port_ioaddr;
	unsigned int port_irq;
	unsigned int toggle;
	struct rttst_irqbench_stats stats;
	rtdm_irq_t irq_handle;
	rtdm_event_t irq_event;
	rtdm_task_t irq_task;
	rthal_pipeline_stage_t domain;
	struct semaphore nrt_mutex;
};

static unsigned int start_index;

module_param(start_index, uint, 0400);
MODULE_PARM_DESC(start_index, "First device instance number to be used");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jan.kiszka@web.de");

static inline int rt_irqbench_check_irq(struct rt_irqbench_context *ctx)
{
	int status;

	switch (ctx->port_type) {
	case RTTST_IRQBENCH_SERPORT:
		status = inb(MSR(ctx));
		/* Any change on DSR or DCD triggers trace freeze */
		if (status & (MSR_DDSR | MSR_DDCD))
			xntrace_user_freeze(0, 0);
		if (!(status & MSR_DCTS))
			return 0;
		break;

	case RTTST_IRQBENCH_PARPORT:
		/* A set BUSY line on /ACK IRW triggers trace freeze */
		if (!(inb(STAT(ctx)) & STAT_BUSY)) {
			xntrace_user_freeze(0, 0);
			return 0;
		}
		break;
	}
	ctx->stats.irqs_received++;
	return 1;
}

static inline void rt_irqbench_hwreply(struct rt_irqbench_context *ctx)
{
	switch (ctx->port_type) {
	case RTTST_IRQBENCH_SERPORT:
		/* Toggle RTS */
		ctx->toggle ^= MCR_RTS;
		outb(ctx->toggle, MCR(ctx));
		break;

	case RTTST_IRQBENCH_PARPORT:
		ctx->toggle ^= 0x08;
		outb(ctx->toggle, DATA(ctx));
		break;
	}
	xntrace_special(0xBE, 0);
	ctx->stats.irqs_acknowledged++;
}

static void rt_irqbench_task(void *arg)
{
	struct rt_irqbench_context *ctx = arg;

	while (1) {
		if (rtdm_event_wait(&ctx->irq_event) < 0)
			return;
		rt_irqbench_hwreply(ctx);
	}
}

static int rt_irqbench_task_irq(rtdm_irq_t *irq_handle)
{
	struct rt_irqbench_context *ctx;

	ctx = rtdm_irq_get_arg(irq_handle, struct rt_irqbench_context);

	if (rt_irqbench_check_irq(ctx))
		rtdm_event_signal(&ctx->irq_event);

	return RTDM_IRQ_HANDLED;
}

static int rt_irqbench_direct_irq(rtdm_irq_t *irq_handle)
{
	struct rt_irqbench_context *ctx;

	ctx = rtdm_irq_get_arg(irq_handle, struct rt_irqbench_context);

	if (rt_irqbench_check_irq(ctx))
		rt_irqbench_hwreply(ctx);

	return RTDM_IRQ_HANDLED;
}

static void rt_irqbench_domain_irq(unsigned irq, void *arg)
{
	struct rt_irqbench_context *ctx = arg;

	if (rt_irqbench_check_irq(ctx))
		rt_irqbench_hwreply(ctx);

	rthal_irq_end(ctx->port_irq);
}

static inline void do_rt_irqbench_domain_entry(void)
{
}

static RTHAL_DECLARE_DOMAIN(rt_irqbench_domain_entry);

static int rt_irqbench_stop(struct rt_irqbench_context *ctx)
{
	if (ctx->mode < 0)
		return -EINVAL;

	/* Disable hardware */
	switch (ctx->port_type) {
	case RTTST_IRQBENCH_SERPORT:
		outb(0, IER(ctx));
		release_region(ctx->port_ioaddr, 8);
		break;

	case RTTST_IRQBENCH_PARPORT:
		outb(0, CTRL(ctx));
		release_region(ctx->port_ioaddr, 3);
		break;
	}

	if (ctx->mode == RTTST_IRQBENCH_HARD_IRQ) {
		rthal_virtualize_irq(&ctx->domain, ctx->port_irq, NULL, NULL,
				     NULL, IPIPE_PASS_MASK);
		rthal_unregister_domain(&ctx->domain);
	} else
		rtdm_irq_free(&ctx->irq_handle);

	if (ctx->mode == RTTST_IRQBENCH_KERNEL_TASK)
		rtdm_task_destroy(&ctx->irq_task);

	ctx->mode = -1;

	return 0;
}

static int rt_irqbench_open(struct rtdm_dev_context *context,
			    rtdm_user_info_t *user_info, int oflags)
{
	struct rt_irqbench_context *ctx;

	ctx = (struct rt_irqbench_context *)context->dev_private;
	ctx->mode = -1;
	rtdm_event_init(&ctx->irq_event, 0);
	init_MUTEX(&ctx->nrt_mutex);

	return 0;
}

static int rt_irqbench_close(struct rtdm_dev_context *context,
			     rtdm_user_info_t *user_info)
{
	struct rt_irqbench_context *ctx;

	ctx = (struct rt_irqbench_context *)context->dev_private;
	down(&ctx->nrt_mutex);
	rt_irqbench_stop(ctx);
	rtdm_event_destroy(&ctx->irq_event);
	up(&ctx->nrt_mutex);

	return 0;
}

static int rt_irqbench_ioctl_nrt(struct rtdm_dev_context *context,
				 rtdm_user_info_t *user_info,
				 unsigned int request, void __user *arg)
{
	struct rt_irqbench_context *ctx;
	struct rttst_irqbench_config config_buf;
	struct rttst_irqbench_config *config;
	int err = 0;

	ctx = (struct rt_irqbench_context *)context->dev_private;

	switch (request) {
	case RTTST_RTIOC_IRQBENCH_START:
		config = (void *)arg;
		if (user_info) {
			if (rtdm_safe_copy_from_user
			    (user_info, &config_buf, arg,
			     sizeof(struct rttst_irqbench_config)) < 0)
				return -EFAULT;

			config = &config_buf;
		}

		if (config->port_type > RTTST_IRQBENCH_PARPORT)
			return -EINVAL;

		down(&ctx->nrt_mutex);

		if (test_bit(RTDM_CLOSING, &context->context_flags))
			goto unlock_start_out;

		ctx->port_type = config->port_type;
		ctx->port_ioaddr = config->port_ioaddr;

		/* Initialise hardware */
		switch (ctx->port_type) {
		case RTTST_IRQBENCH_SERPORT:
			if (!request_region(ctx->port_ioaddr, 8,
					    context->device->device_name)) {
				err = -EBUSY;
				goto unlock_start_out;
			}

			ctx->toggle = MCR_OUT2;

			/* Reset DLAB, reset RTS, enable OUT2 */
			outb(0, LCR(ctx));
			outb(MCR_OUT2, MCR(ctx));

			/* Mask all UART interrupts and clear pending ones. */
			outb(0, IER(ctx));
			inb(IIR(ctx));
			inb(LSR(ctx));
			inb(RHR(ctx));
			inb(MSR(ctx));
			break;

		case RTTST_IRQBENCH_PARPORT:
			if (!request_region(ctx->port_ioaddr, 3,
					    context->device->device_name)) {
				err = -EBUSY;
				goto unlock_start_out;
			}

			ctx->toggle = 0;
			outb(0, DATA(ctx));
			outb(CTRL_INIT, CTRL(ctx));
			break;
		}

		switch (config->mode) {
		case RTTST_IRQBENCH_USER_TASK:
			err =
			    rtdm_irq_request(&ctx->irq_handle,
					     config->port_irq,
					     rt_irqbench_task_irq, 0,
					     "irqbench", ctx);
			break;

		case RTTST_IRQBENCH_KERNEL_TASK:
			err =
			    rtdm_irq_request(&ctx->irq_handle,
					     config->port_irq,
					     rt_irqbench_task_irq, 0,
					     "irqbench", ctx);
			if (err)
				break;

			err = rtdm_task_init(&ctx->irq_task, "irqbench",
					     rt_irqbench_task, ctx,
					     config->priority, 0);
			if (err)
				rtdm_irq_free(&ctx->irq_handle);
			break;

		case RTTST_IRQBENCH_HANDLER:
			err =
			    rtdm_irq_request(&ctx->irq_handle,
					     config->port_irq,
					     rt_irqbench_direct_irq, 0,
					     "irqbench", ctx);
			break;

		case RTTST_IRQBENCH_HARD_IRQ:
			err =
			    rthal_register_domain(&ctx->domain,
						  "irqbench",
						  0x49525142,
						  IPIPE_HEAD_PRIORITY,
						  rt_irqbench_domain_entry);
			if (err)
				break;

			ctx->port_irq = config->port_irq;
			err =
			    rthal_virtualize_irq(&ctx->domain,
						 config->port_irq,
						 rt_irqbench_domain_irq,
						 ctx, NULL,
						 IPIPE_HANDLE_MASK |
						 IPIPE_WIRED_MASK |
						 IPIPE_EXCLUSIVE_MASK);
			if (err)
				rthal_unregister_domain(&ctx->domain);
			rthal_irq_enable(ctx->port_irq);
			break;

		default:
			err = -EINVAL;
			goto unlock_start_out;
		}

		if (err)
			switch (ctx->port_type) {
			case RTTST_IRQBENCH_SERPORT:
				release_region(ctx->port_ioaddr, 8);
				break;

			case RTTST_IRQBENCH_PARPORT:
				release_region(ctx->port_ioaddr, 3);
				break;
			}
		else {
			ctx->mode = config->mode;
	
			memset(&ctx->stats, 0, sizeof(ctx->stats));
	
			/* Arm IRQ */
			switch (ctx->port_type) {
			case RTTST_IRQBENCH_SERPORT:
				outb(IER_MODEM, IER(ctx));
				break;
	
			case RTTST_IRQBENCH_PARPORT:
				outb(CTRL_STROBE, CTRL(ctx));
				break;
			}
		}

	      unlock_start_out:
		up(&ctx->nrt_mutex);
		break;

	case RTTST_RTIOC_IRQBENCH_STOP:
		down(&ctx->nrt_mutex);
		err = rt_irqbench_stop(ctx);
		up(&ctx->nrt_mutex);
		break;

	case RTTST_RTIOC_IRQBENCH_GET_STATS:
		if (user_info)
			err =
			    rtdm_safe_copy_to_user(user_info, arg, &ctx->stats,
						   sizeof(struct
							  rttst_irqbench_stats));
		else
			*(struct rttst_irqbench_stats *)arg = ctx->stats;
		break;

	case RTTST_RTIOC_IRQBENCH_WAIT_IRQ:
		err = -ENOSYS;
		break;

	case RTTST_RTIOC_IRQBENCH_REPLY_IRQ:
		rt_irqbench_hwreply(ctx);
		break;

	default:
		err = -ENOTTY;
	}

	return err;
}

static int rt_irqbench_ioctl_rt(struct rtdm_dev_context *context,
				rtdm_user_info_t *user_info,
				unsigned int request, void __user *arg)
{
	struct rt_irqbench_context *ctx;
	int err = 0;

	ctx = (struct rt_irqbench_context *)context->dev_private;

	switch (request) {
	case RTTST_RTIOC_IRQBENCH_WAIT_IRQ:
		err = rtdm_event_wait(&ctx->irq_event);
		break;

	case RTTST_RTIOC_IRQBENCH_REPLY_IRQ:
		rt_irqbench_hwreply(ctx);
		break;

	case RTTST_RTIOC_IRQBENCH_START:
	case RTTST_RTIOC_IRQBENCH_STOP:
	case RTTST_RTIOC_IRQBENCH_GET_STATS:
		err = -ENOSYS;
		break;

	default:
		err = -ENOTTY;
	}

	return err;
}

static struct rtdm_device device = {
	.struct_version    = RTDM_DEVICE_STRUCT_VER,

	.device_flags      = RTDM_NAMED_DEVICE,
	.context_size      = sizeof(struct rt_irqbench_context),
	.device_name       = "",

	.open_nrt = rt_irqbench_open,

	.ops = {
		.close_nrt = rt_irqbench_close,

		.ioctl_rt  = rt_irqbench_ioctl_rt,
		.ioctl_nrt = rt_irqbench_ioctl_nrt,
	},

	.device_class      = RTDM_CLASS_TESTING,
	.device_sub_class  = RTDM_SUBCLASS_IRQBENCH,
	.profile_version   = RTTST_PROFILE_VER,
	.driver_name       = "xeno_irqbench",
	.driver_version    = RTDM_DRIVER_VER(0, 1, 1),
	.peripheral_name   = "IRQ Latency Benchmark",
	.provider_name     = "Jan Kiszka",
	.proc_name         = device.device_name,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static const struct pnp_device_id irqbench_pnp_tbl[] = {
	/* Standard LPT Printer Port */
	{.id = "PNP0400", .driver_data = 0},
	/* ECP Printer Port */
	{.id = "PNP0401", .driver_data = 0},
	{ }
};

static int irqbench_pnp_probe(struct pnp_dev *dev,
			      const struct pnp_device_id *id)
{
	return 0;
}

static struct pnp_driver irqbench_pnp_driver = {
	.name     = "irqbench",
	.id_table = irqbench_pnp_tbl,
	.probe    = irqbench_pnp_probe,
};

static int pnp_registered;
#endif /* Linux >= 2.6.0 */

static int __init __irqbench_init(void)
{
	int err;

	do {
		snprintf(device.device_name, RTDM_MAX_DEVNAME_LEN, "rttest%d",
			 start_index);
		err = rtdm_dev_register(&device);

		start_index++;
	} while (err == -EEXIST);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	if (!err && pnp_register_driver(&irqbench_pnp_driver) == 0)
		pnp_registered = 1;
#endif /* Linux >= 2.6.0 */

	return err;
}

static void __exit __irqbench_exit(void)
{
	rtdm_dev_unregister(&device, 1000);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	if (pnp_registered)
		pnp_unregister_driver(&irqbench_pnp_driver);
#endif /* Linux >= 2.6.0 */
}

module_init(__irqbench_init);
module_exit(__irqbench_exit);
