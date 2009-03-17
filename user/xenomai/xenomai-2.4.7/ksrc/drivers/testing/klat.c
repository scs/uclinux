/*
 * Copyright (C) 2008 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

#include <native/pipe.h>
#include <native/task.h>
#include <rtdm/rttesting.h>

#define DEV_NR_MAX 256

static int pipe = P_MINOR_AUTO;
module_param(pipe, int, 0400);
MODULE_PARM_DESC(pipe, "Index of the RT-pipe used for first connection"
		 " (-1, the default, means automatic minor allocation)");

static int mode = 1;
module_param(mode, int, 0400);
MODULE_PARM_DESC(mode, "Test mode, (1 for kernel task, 2 for timer handler)");

static int priority = 99;
module_param(priority, int, 0400);
MODULE_PARM_DESC(priority, "Kernel task priority");

static unsigned period = 100;
module_param(period, uint, 0400);
MODULE_PARM_DESC(period, "Sampling period, in microseconds");

static int freeze_max = 0;
module_param(freeze_max, int, 0400);
MODULE_PARM_DESC(freeze_max, "Freeze trace for each new max latency");

MODULE_LICENSE("GPL");
MODULE_AUTHOR("gilles.chanteperdrix@xenomai.org");

static RT_TASK klat_srvr;
static RT_PIPE klat_pipe;
static int fd;
static struct {
	struct rttst_tmbench_config config;
	struct rttst_interm_bench_res res;
} pkt;

static void klat_server(void *cookie)
{
	int err;

	for (;;) {
		err = rt_dev_ioctl(fd, RTTST_RTIOC_INTERM_BENCH_RES, &pkt.res);
		if (err) {
			if (err != -EIDRM)
				printk("rt_dev_ioctl(RTTST_RTIOC_INTERM_BENCH_RES): %d",
				       err);
			return;
		}

		/* Do not check rt_pipe_write return value, the pipe may well be
		   full. */
		rt_pipe_write(&klat_pipe, &pkt, sizeof(pkt), P_NORMAL);
	}
}

static int __init klat_mod_init(void)
{
	char devname[RTDM_MAX_DEVNAME_LEN + 1];
	unsigned dev_nr;
	int err;

	err = rt_pipe_create(&klat_pipe, "klat_pipe", pipe, 4096);
	if (err) {
		printk("rt_pipe_create(klat_pipe): %d\n", err);
		return err;
	}

	err = rt_task_create(&klat_srvr, "klat_srvr", 0, 0, 0);
	if (err) {
		printk("rt_task_create(klat_srvr): %d\n", err);
		goto err_close_pipe;
	}

	pkt.config.mode = mode;
	pkt.config.priority = priority;
	pkt.config.period = period * 1000;
	pkt.config.warmup_loops = 1;
	pkt.config.histogram_size = 0;
	pkt.config.freeze_max = freeze_max;

	for (dev_nr = 0; dev_nr < DEV_NR_MAX; dev_nr++) {
		snprintf(devname, sizeof(devname), "rttest%d", dev_nr);
		fd = rt_dev_open(devname, O_RDONLY);
		if (fd < 0)
			continue;

		err = rt_dev_ioctl(fd, RTTST_RTIOC_TMBENCH_START, &pkt.config);
		if (err == -ENOTTY) {
			rt_dev_close(fd);
			continue;
		}

		if (err < 0) {
			printk("rt_dev_ioctl(RTTST_RTIOC_TMBENCH_START): %d\n",
			       err);
			goto err_destroy_task;
		}

		break;
	}
	if (fd < 0) {
		printk("rt_dev_open: could not find rttest device\n"
		       "(modprobe timerbench?)");
		err = fd;
		goto err_destroy_task;
	}

	err = rt_task_start(&klat_srvr, &klat_server, NULL);
	if (err) {
		printk("rt_task_start: %d\n", err);
		goto err_close_dev;
	}
	
	return 0;

  err_close_dev:
	rt_dev_close(fd);
  err_destroy_task:
	rt_task_delete(&klat_srvr);
  err_close_pipe:
	rt_pipe_delete(&klat_pipe);
	return err;
}


static void klat_mod_exit(void)
{
	rt_dev_close(fd);
	rt_task_delete(&klat_srvr);
	rt_pipe_delete(&klat_pipe);
}

module_init(klat_mod_init);
module_exit(klat_mod_exit);
