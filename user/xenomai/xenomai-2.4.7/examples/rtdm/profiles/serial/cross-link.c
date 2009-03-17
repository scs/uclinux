/*
 * cross-link.c
 *
 * Userspace test program (Xenomai native skin) for RTDM-based UART drivers
 * Copyright 2005 by Joerg Langenberg <joergel75@gmx.net>
 *
 * Updates by Jan Kiszka <jan.kiszka@web.de>
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
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#include <native/task.h>
#include <native/timer.h>

#include <rtdm/rtserial.h>

#define MAIN_PREFIX   "main : "
#define WTASK_PREFIX  "write_task: "
#define RTASK_PREFIX  "read_task: "

#define WRITE_FILE    "rtser0"
#define READ_FILE     "rtser1"

int read_fd  = -1;
int write_fd = -1;

#define STATE_FILE_OPENED         1
#define STATE_TASK_CREATED        2

unsigned int read_state = 0;
unsigned int write_state = 0;

/*                           --s-ms-us-ns */
RTIME write_task_period_ns =    100000000llu;
RT_TASK write_task;
RT_TASK read_task;

static const struct rtser_config read_config = {
	.config_mask       = 0xFFFF,
	.baud_rate         = 115200,
	.parity            = RTSER_DEF_PARITY,
	.data_bits         = RTSER_DEF_BITS,
	.stop_bits         = RTSER_DEF_STOPB,
	.handshake         = RTSER_DEF_HAND,
	.fifo_depth        = RTSER_DEF_FIFO_DEPTH,
	.rx_timeout        = RTSER_DEF_TIMEOUT,
	.tx_timeout        = RTSER_DEF_TIMEOUT,
	.event_timeout     = 1000000000, /* 1 s */
	.timestamp_history = RTSER_RX_TIMESTAMP_HISTORY,
	.event_mask        = RTSER_EVENT_RXPEND,
};

static const struct rtser_config write_config = {
	.config_mask       = RTSER_SET_BAUD | RTSER_SET_TIMESTAMP_HISTORY,
	.baud_rate         = 115200,
	.timestamp_history = RTSER_DEF_TIMESTAMP_HISTORY,
	/* the rest implicitely remains default */
};

static int close_file( int fd, char *name)
{
	int err, i=0;
	
	do {
		i++;
		err = rt_dev_close(fd);
		switch (err) {
		case -EAGAIN:
			printf(MAIN_PREFIX "%s -> EAGAIN (%d times)\n",
			       name, i);
			rt_task_sleep(50000); /* wait 50us */
			break;
		case 0:
			printf(MAIN_PREFIX "%s -> closed\n", name);
			break;
		default:
			printf(MAIN_PREFIX "%s -> %s\n", name,
			       strerror(-err));
			break;
		}
	} while (err == -EAGAIN && i < 10);

	return err;
}

void cleanup_all(void)
{
	if (read_state & STATE_FILE_OPENED) {
		close_file(read_fd, READ_FILE" (read)");
		read_state &= ~STATE_FILE_OPENED;
	}
	
	if (write_state & STATE_FILE_OPENED) {
		close_file(write_fd, WRITE_FILE " (write)");
		write_state &= ~STATE_FILE_OPENED;
	}
	
	if (write_state & STATE_TASK_CREATED) {
		printf(MAIN_PREFIX "delete write_task\n");
		rt_task_delete(&write_task);
		write_state &= ~STATE_TASK_CREATED;
	}
	
	if (read_state & STATE_TASK_CREATED) {
		printf(MAIN_PREFIX "delete read_task\n");
		rt_task_delete(&read_task);
		read_state &= ~STATE_TASK_CREATED;
	}
}

void catch_signal(int sig)
{
	cleanup_all();
	printf(MAIN_PREFIX "exit\n");
	return;
}

void write_task_proc(void *arg)
{
	int err;
	RTIME write_time;
	ssize_t sz = sizeof(RTIME);
	ssize_t written = 0;

	err = rt_task_set_periodic(NULL, TM_NOW,
				   rt_timer_ns2ticks(write_task_period_ns));
	if (err) {
		printf(WTASK_PREFIX "error on set periodic, %s\n",
		       strerror(-err));
		goto exit_write_task;
	}

	while (1) {
		err = rt_task_wait_period(NULL);
		if (err) {
			printf(WTASK_PREFIX
			       "error on rt_task_wait_period, %s\n",
			       strerror(-err));
			break;
		}
	
		write_time = rt_timer_read();

		written = rt_dev_write(write_fd, &write_time, sz);
		if (written < 0 ) {
			printf(WTASK_PREFIX "error on rt_dev_write, %s\n",
			       strerror(-err));
			break;
		} else if (written != sz) {
			printf(WTASK_PREFIX "only %d / %d byte transmitted\n",
			       written, sz);
			break;
		}
	}

 exit_write_task:
	if ((write_state & STATE_FILE_OPENED) &&
	    close_file(write_fd, WRITE_FILE " (write)") == 0)
		write_state &= ~STATE_FILE_OPENED;

	printf(WTASK_PREFIX "exit\n");
}

void read_task_proc(void *arg)
{
	int err;
	int nr = 0;
	RTIME read_time  = 0;
	RTIME write_time = 0;
	RTIME irq_time   = 0;
	ssize_t sz = sizeof(RTIME);
	ssize_t read = 0;
	struct rtser_event rx_event;
	
	printf(" Nr |   write->irq    |    irq->read    |   write->read   |\n");
	printf("-----------------------------------------------------------\n");

	/*
	 * We are in secondary mode now due to printf, the next
	 * blocking Xenomai or driver call will switch us back
	 * (here: RTSER_RTIOC_WAIT_EVENT).
	 */

	while (1) {
		/* waiting for event */
		err = rt_dev_ioctl(read_fd, RTSER_RTIOC_WAIT_EVENT, &rx_event);
		if (err) {
			printf(RTASK_PREFIX
			       "error on RTSER_RTIOC_WAIT_EVENT, %s\n",
			       strerror(-err));
			if (err == -ETIMEDOUT)
				continue;
			break;
		}

		irq_time = rx_event.rxpend_timestamp;
		read = rt_dev_read(read_fd, &write_time, sz);
		if (read == sz) {
			read_time = rt_timer_read();
			printf("%3d |%16llu |%16llu |%16llu\n", nr,
			       irq_time  - write_time,
			       read_time - irq_time,
			       read_time - write_time);
			nr++;
		} else if (read < 0 ) {
			printf(RTASK_PREFIX "error on rt_dev_read, code %s\n",
			       strerror(-err));
			break;
		} else {
			printf(RTASK_PREFIX "only %d / %d byte received \n",
			       read, sz);
			break;
		}
	}

	if ((read_state & STATE_FILE_OPENED) &&
	    close_file(read_fd, READ_FILE " (read)") == 0)
		read_state &= ~STATE_FILE_OPENED;

	printf(RTASK_PREFIX "exit\n");
}

int main(int argc, char* argv[])
{
	int err = 0;

	signal(SIGTERM, catch_signal);
	signal(SIGINT, catch_signal);

	/* no memory-swapping for this programm */
	mlockall(MCL_CURRENT | MCL_FUTURE);

	/* open rtser0 */
	write_fd = rt_dev_open( WRITE_FILE, 0);
	if (write_fd < 0) {
		printf(MAIN_PREFIX "can't open %s (write), %s\n", WRITE_FILE,
		       strerror(-write_fd));
		goto error;
	}
	write_state |= STATE_FILE_OPENED;
	printf(MAIN_PREFIX "write-file opened\n");

	/* writing write-config */
	err = rt_dev_ioctl(write_fd, RTSER_RTIOC_SET_CONFIG, &write_config);
	if (err) {
		printf(MAIN_PREFIX "error while RTSER_RTIOC_SET_CONFIG, %s\n",
		       strerror(-err));
		goto error;
	}
	printf(MAIN_PREFIX "write-config written\n");

	/* open rtser1 */
	read_fd = rt_dev_open( READ_FILE, 0 );
	if (read_fd < 0) {
		printf(MAIN_PREFIX "can't open %s (read), %s\n", READ_FILE,
		       strerror(-read_fd));
		goto error;
	}
	read_state |= STATE_FILE_OPENED;
	printf(MAIN_PREFIX "read-file opened\n");

	/* writing read-config */
	err = rt_dev_ioctl(read_fd, RTSER_RTIOC_SET_CONFIG, &read_config);
	if (err) {
		printf(MAIN_PREFIX "error while rt_dev_ioctl, %s\n",
		       strerror(-err));
		goto error;
	}
	printf(MAIN_PREFIX "read-config written\n");

	/* create write_task */
	err = rt_task_create(&write_task, "write_task", 0, 50, 0);
	if (err) {
		printf(MAIN_PREFIX "failed to create write_task, %s\n",
		       strerror(-err));
		goto error;
	}
	write_state |= STATE_TASK_CREATED;
	printf(MAIN_PREFIX "write-task created\n");

	/* create read_task */
	err = rt_task_create(&read_task, "read_task", 0, 51, 0);
	if (err) {
		printf(MAIN_PREFIX "failed to create read_task, %s\n",
		       strerror(-err));
		goto error;
	}
	read_state |= STATE_TASK_CREATED;
	printf(MAIN_PREFIX "read-task created\n");

	/* start write_task */
	printf(MAIN_PREFIX "starting write-task\n");
	err = rt_task_start(&write_task, &write_task_proc, NULL);
	if (err) {
		printf(MAIN_PREFIX "failed to start write_task, %s\n",
		       strerror(-err));
		goto error;
	}

	/* start read_task */
	printf(MAIN_PREFIX "starting read-task\n");
	err = rt_task_start(&read_task,&read_task_proc,NULL);
	if (err) {
		printf(MAIN_PREFIX "failed to start read_task, %s\n",
		       strerror(-err));
		goto error;
	}

	pause();
	return 0;

 error:
	cleanup_all();
	return err;
}
