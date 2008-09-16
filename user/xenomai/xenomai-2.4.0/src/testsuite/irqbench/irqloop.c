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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rtdm/rttesting.h>

static int benchdev;
static int terminate;

void *irq_thread(void *arg)
{
    struct sched_param param = { .sched_priority = (long)arg };

    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

    while (1) {
        if (ioctl(benchdev, RTTST_RTIOC_IRQBENCH_WAIT_IRQ) ||
            ioctl(benchdev, RTTST_RTIOC_IRQBENCH_REPLY_IRQ))
            break;
    }

    param.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &param);

    return NULL;
}


void sighand(int sig)
{
    terminate = 1;
}


int main(int argc, char *argv[])
{
    const char *mode_name[] =
        { "user-space task", "kernel-space task",
          "IRQ handler", "hard-IRQ handler" };
    const char *port_type_name[] = { "serial", "parallel" };
    char devname[RTDM_MAX_DEVNAME_LEN];
    int benchdev_no = 0;
    struct rttst_irqbench_config config = {
        mode:               RTTST_IRQBENCH_USER_TASK,
        priority:           sched_get_priority_max(SCHED_FIFO),
        calibration_loops:  0,
        port_type:          RTTST_IRQBENCH_SERPORT,
        port_ioaddr:        0x3f8,
        port_irq:           4
    };
    struct rttst_irqbench_stats stats;
    unsigned long long last_received = 0;
    pthread_t thr;
    int ioaddr_set = 0;
    int irq_set = 0;
    int c;
    int timeout = 10;


    while ((c = getopt(argc,argv,"D:t:P:o:a:i:")) != EOF)
        switch (c) {
            case 'D':
                benchdev_no = atoi(optarg);
                break;

            case 't':
                config.mode = atoi(optarg);
                break;

            case 'P':
                config.priority = atoi(optarg);
                break;

            case 'o':
                config.port_type = atoi(optarg);
                break;

            case 'a':
                config.port_ioaddr = strtol(optarg, NULL,
                    (strncmp(optarg, "0x", 2) == 0) ? 16 : 10);
                ioaddr_set = 1;
                break;

            case 'i':
                config.port_irq = atoi(optarg);
                irq_set = 1;
                break;

            default:
                fprintf(stderr, "usage: irqloop [options]\n"
                        "  [-D <testing_device_no>] # number of testing device, default=0\n"
                        "  [-t <test_mode>]         # 0=user task (default), 1=kernel task,\n"
                        "                           # 2=IRQ handler, 3=hard-IRQ handler\n"
                        "  [-P <priority>]          # task priority (test mode 0 and 1 only)\n"
                        "  [-o <port_type>]         # 0=serial (default), 1=parallel\n"
                        "  [-a <port_io_address>]   # default=0x3f8/0x378\n"
                        "  [-i <port_irq>]          # default=4/7\n");
                exit(2);
        }

    /* set defaults for parallel port */
    if (config.port_type == 1) {
        if (!ioaddr_set)
            config.port_ioaddr = 0x378;
        if (!irq_set)
            config.port_irq = 0x7;
    }

    signal(SIGINT, sighand);
    signal(SIGTERM, sighand);
    signal(SIGHUP, sighand);

    mlockall(MCL_CURRENT|MCL_FUTURE);

    snprintf(devname, RTDM_MAX_DEVNAME_LEN, "/dev/rttest%d", benchdev_no);
    benchdev = open(devname, O_RDWR);
    if (benchdev < 0) {
        perror("irqloop: failed to open benchmark device");
        fprintf(stderr, "(modprobe xeno_irqbench?)\n");
        return 1;
    }

    if (config.mode == RTTST_IRQBENCH_USER_TASK) {
        pthread_attr_t attr;

        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);

        pthread_create(&thr, &attr, irq_thread, (void *)(long)config.priority);
    }

    if (ioctl(benchdev, RTTST_RTIOC_IRQBENCH_START, &config)) {
        perror("irqloop: error starting test");
        goto cleanup;
    }

    printf("Test mode:    %s\n"
           "Port type:    %s\n"
           "Port address: 0x%lx\n"
           "Port IRQ:     %d\n\n\n\n",
           mode_name[config.mode], port_type_name[config.port_type],
           config.port_ioaddr, config.port_irq);

    while (!terminate) {
        if (ioctl(benchdev, RTTST_RTIOC_IRQBENCH_GET_STATS, &stats) < 0) {
            perror("irqloop: error reading stats");
            break;
        }

        if ((last_received > 0) && (stats.irqs_received == last_received)) {
            if (--timeout == 0)
                break; /* timed out */
        } else
            timeout = 10;
        last_received = stats.irqs_received;

        printf("\033[2AReceived IRQs:     %lld\nAcknowledged IRQs: %lld\n",
                stats.irqs_received, stats.irqs_acknowledged);
        usleep(250000);
    }

    ioctl(benchdev, RTTST_RTIOC_IRQBENCH_STOP);

  cleanup:
    close(benchdev);
    if (config.mode == RTTST_IRQBENCH_USER_TASK) {
        pthread_cancel(thr);
        pthread_join(thr, NULL);
    }
    return 0;
}
