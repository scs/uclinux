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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/io.h>
#include <sys/mman.h>


#define SERPORT                 0
#define PARPORT                 1

/* --- Serial port --- */

#define MCR_DTR                 0x01
#define MCR_RTS                 0x02
#define MCR_OUT2                0x08

#define MSR_DELTA               0x0F

#define LCR(base) (base + 3) /* Line Control Register */
#define MCR(base) (base + 4) /* Modem Control Register */
#define LSR(base) (base + 5) /* Line Status Register */
#define MSR(base) (base + 6) /* Modem Status Register */

/* --- Parallel port --- */

#define CTRL_INIT               0x04
#define CTRL_STROBE             0x10

#define DATA(base) (base + 0) /* Data register */
#define STAT(base) (base + 1) /* Status register */
#define CTRL(base) (base + 2) /* Control register */

double tsc2ns_scale;
long long min_lat = LONG_MAX;
long long max_lat = LONG_MIN;
long long avg_lat = 0;
long outer_loops = 0;
int warmup = 1;
int terminate = 0;

static inline long long rdtsc(void)
{
    unsigned long long tsc;

    __asm__ __volatile__("rdtsc" : "=A" (tsc));
    return tsc;
}


static long tsc2ns(long long tsc)
{
    if ((tsc > LONG_MAX) || (tsc < LONG_MIN)) {
        fprintf(stderr, "irqbench: overflow (%lld ns)!\n",
                (long long)(tsc2ns_scale * (double)tsc));
        exit(2);
    }
    return (long)(tsc2ns_scale * (double)tsc);
}


static inline long long ns2tsc(long long ns)
{
    return (long long)(((double)ns) / tsc2ns_scale);
}


void calibrate_tsc(void)
{
    FILE *proc;
    char *lineptr = NULL;
    size_t len;
    double cpu_mhz;

    proc = fopen("/proc/cpuinfo", "r");
    if (proc == NULL) {
        perror("irqbench: Unable to open /proc/cpuinfo");
        exit(1);
    }

    while (getline(&lineptr, &len, proc) != -1)
        if (strncmp(lineptr, "cpu MHz", 7) == 0) {
            sscanf(strchr(lineptr, ':') + 1, "%lf", &cpu_mhz);
            break;
        }

    if (lineptr)
        free(lineptr);
    fclose(proc);

    printf("CPU frequency: %.3lf MHz\n", cpu_mhz);

    tsc2ns_scale = 1000.0 / cpu_mhz;
}


void sighand(int signal)
{
    if (warmup)
        exit(0);
    else
        terminate = 1;
}


int main(int argc, char *argv[])
{
    int                 port_type   = SERPORT;
    unsigned long       port_ioaddr = 0x3F8;
    int                 ioaddr_set = 0;
    long long           period = 100000;
    long long           timeout;
    long long           start, delay;
    unsigned long long  count = 1;
    unsigned int        toggle = 0;
    int                 trigger_trace = 0;
    int                 c;


    signal(SIGINT, sighand);
    signal(SIGTERM, sighand);
    signal(SIGHUP, sighand);
    signal(SIGALRM, sighand);

    calibrate_tsc();

    while ((c = getopt(argc,argv,"p:T:o:a:f")) != EOF)
        switch (c) {
            case 'p':
                period = atoi(optarg) * 1000;
                break;

            case 'T':
                alarm(atoi(optarg));
                break;

            case 'o':
                port_type = atoi(optarg);
                break;

            case 'a':
                port_ioaddr = strtol(optarg, NULL,
                    (strncmp(optarg, "0x", 2) == 0) ? 16 : 10);
                ioaddr_set = 1;
                break;

            case 'f':
                trigger_trace = 1;
                break;

            default:
                fprintf(stderr, "usage: irqbench [options]\n"
                        "  [-p <period_us>]             # signal period, default=100 us\n"
                        "  [-T <test_duration_seconds>] # default=0, so ^C to end\n"
                        "  [-o <port_type>]             # 0=serial (default), 1=parallel\n"
                        "  [-a <port_io_address>]       # default=0x3f8/0x378\n"
                        "  [-f]                         # freeze trace for each new max latency\n");
                exit(2);
        }

    /* set defaults for parallel port */
    if (port_type == 1 && !ioaddr_set)
        port_ioaddr = 0x378;

    if (iopl(3) < 0) {
        fprintf(stderr, "irqbench: superuser permissions required\n");
        exit(1);
    }
    mlockall(MCL_CURRENT | MCL_FUTURE);

    switch (port_type) {
        case SERPORT:
            toggle = MCR_OUT2;
            inb(MSR(port_ioaddr));
            break;

        case PARPORT:
            outb(CTRL_INIT, CTRL(port_ioaddr));
            break;

        default:
            fprintf(stderr, "irqbench: invalid port type\n");
            exit(1);
    }

    period = ns2tsc(period);

    printf("Port type:     %s\n"
           "Port address:  0x%lx\n\n",
           (port_type == SERPORT) ? "serial" : "parallel", port_ioaddr);

    printf("Waiting on target...\n");

    while (1)
        if (port_type ==  SERPORT) {
            toggle ^= MCR_RTS;
            outb(toggle, MCR(port_ioaddr));
            usleep(100000);
            if ((inb(MSR(port_ioaddr)) & MSR_DELTA) != 0)
                break;
        } else {
            int status = inb(STAT(port_ioaddr));

            outb(0x08, DATA(port_ioaddr));
            outb(0x00, DATA(port_ioaddr));
            usleep(100000);
            if (inb(STAT(port_ioaddr)) != status)
                break;
        }

    printf("Warming up...\n");

    while (!terminate) {
        long long loop_timeout = rdtsc() + ns2tsc(1000000000LL);
        long loop_avg = 0;
        int inner_loops = 0;

        while (rdtsc() < loop_timeout) {
            long lat;

            __asm__ __volatile__("cli");

            if (port_type ==  SERPORT) {
                start = rdtsc();

                toggle ^= MCR_RTS;
                outb(toggle, MCR(port_ioaddr));

                timeout = start + period * 100;
                while (((inb(MSR(port_ioaddr)) & MSR_DELTA) == 0) &&
                       (rdtsc() < timeout));

                delay = rdtsc() - start;
            } else {
                int status = inb(STAT(port_ioaddr));

                outb(0x08, DATA(port_ioaddr));

                start = rdtsc();

                outb(0x00, DATA(port_ioaddr));

                timeout = start + period * 100;
                while ((inb(STAT(port_ioaddr)) == status) &&
                       (rdtsc() < timeout));

                delay = rdtsc() - start;
            }

            if (!warmup) {
                lat = tsc2ns(delay);

                loop_avg += lat;
                if (lat < min_lat)
                    min_lat = lat;
                if (lat > max_lat) {
                    max_lat = lat;
                    if (trigger_trace) {
                        if (port_type == SERPORT) {
                            toggle ^= MCR_DTR;
                            outb(toggle, MCR(port_ioaddr));
                        } else {
                            outb(0x18, DATA(port_ioaddr));
                            outb(0x10, DATA(port_ioaddr));
                        }
                    }
                }
            }

            __asm__ __volatile__("sti");

            inner_loops++;

            while (rdtsc() < start + period);
        }

        count += inner_loops;

        if (!warmup && !terminate) {
            loop_avg /= inner_loops;

            printf("%llu: %.3f / %.3f / %.3f us\n", count,
                ((double)min_lat) / 1000.0, ((double)loop_avg) / 1000.0,
                ((double)max_lat) / 1000.0);

            avg_lat += loop_avg;
            outer_loops++;
        } else
            warmup = 0;
    }

    avg_lat /= outer_loops;
    printf("---\n%llu: %.3f / %.3f / %.3f us\n", count,
           ((double)min_lat) / 1000.0, ((double)avg_lat) / 1000.0,
           ((double)max_lat) / 1000.0);

    return 0;
}
