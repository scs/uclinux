/*
 * Program to configuring the CAN controller
 *
 * Copyright (C) 2006 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Copyright (C) 2005, 2006 Sebastian Smolorz
 *                          <Sebastian.Smolorz@stud.uni-hannover.de>
 *
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
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <sys/mman.h>

#include <rtdm/rtcan.h>

static void print_usage(char *prg)
{
    fprintf(stderr,
	    "Usage: %s <can-interface> [Options] [up|down|start|stop|sleep]\n"
	    "Options:\n"
	    " -v, --verbose            be verbose\n"
	    " -h, --help               this help\n"
	    " -c, --ctrlmode=CTRLMODE  listenonly, loopback or none\n"
	    " -b, --baudrate=BPS       baudrate in bits/sec\n"
	    " -B, --bittime=BTR0:BTR1  BTR or standard bit-time\n"
	    " -B, --bittime=BRP:PROP_SEG:PHASE_SEG1:PHASE_SEG2:SJW:SAM\n",
	    prg);
}

can_baudrate_t string_to_baudrate(char *str)
{
    can_baudrate_t baudrate;
    if (sscanf(str, "%i", &baudrate) != 1)
	return -1;
    return baudrate;
}

int string_to_mode(char *str)
{
    if ( !strcmp(str, "up") || !strcmp(str, "start") )
	return CAN_MODE_START;
    else if ( !strcmp(str, "down") || !strcmp(str, "stop") )
	return CAN_MODE_STOP;
    else if ( !strcmp(str, "sleep") )
	return CAN_MODE_SLEEP;
    return -EINVAL;
}

int string_to_ctrlmode(char *str)
{
    if ( !strcmp(str, "listenonly") )
	return CAN_CTRLMODE_LISTENONLY;
    else if ( !strcmp(str, "loopback") )
	return CAN_CTRLMODE_LOOPBACK;
    else if ( !strcmp(str, "none") )
	return 0;

    return -1;
}

int main(int argc, char *argv[])
{
    char    ifname[16];
    int     can_fd = -1;
    int     new_baudrate = -1;
    int     new_mode = -1;
    int     new_ctrlmode = 0, set_ctrlmode = 0;
    int     verbose = 0;
    int     bittime_count = 0, bittime_data[6];
    struct  ifreq ifr;
    can_baudrate_t *baudrate;
    can_ctrlmode_t *ctrlmode;
    can_mode_t *mode;
    struct can_bittime *bittime;
    int opt, ret;
    char* ptr;

    struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "verbose", no_argument, 0, 'v'},
	{ "baudrate", required_argument, 0, 'b'},
	{ "bittime", required_argument, 0, 'B'},
	{ "ctrlmode", required_argument, 0, 'c'},
	{ 0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "hvb:B:c:",
			      long_options, NULL)) != -1) {
	switch (opt) {
	case 'h':
	    print_usage(argv[0]);
	    exit(0);

	case 'v':
	    verbose = 1;
	    break;

	case 'b':
	    new_baudrate = string_to_baudrate(optarg);
	    if (new_baudrate == -1) {
		print_usage(argv[0]);
		exit(0);
	    }
	    break;

	case 'B':
	    ptr = optarg;
	    while (1) {
		bittime_data[bittime_count++] = strtoul(ptr, NULL, 0);
	        if (!(ptr = strchr(ptr, ':')))
		    break;
		ptr++;
	    }
	    if (bittime_count != 2 && bittime_count != 6) {
		print_usage(argv[0]);
		exit(0);
	    }
	    break;

	case 'c':
	    ret = string_to_ctrlmode(optarg);
	    if (ret == -1) {
		print_usage(argv[0]);
		exit(0);
	    }
	    new_ctrlmode |= ret;
	    set_ctrlmode = 1;
	    break;

	    break;

	default:
	    fprintf(stderr, "Unknown option %c\n", opt);
	    break;
	}
    }

    /* Get CAN interface name */
    if (optind != argc - 1 && optind != argc - 2) {
	print_usage(argv[0]);
	return 0;
    }

    strncpy(ifname, argv[optind], IFNAMSIZ);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (optind == argc - 2) {   /* Get mode setting */
	new_mode = string_to_mode(argv[optind + 1]);
	if (verbose)
	    printf("mode: %s (%#x)\n", argv[optind + 1], new_mode);
	if (new_mode < 0) {
	    print_usage(argv[0]);
	    return 0;
	}
    }

    can_fd = rt_dev_socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_fd < 0) {
	fprintf(stderr, "Cannot open RTDM CAN socket. Maybe driver not loaded? \n");
	return can_fd;
    }

    ret = rt_dev_ioctl(can_fd, SIOCGIFINDEX, &ifr);
    if (ret) {
	fprintf(stderr,"Can't get interface index for %s, code = %d\n", ifname, ret);
	return ret;
    }


    if (new_baudrate != -1) {
	if (verbose)
	    printf("baudrate: %d\n", new_baudrate);
	baudrate = (can_baudrate_t *)&ifr.ifr_ifru;
	*baudrate = new_baudrate;
	ret = rt_dev_ioctl(can_fd, SIOCSCANBAUDRATE, &ifr);
	if (ret) {
	    goto abort;
	}
    }

    if (bittime_count) {
	bittime = (struct can_bittime *)&ifr.ifr_ifru;
	if (bittime_count == 2) {
	    bittime->type = CAN_BITTIME_BTR;
	    bittime->btr.btr0 = bittime_data[0];
	    bittime->btr.btr1 = bittime_data[1];
	    if (verbose)
		printf("bit-time: btr0=0x%02x btr1=0x%02x\n",
		       bittime->btr.btr0, bittime->btr.btr1);
	} else {
	    bittime->type = CAN_BITTIME_STD;
	    bittime->std.brp = bittime_data[0];
	    bittime->std.prop_seg = bittime_data[1];
	    bittime->std.phase_seg1 = bittime_data[2];
	    bittime->std.phase_seg2 = bittime_data[3];
	    bittime->std.sjw = bittime_data[4];
	    bittime->std.sam = bittime_data[5];
	    if (verbose)
		printf("bit-time: brp=%d prop_seg=%d phase_seg1=%d "
		       "phase_seg2=%d sjw=%d sam=%d\n",
		       bittime->std.brp,
		       bittime->std.prop_seg,
		       bittime->std.phase_seg1,
		       bittime->std.phase_seg2,
		       bittime->std.sjw,
		       bittime->std.sam);
	}

	ret = rt_dev_ioctl(can_fd, SIOCSCANCUSTOMBITTIME, &ifr);
	if (ret) {
	    goto abort;
	}

    }

    if (set_ctrlmode != 0) {
	ctrlmode = (can_ctrlmode_t *)&ifr.ifr_ifru;
	*ctrlmode = new_ctrlmode;
	if (verbose)
	    printf("ctrlmode: %#x\n", new_ctrlmode);
	ret = rt_dev_ioctl(can_fd, SIOCSCANCTRLMODE, &ifr);
	if (ret) {
	    goto abort;
	}
    }

    if (new_mode != -1) {
	mode = (can_mode_t *)&ifr.ifr_ifru;
        *mode = new_mode;
	ret = rt_dev_ioctl(can_fd, SIOCSCANMODE, &ifr);
	if (ret) {
	    goto abort;
	}
    }

    rt_dev_close(can_fd);
    return 0;

 abort:
    rt_dev_close(can_fd);
    return ret;
}
