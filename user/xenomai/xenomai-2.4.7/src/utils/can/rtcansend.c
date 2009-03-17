#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <sys/mman.h>

#include <native/task.h>
#include <native/timer.h>
#include <native/pipe.h>

#include <rtdm/rtcan.h>

extern int optind, opterr, optopt;

static void print_usage(char *prg)
{
    fprintf(stderr,
	    "Usage: %s <can-interface> [Options] <can-msg>\n"
	    "<can-msg> can consist of up to 8 bytes given as a space separated list\n"
	    "Options:\n"
	    " -i, --identifier=ID   CAN Identifier (default = 1)\n"
	    " -r  --rtr             send remote request\n"
	    " -e  --extended        send extended frame\n"
	    " -l  --loop=COUNT      send message COUNT times\n"
	    " -c, --count           message count in data[0-3]\n"
	    " -d, --delay=MS        delay in ms (default = 1ms)\n"
	    " -s, --send            use send instead of sendto\n"
	    " -t, --timeout=MS      timeout in ms\n"
	    " -L, --loopback=0|1    switch local loopback off or on\n"
	    " -v, --verbose         be verbose\n"
	    " -p, --print=MODULO    print every MODULO message\n"
	    " -h, --help            this help\n",
	    prg);
}


RT_TASK rt_task_desc;

static int s=-1, dlc=0, rtr=0, extended=0, verbose=0, loops=1;
static SRTIME delay=1000000;
static int count=0, print=1, use_send=0, loopback=-1;
static nanosecs_rel_t timeout = 0;
static struct can_frame frame;
static struct sockaddr_can to_addr;


void cleanup(void)
{
    int ret;

    if (verbose)
	printf("Cleaning up...\n");

    usleep(100000);

    if (s >= 0) {
	ret = rt_dev_close(s);
	s = -1;
	if (ret) {
	    fprintf(stderr, "rt_dev_close: %s\n", strerror(-ret));
	}
	rt_task_delete(&rt_task_desc);
    }
}

void cleanup_and_exit(int sig)
{
    if (verbose)
	printf("Signal %d received\n", sig);
    cleanup();
    exit(0);
}

void rt_task(void)
{
    int i, j, ret;

    for (i = 0; i < loops; i++) {
        rt_task_sleep(rt_timer_ns2ticks(delay));
	if (count)
	    memcpy(&frame.data[0], &i, sizeof(i));
	/* Note: sendto avoids the definiton of a receive filter list */
	if (use_send)
	    ret = rt_dev_send(s, (void *)&frame, sizeof(can_frame_t), 0);
	else
	    ret = rt_dev_sendto(s, (void *)&frame, sizeof(can_frame_t), 0,
				(struct sockaddr *)&to_addr, sizeof(to_addr));
	if (ret < 0) {
	    switch (ret) {
	    case -ETIMEDOUT:
		if (verbose)
		    printf("rt_dev_send(to): timed out");
		break;
	    case -EBADF:
		if (verbose)
		    printf("rt_dev_send(to): aborted because socket was closed");
		break;
	    default:
		fprintf(stderr, "rt_dev_send: %s\n", strerror(-ret));
		break;
	    }
	    i = loops;		/* abort */
	    break;
	}
	if (verbose && (i % print) == 0) {
	    if (frame.can_id & CAN_EFF_FLAG)
		printf("<0x%08x>", frame.can_id & CAN_EFF_MASK);
	    else
		printf("<0x%03x>", frame.can_id & CAN_SFF_MASK);
	    printf(" [%d]", frame.can_dlc);
	    for (j = 0; j < frame.can_dlc; j++) {
		printf(" %02x", frame.data[j]);
	    }
	    printf("\n");
	}
    }
}

int main(int argc, char **argv)
{
    int i, opt, ret;
    struct ifreq ifr;
    char name[32];

    struct option long_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "identifier", required_argument, 0, 'i'},
	{ "rtr", no_argument, 0, 'r'},
	{ "extended", no_argument, 0, 'e'},
	{ "verbose", no_argument, 0, 'v'},
	{ "count", no_argument, 0, 'c'},
	{ "print", required_argument, 0, 'p'},
	{ "loop", required_argument, 0, 'l'},
	{ "delay", required_argument, 0, 'd'},
	{ "send", no_argument, 0, 's'},
	{ "timeout", required_argument, 0, 't'},
	{ "loopback", required_argument, 0, 'L'},
	{ 0, 0, 0, 0},
    };

    mlockall(MCL_CURRENT | MCL_FUTURE);

    signal(SIGTERM, cleanup_and_exit);
    signal(SIGINT, cleanup_and_exit);

    frame.can_id = 1;

    while ((opt = getopt_long(argc, argv, "hvi:l:red:t:cp:sL:",
			      long_options, NULL)) != -1) {
	switch (opt) {
	case 'h':
	    print_usage(argv[0]);
	    exit(0);

	case 'p':
	    print = strtoul(optarg, NULL, 0);

	case 'v':
	    verbose = 1;
	    break;

	case 'c':
	    count = 1;
	    break;

	case 'l':
	    loops = strtoul(optarg, NULL, 0);
	    break;

	case 'i':
	    frame.can_id = strtoul(optarg, NULL, 0);
	    break;

	case 'r':
	    rtr = 1;
	    break;

	case 'e':
	    extended = 1;
	    break;

	case 'd':
	    delay = strtoul(optarg, NULL, 0) * 1000000LL;
	    break;

	case 's':
	    use_send = 1;
	    break;

	case 't':
	    timeout = strtoul(optarg, NULL, 0) * 1000000LL;
	    break;

	case 'L':
	    loopback = strtoul(optarg, NULL, 0);
	    break;

	default:
	    fprintf(stderr, "Unknown option %c\n", opt);
	    break;
	}
    }

    if (optind == argc) {
	print_usage(argv[0]);
	exit(0);
    }

    if (argv[optind] == NULL) {
	fprintf(stderr, "No Interface supplied\n");
	exit(-1);
    }

    if (verbose)
	printf("interface %s\n", argv[optind]);

    ret = rt_dev_socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (ret < 0) {
	fprintf(stderr, "rt_dev_socket: %s\n", strerror(-ret));
	return -1;
    }
    s = ret;

    if (loopback >= 0) {
	ret = rt_dev_setsockopt(s, SOL_CAN_RAW, CAN_RAW_LOOPBACK,
				&loopback, sizeof(loopback));
	if (ret < 0) {
	    fprintf(stderr, "rt_dev_setsockopt: %s\n", strerror(-ret));
	    goto failure;
	}
	if (verbose)
	    printf("Using loopback=%d\n", loopback);
    }

    strncpy(ifr.ifr_name, argv[optind], IFNAMSIZ);
    if (verbose)
	printf("s=%d, ifr_name=%s\n", s, ifr.ifr_name);

    ret = rt_dev_ioctl(s, SIOCGIFINDEX, &ifr);
    if (ret < 0) {
	fprintf(stderr, "rt_dev_ioctl: %s\n", strerror(-ret));
	goto failure;
    }

    memset(&to_addr, 0, sizeof(to_addr));
    to_addr.can_ifindex = ifr.ifr_ifindex;
    to_addr.can_family = AF_CAN;
    if (use_send) {
	/* Suppress definiton of a default receive filter list */
	ret = rt_dev_setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);
	if (ret < 0) {
	    fprintf(stderr, "rt_dev_setsockopt: %s\n", strerror(-ret));
	    goto failure;
	}

	ret = rt_dev_bind(s, (struct sockaddr *)&to_addr, sizeof(to_addr));
	if (ret < 0) {
	    fprintf(stderr, "rt_dev_bind: %s\n", strerror(-ret));
	    goto failure;
	}
    }

    if (count)
	frame.can_dlc = sizeof(int);
    else {
	for (i = optind + 1; i < argc; i++) {
	    frame.data[dlc] = strtoul(argv[i], NULL, 0);
	    dlc++;
	    if( dlc == 8 )
		break;
	}
	frame.can_dlc = dlc;
    }

    if (rtr)
	frame.can_id |= CAN_RTR_FLAG;

    if (extended)
	frame.can_id |= CAN_EFF_FLAG;

    if (timeout) {
	if (verbose)
	    printf("Timeout: %lld ns\n", (long long)timeout);
	ret = rt_dev_ioctl(s, RTCAN_RTIOC_SND_TIMEOUT, &timeout);
	if (ret) {
	    fprintf(stderr, "rt_dev_ioctl SND_TIMEOUT: %s\n", strerror(-ret));
	    goto failure;
	}
    }

    snprintf(name, sizeof(name), "rtcansend-%d", getpid());
    ret = rt_task_shadow(&rt_task_desc, name, 1, 0);
    if (ret) {
	fprintf(stderr, "rt_task_shadow: %s\n", strerror(-ret));
	goto failure;
    }

    rt_task();

    cleanup();
    return 0;

 failure:
    cleanup();
    return -1;
}
