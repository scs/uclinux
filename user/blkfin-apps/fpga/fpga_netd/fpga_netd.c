/*
 * File:         fpga_netd.c
 * Based on:
 * Description:  Simple UDP network data server
 *
 * Michael Hennerich Copyright 2009 Analog Devices Inc.
 *
 * Licensed under the GPL-2 or later
 */
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>

#define PPI_DEVICE      "/dev/ppi"
#define BUFFSIZE		(4096 * 2)
#define SYNCPATTERN		'S'
#define SYNCPATTERN_SIZE	1
#define DACFILESIZE		(BUFFSIZE + 2)
#define DACFILE_MAGIC		0xFFFF

#undef DAEMONIZE

typedef struct {
	int port;
	struct in_addr client_addr;
	int new_dac_seq;
	unsigned char *sequence;
} conn_t;

pthread_t rx_thread;
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
conn_t rx_thread_data;

void Die(char *mess)
{
	perror(mess);
	exit(1);
}

void *rx_thread_code(void *arg)
{

	int received;
	int sock_rx;
	socklen_t slen;
	unsigned short *dacfile;
	unsigned char *buf;
	struct sockaddr_in dataserver;
	conn_t *c = (conn_t *) arg;

	buf = malloc(DACFILESIZE * 2);
	if (buf == NULL)
		pthread_exit(0);

	openlog("fpga_netd", LOG_NDELAY | LOG_PID, LOG_DAEMON);
	syslog(LOG_NOTICE, "started");

	c->sequence = buf + DACFILESIZE;
	dacfile = (unsigned short *)buf;

	/* Create the UDP inbound DATA socket */
	if ((sock_rx = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		syslog(LOG_ERR, "Failed to create socket");
		pthread_exit(0);
	}
	/* Construct the server sockaddr_in structure */
	memset(&dataserver, 0, sizeof(dataserver));	/* Clear struct */
	dataserver.sin_family = AF_INET;	/* Internet/IP */
	dataserver.sin_addr.s_addr = htonl(INADDR_ANY);	/* IP address */
	dataserver.sin_port = htons(c->port);	/* server port */

	/* Receive the word back from the server */
	slen = sizeof(dataserver);
	if (bind(sock_rx, (struct sockaddr *)&dataserver, slen)) {
		syslog(LOG_ERR, "bind failed");
		pthread_exit(0);
	};

	while (1) {
		do {
			received = 0;
			do {
				received += recvfrom(sock_rx, &buf[received], DACFILESIZE, 0,
						 (struct sockaddr *)&dataserver, &slen);


					if (dataserver.sin_addr.s_addr != c->client_addr.s_addr) {
						syslog(LOG_WARNING,
						       "Received a packet from an unexpected client");
						break;
					}

			} while(received < DACFILESIZE);

			if (received != DACFILESIZE) {
				syslog(LOG_WARNING,
					       "Mismatch in number of received bytes: %d\n", received);
			} else {
				if (dacfile[4096] != DACFILE_MAGIC)
					syslog(LOG_WARNING, "wrong DACFILE_MAGIC: %x\n", dacfile[4096]);
			}


		} while((received != DACFILESIZE) || (dacfile[4096] != DACFILE_MAGIC));

		syslog(LOG_NOTICE, "Matched number of received bytes: %d",
		       received);

		pthread_mutex_lock(&m);
		memcpy(c->sequence, buf, DACFILESIZE);
		c->new_dac_seq = 1;
		pthread_mutex_unlock(&m);
	}
};

int main(int argc, char *argv[])
{
	struct sockaddr_in dataclient;
	struct sockaddr_in ctrlclient;
	char buffer[BUFFSIZE];
	char syncpattern[SYNCPATTERN_SIZE] = { SYNCPATTERN };
	int sock_data, sock_ctrl, ret;
	int fd;

	if (argc != 5) {
		fprintf(stderr,
			"USAGE: %s <client_ip> <adc data port> <adc sync port> <dac control port>\n",
			argv[0]);
		exit(1);
	}

#ifdef DAEMONIZE
	if (daemon(0, 0) < 0) {
		Die("daemon");
	}
#endif
	/* Open /dev/ppi */
	fd = open(PPI_DEVICE, O_RDWR, 0);
	if (fd < 1) {
		Die("PPI");
	}

	/* Create the UDP DATA socket */
	if ((sock_data = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		Die("Failed to create socket");
	}
	/* Construct the client sockaddr_in structure */
	memset(&dataclient, 0, sizeof(dataclient));	/* Clear struct */
	dataclient.sin_family = AF_INET;	/* Internet/IP */
	dataclient.sin_addr.s_addr = inet_addr(argv[1]);	/* IP address */
	dataclient.sin_port = htons(atoi(argv[2]));	/* client port */

	/* Create the UDP CTRL socket */
	if ((sock_ctrl = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		Die("Failed to create socket");
	}
	/* Construct the client sockaddr_in structure */
	memset(&ctrlclient, 0, sizeof(ctrlclient));	/* Clear struct */
	ctrlclient.sin_family = AF_INET;	/* Internet/IP */
	ctrlclient.sin_addr.s_addr = inet_addr(argv[1]);	/* IP address */
	ctrlclient.sin_port = htons(atoi(argv[3]));	/* client port */

	rx_thread_data.port = atoi(argv[4]);
	rx_thread_data.client_addr.s_addr = dataclient.sin_addr.s_addr;
	pthread_create(&rx_thread, 0, rx_thread_code, &rx_thread_data);

	while (1) {
		pthread_mutex_lock(&m);
		if (rx_thread_data.new_dac_seq) {
			write(fd, rx_thread_data.sequence, BUFFSIZE);
			rx_thread_data.new_dac_seq = 0;
		}
		pthread_mutex_unlock(&m);

		if (sendto(sock_ctrl, syncpattern, SYNCPATTERN_SIZE, 0,
			   (struct sockaddr *)&ctrlclient,
			   sizeof(ctrlclient)) != SYNCPATTERN_SIZE) {
			Die("Mismatch in number of sent bytes");
		}

		ret = read(fd, buffer, BUFFSIZE);

		if (sendto(sock_data, buffer, BUFFSIZE, 0,
			   (struct sockaddr *)&dataclient,
			   sizeof(dataclient)) != BUFFSIZE) {
			Die("Mismatch in number of sent bytes");
		}
	}
}
