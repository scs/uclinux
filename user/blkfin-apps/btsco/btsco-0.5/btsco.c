/*
 *  Userspace management of snd-bt-sco
 *
 *  Copyright (c) 2003 by Jonathan Paisley <jp@dcs.gla.ac.uk>
 * 
 *  Daemon enhancements (c) 2004 by Lars Grunewaldt <lgw@dark-reality.de>
 *
 *  Based on sb16_csp/cspctl.c and hstest.c from bluez-utils/test.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#define HEADSET_AVAIL_FILE "/tmp/bt_headset_connected"

#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <ctype.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <alsa/asoundlib.h>

#define SNDRV_BT_SCO_IOCTL_SET_SCO_SOCKET _IOW ('H', 0x10, int)
#define SNDRV_BT_SCO_IOCTL_REQ_INFO _IO ('H', 0x11)

#ifndef SND_HWDEP_IFACE_EMUX_WAVETABLE
#define SND_HWDEP_IFACE_EMUX_WAVETABLE (SND_HWDEP_IFACE_USX2Y + 1)
#endif

#ifndef SND_HWDEP_IFACE_BLUETOOTH
#define SND_HWDEP_IFACE_BLUETOOTH (SND_HWDEP_IFACE_EMUX_WAVETABLE + 1)
#endif

#ifndef SNDRV_HWDEP_IFACE_BT_SCO
#define SNDRV_HWDEP_IFACE_BT_SCO (SND_HWDEP_IFACE_BLUETOOTH + 1)
#endif

#define NOT_CONNECTED 0
#define CONNECTED 1

typedef struct snd_card_bt_sco_info {
	int mixer_volume[2];
	int playback_count, capture_count;
} snd_card_bt_sco_info_t;

struct action {
	struct action *next;
	regex_t regex;
	char *cmd;
};

static volatile int terminate = 0, ring = 0, hupped = 0, reconnect = 0, rfreconnect = 0;
static int verbose = 0, auto_reconn = 0, conn_status = 0;

static void sig_term(int sig)
{
	terminate = 1;
}

static void sig_ring(int sig)
{
	ring = 1;
}

static void sig_hup(int sig)
{
	hupped = 1;
}

static void sig_usr(int sig)
{
	reconnect = 1;
}

static int rfcomm_connect(bdaddr_t * src, bdaddr_t * dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);
	addr.rc_channel = 0;
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	return s;
}

static int sco_connect(bdaddr_t * src, bdaddr_t * dst, uint16_t * handle,
		       uint16_t * mtu)
{
	struct sockaddr_sco addr;
	struct sco_conninfo conn;
	struct sco_options opts;
	int s;
	unsigned int size;

	if ((s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, src);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, dst);
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	size = sizeof(conn);
	if (getsockopt(s, SOL_SCO, SCO_CONNINFO, &conn, &size) < 0) {
		close(s);
		return -1;
	}

	size = sizeof(opts);
	if (getsockopt(s, SOL_SCO, SCO_OPTIONS, &opts, &size) < 0) {
		close(s);
		return -1;
	}

	if (handle)
		*handle = conn.hci_handle;

	if (mtu)
		*mtu = opts.mtu;

	return s;
}

static void error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);
}

static int bt_sco_set_fd(snd_hwdep_t * handle, int sco_fd)
{
	if (snd_hwdep_ioctl
	    (handle, SNDRV_BT_SCO_IOCTL_SET_SCO_SOCKET, (void *)sco_fd) < 0) {
		error("unable to set fd");
		return 1;
	}
	return 0;
}

int find_hwdep_device(int *cardP, int *devP)
{
	snd_ctl_t *ctl_handle;
	snd_ctl_card_info_t *card_info;
	snd_hwdep_info_t *hwdep_info;

	int card;
	int dev;
	int err;
	char card_id[32];

	ctl_handle = NULL;

	snd_ctl_card_info_alloca(&card_info);
	snd_hwdep_info_alloca(&hwdep_info);

	for (card = 0; card < 7; card++) {
		*cardP = card;

		if (ctl_handle) {
			snd_ctl_close(ctl_handle);
			ctl_handle = NULL;
		}
		// Get control handle for selected card
		sprintf(card_id, "hw:%i", card);
		if ((err = snd_ctl_open(&ctl_handle, card_id, 0)) < 0) {
			error("control open (%s): %s", card_id,
			      snd_strerror(err));
			return -1;
		}
		// Read control hardware info from card
		if ((err = snd_ctl_card_info(ctl_handle, card_info)) < 0) {
			error("control hardware info (%s): %s", card_id,
			      snd_strerror(err));
			continue;
		}
		//if (strcmp(snd_ctl_card_info_get_driver(card_info),"BT SCO (d)"))
		//    continue;

		dev = -1;
		err = 1;
		while (1) {
			if (snd_ctl_hwdep_next_device(ctl_handle, &dev) < 0)
				error("hwdep next device (%s): %s",
				      card_id, snd_strerror(err));
			if (dev < 0)
				break;
			snd_hwdep_info_set_device(hwdep_info, dev);
			if (snd_ctl_hwdep_info(ctl_handle, hwdep_info) < 0) {
				if (err != -ENOENT)
					error
					    ("control hwdep info (%s): %s",
					     card_id, snd_strerror(err));
				continue;
			}
			if (snd_hwdep_info_get_iface(hwdep_info) ==
			    SNDRV_HWDEP_IFACE_BT_SCO) {
				snd_ctl_close(ctl_handle);
				*devP = dev;
				return 0;
			}
		}
	}
	if (ctl_handle)
		snd_ctl_close(ctl_handle);

	return -1;
}

static void usage(void)
{
	printf("\nbtsco bluetooth audio handler\n");
	printf("Usage:\n" "\tbtsco [options] <bdaddr> [channel]\n");
	printf("Options:\n");
	printf(" -v print verbose output\n");	
	printf(" -r automatically reconnect upon lost rfcomm channel\n");
	printf(" -f fork and run as a daemon\n");
	printf(" -c clear filehandle and exit\n");
	printf(" -s indicate status by creating the file %s\n", HEADSET_AVAIL_FILE);
	printf(" -i hciX : use interface hciX\n");	
	printf(" -h print this usage and exit\n");
	printf("\nThe headset channel will be automatically detected if not specified\n\n");
}

int detect_channel(bdaddr_t * bdaddr)
{
	// equivalent to running:
	// sdptool search --bdaddr 00:0A:D9:74:B4:EA 0x1108
	// and parsing out the channel number

	uuid_t group;
	bdaddr_t interface;
	sdp_list_t *attrid, *search, *seq, *next;
	uint32_t range = 0x0000ffff;
	sdp_session_t *sess;
	int channel = 2;
	int searchresult;

	bacpy(&interface, BDADDR_ANY);

	sdp_uuid16_create(&group, 0x1108);
	sess = sdp_connect(&interface, bdaddr, SDP_RETRY_IF_BUSY);
	if (!sess) {
		error
		    ("Failed to connect to SDP server: %s\nAssuming channel %d\n",
		     strerror(errno), channel);
		return channel;
	}

	attrid = sdp_list_append(0, &range);
	search = sdp_list_append(0, &group);
	searchresult =
	    sdp_service_search_attr_req(sess, search, SDP_ATTR_REQ_RANGE,
					attrid, &seq);
	sdp_list_free(attrid, 0);
	sdp_list_free(search, 0);

	if (searchresult) {
		error("Service Search failed: %s\nAssuming channel %d\n",
		       strerror(errno), channel);
		sdp_close(sess);
		return channel;
	}

	for (; seq; seq = next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_list_t *list = 0;
		if (sdp_get_access_protos(rec, &list) == 0) {
			channel = sdp_get_proto_port(list, RFCOMM_UUID);
		}
		next = seq->next;
		free(seq);
		sdp_record_free(rec);
	}

	sdp_close(sess);
	return channel;
}

static void free_actions(struct action *list)
{
	struct action *cur;
	
	while(list != NULL) {
		cur = list;
		list = cur->next;
		regfree(&cur->regex);
		free(cur->cmd);
		free(cur);
	}
}

static struct action *read_actions(void)
{
	int state, retval, len;
	struct action *ret, *cur, *new;
	static char buf[1024];
	char *p;
	FILE *cf;
	
	ret = NULL;
	cur = NULL;
	new = NULL;
	if(getenv("HOME") == NULL)
		return(NULL);
	snprintf(buf, sizeof(buf), "%s/.btscorc", getenv("HOME"));
	if((cf = fopen(buf, "r")) == NULL) {
		if(errno != ENOENT)
			perror(buf);
		return(NULL);
	}
	state = 0;
	while(!feof(cf)) {
		if(fgets(buf, sizeof(buf), cf) == NULL) {
			if(ferror(cf)) {
				error("reading cf: %s", strerror(ferror(cf)));
				free_actions(ret);
				return(NULL);
			} else {
				continue;
			}
		}
		
		if(buf[0] == '#')
			continue;
		for(p = buf; isspace(*p); p++);
		memmove(buf, p, strlen(buf) + 1 - (p - buf));
		if(strlen(buf) == 0)
			continue;
		for(p = buf + strlen(buf) - 1; isspace(*p); p--);
		p[1] = 0;
		
		switch(state) {
		case 0:
			new = malloc(sizeof(*new));
			new->next = NULL;
			new->cmd = NULL;
			if((retval = regcomp(&new->regex, buf, REG_EXTENDED)) != 0) {
				error("could not compile regex `%s'", buf);
				free_actions(ret);
				free(new);
				return(NULL);
			}
			state = 1;
			break;
		case 1:
			len = strlen(buf);
			if(buf[len - 1] == '\\') {
				buf[len - 1] = 0;
			} else {
				state = 0;
				if(ret == NULL) {
					ret = cur = new;
				} else {
					cur->next = new;
					cur = new;
				}
			}
			if(new->cmd == NULL) {
				new->cmd = strdup(buf);
			} else {
				len = strlen(new->cmd);
				new->cmd = realloc(new->cmd, len + strlen(buf) + 1);
				memcpy(new->cmd + len, buf, strlen(buf));
				new->cmd[len + strlen(buf)] = 0;
			}
			break;
		}
	}
	fclose(cf);
	return(ret);
}

void headset_available(int onoff) {

	if (onoff) {
		int fd;
		fd=open(HEADSET_AVAIL_FILE,O_CREAT|O_WRONLY,0);
		if (fd) close(fd);
		else fprintf(stderr,"Can't create availability indicator %s.\n",HEADSET_AVAIL_FILE);
	} else {
		if (unlink(HEADSET_AVAIL_FILE)) {
			fprintf(stderr,"Can't delete availability indicator %s.\n",HEADSET_AVAIL_FILE);
		}
	}
}

int main(int argc, char *argv[])
{
	int dev;
	int card;
	int ret;
	int fork, clear;
        int hci_if;
	char *hci_opt = NULL;
	 
	struct sigaction sa;

	//struct timeval timeout;
	static char buf[2048];
	//int sel, rlen, wlen;
	int rlen, wlen;

	bdaddr_t local;
	bdaddr_t bdaddr;
	uint8_t channel;

	//char *filename;
	//mode_t filemode;
	//int mode = 0;
	int dd;
	int rd;			// rfcomm handle
	int sd;			//sco handle
	uint16_t sco_handle, sco_mtu, vs;
	char line[100];
	int last_volumes[2];
	int dr_usage, force_sco, force_old;

	// sco_mode is our running mode. 0 => not connect, 1 => connected
	// see NOT_CONNECTED,CONNECTED :)
	int sco_mode;

	struct pollfd pfds[10];
	int nfds;

	int i, err;

	snd_hwdep_t *handle;
	char hwdep_name[16];
	snd_card_bt_sco_info_t infobuf;
	struct action *actions;

	fork = 0;
	clear = 0;
	while((i = getopt(argc, argv, "fcvhrsi:")) >= 0) {
		switch(i) {
		case 'v':
			verbose++;
			break;
		case 'f':
			fork = 1;
			break;
		case 'c':
			clear = 1;
		        break;
		case 'r':
		        auto_reconn = 1;
		        break;
		case 's':
			conn_status = 1;
			break;
		case 'i':
			hci_opt = optarg;
			break;
		case 'h':
		case '?':
		case ':':
		default:
			usage();
			exit((i == 'h')?0:1);
		}
	}

	if(verbose) {
		printf("btsco v0.42\n");
		fflush(stdout);
	}

	actions = read_actions();
	
	/* detect the audio device */
	if (find_hwdep_device(&card, &dev)) {
		error("Can't find device. Bail");
		return 1;
	}

	if(verbose) {
		printf("Device is %d:%d\n", card, dev);
		fflush(stdout);
	}

	sprintf(hwdep_name, "hw:%i,%i", card, dev);

	/* open hwdep on audio device */
	if ((err = snd_hwdep_open(&handle, hwdep_name, O_RDWR)) < 0) {
		error("btsco open (%i-%i): %s\n", card, dev, snd_strerror(err));
		return -1;
	}

	if (clear) {
		if(verbose)
			printf("Clearing fd\n");
		bt_sco_set_fd(handle, 1);
		return 1;
	}

	/* find bdaddr */
	switch (argc - optind) {
	case 1:
		str2ba(argv[optind], &bdaddr);
		channel = detect_channel(&bdaddr);
		break;
	case 2:
		str2ba(argv[optind], &bdaddr);
		channel = atoi(argv[optind + 1]);
		break;
	default:
		usage();
		exit(-1);
	}

        /* set hci interface number */
	if(hci_opt == NULL)
		hci_if = 0;
	else if ( strncmp("hci",hci_opt,3) == 0 ) {
		hci_if = atoi(hci_opt+3);
	}
	else {
		usage();
		exit(-1);
        }

	/* check voice settings. in this version we only support mu-law */	
	hci_devba(hci_if, &local);
	dd = hci_open_dev(hci_if);
	hci_read_voice_setting(dd, &vs, 1000);
	vs = htobs(vs);
	if(verbose)
		printf("Voice setting: 0x%04x\n", vs);
	close(dd);
	/*
	   MU_LAW
	   if (vs != 0x0140) {
	   fprintf(stderr, "The voice setting must be 0x0140\n");
	   return -1;
	   }
	 */

	// 16bit
	if (vs != 0x060) {
		error("The voice setting must be 0x060\n");
		return -1;
	}

	/* setup sigterm handler. we must make sure to do a clean disconnect */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	
	sa.sa_handler = sig_ring;
	sigaction(SIGUSR1, &sa, NULL);

	sa.sa_handler = sig_usr;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	do {
        
		/* connect rfcomm control channel */
		if ((rd = rfcomm_connect(&local, &bdaddr, channel)) < 0) {
			perror("Can't connect RFCOMM channel");
			return -1;
		}
		
		if(verbose) {
			printf("RFCOMM channel %i connected\n", channel);
			printf("Using interface hci%d\n", hci_if);
			fflush(stdout);
		}
		
		i = 0;
		
		/* set up data polling description */
		nfds = 0;
		
		/* polling data from rfcomm */
		pfds[nfds].fd = rd;
		pfds[nfds++].events = POLLIN;
		
		// polling data from command line - unused now
//      pfds[nfds].fd = 0;
//      pfds[nfds++].events = POLLIN;
		
		/* polling data from hwdep interface */
		nfds += snd_hwdep_poll_descriptors(handle, &pfds[nfds], 1);
		
		last_volumes[0] = last_volumes[1] = 0;
		
		snd_hwdep_ioctl(handle, SNDRV_BT_SCO_IOCTL_REQ_INFO, NULL);
		if(snd_hwdep_read(handle, &infobuf, sizeof(infobuf)) < 0) {
			perror("read info");
			exit(1);
		}
		dr_usage = infobuf.playback_count || infobuf.capture_count;
		force_sco = -1;
		force_old = -1;
		
//		if (fork)
			//daemon(0, 0);
		
		/* we are not yet connected */
		sco_mode = NOT_CONNECTED;
		sd = -1;
		if(conn_status) headset_available(1);
		while (!terminate) {
			/*printf("outer loop\n"); */
			
			ret = poll(pfds, nfds, -1);
			if ((ret < 0) && (errno != EINTR)) {
				perror("poll");
				sleep(1); /* Don't steal the CPU in case of non-transient errors. */
			} else if (ret > 0) {
				unsigned short revents;
				
				/*printf("inner loop\n"); */
				/* Volume polling (sound card) */
				if (!snd_hwdep_poll_descriptors_revents
				    (handle, &pfds[nfds - 1], 1, &revents)) {
					if (revents & POLLIN) {
						int len;
						
						len = snd_hwdep_read(handle, &infobuf, sizeof(infobuf));
						if (len == sizeof(infobuf)) {
							if(verbose) {
								printf ("speaker volume: %d mic volume: %d\n",
									infobuf.mixer_volume[0], infobuf.mixer_volume[1]);
								fflush(stdout);
							}
							if (infobuf.mixer_volume[0] != last_volumes[0]) {
								sprintf(line, "\r\nAT+VGS=%d\r\n",
									infobuf.mixer_volume[0]);
								write(rd, line, strlen(line));
							}
							if (infobuf.mixer_volume[1] != last_volumes[1]) {
								sprintf(line, "\r\nAT+VGM=%d\r\n",
									infobuf.mixer_volume[1]);
								write(rd, line, strlen(line));
							}
							memcpy(last_volumes, infobuf.mixer_volume,
							       sizeof(infobuf.mixer_volume));
							dr_usage = infobuf.playback_count || infobuf.capture_count;
						}
					}
				}
				
				if ((pfds[0].revents & POLLHUP) || (pfds[0].revents & POLLERR)) {
					/* RFCOMM channel lost.
					 * For now, exit. */
					if(verbose) {
						printf("RFCOMM channel lost\n");
						fflush(stdout);
					}
					terminate = 1;
					if(auto_reconn) {
						rfreconnect = 1;
					}
				}
				
				// control transmission events for volume and channel control
				if (pfds[0].revents & POLLIN) {
					memset(buf, 0, sizeof(buf));
					rlen = read(rd, buf, sizeof(buf) - 1);
					if (rlen > 0) {
						struct action *cur;
						
						if(verbose) {
							printf("recieved %s\n", buf);
							fflush(stdout);
						}
						/* tell them we recieved */
						wlen = write(rd, "\r\nOK\r\n", 6);
						
						for(cur = actions; cur != NULL; cur = cur->next) {
							regmatch_t matches[10];
							char *cmdbuf, *args;
							int match;
							
							if(regexec(&cur->regex, buf, 10, matches, 0))
								continue;
							cmdbuf = strdup(cur->cmd);
							if((args = strchr(cmdbuf, ' ')) != NULL)
								*(args++) = 0;
							if(!strcmp(cmdbuf, "system")) {
								char *subst;
								char *sysbuf;
								int substl = 0;
								
								subst = NULL;
								sysbuf = strdup(args);
								
								for(i = 0; sysbuf[i]; i++) {
									if((sysbuf[i] == '\\') && (sysbuf[i + 1] >= '0') && (sysbuf[i + 1] <= '9')) {
										match = sysbuf[i + 1] - '0';
										if(matches[match].rm_so == -1)
											continue;
										substl = matches[match].rm_eo - matches[match].rm_so;
										subst = memcpy(malloc(substl), buf + matches[match].rm_so, substl);
									}
									if((sysbuf[i] == '\\') && (sysbuf[i + 1] == 'p')) {
										subst = malloc(11); /* For potentially 32-bit PIDs */
										substl = snprintf(subst, 11, "%i", getpid());
									}
									if((sysbuf[i] == '\\') && (sysbuf[i + 1] == 's')) {
										subst = malloc(11); /* same as above, for SCO mode */
										substl = snprintf(subst, 11, "%d", sco_mode);
									}
									if(subst != NULL) {
										sysbuf = realloc(sysbuf, strlen(sysbuf) + substl - 1);
										memmove(sysbuf + i + substl, sysbuf + i + 2, strlen(sysbuf) - i - 1);
										memmove(sysbuf + i, subst, substl);
										free(subst);
										subst = NULL;
										i += substl - 1;
									}
								}
								if(verbose) {
									printf("running %s\n", sysbuf);
									fflush(stdout);
								}
								system(sysbuf);
								free(sysbuf);
							} else if(!strcmp(cmdbuf, "sco-toggle")) {
								int target;
								char *p;
								
								target = 1;
								p = NULL;
								if(args != NULL) {
									if((p = strchr(args, ' ')) != NULL)
										*(p++) = 0;
									if(!strcmp(args, "on"))
										target = 1;
									else if(!strcmp(args, "off"))
										target = 0;
									else if(!strcmp(args, "none"))
										target = -1;
								}
								if(force_sco == target) {
									force_sco = -1;
									if(p != NULL) {
										if(!strcmp(p, "on"))
											force_sco = 1;
										else if(!strcmp(p, "off"))
											force_sco = 0;
										else if(!strcmp(p, "none"))
											force_sco = -1;
									}
								} else {
									force_sco = target;
								}
							} else if(!strcmp(cmdbuf, "sco-force")) {
								if(args != NULL) {
									if(!strcmp(args, "on"))
										force_sco = 1;
									else if(!strcmp(args, "off"))
										force_sco = 0;
									else if(!strcmp(args, "none"))
										force_sco = -1;
								}
							}
							free(cmdbuf);
						}
						
						if (sscanf
						    (buf, "AT+VGS=%d",
						     &infobuf.mixer_volume[0]) == 1) {
							if(verbose) {
								printf("Sending up speaker change %d\n", infobuf.mixer_volume[0]);
								fflush(stdout);
							}
							snd_hwdep_write(handle,
									infobuf.mixer_volume,
									sizeof
									(infobuf.mixer_volume));
						}
						if (sscanf
						    (buf, "AT+VGM=%d",
						     &infobuf.mixer_volume[1]) == 1) {
							if(verbose) {
								printf("Sending up microphone change %d\n", infobuf.mixer_volume[1]);
								fflush(stdout);
							}
							snd_hwdep_write(handle,
									infobuf.mixer_volume,
									sizeof
									(infobuf.mixer_volume));
							
						}
					}
				}
				
			}
			
			// mean little hack to allow for a signal-triggered reconnect
			// force disconnection of the channel (if connected)
			if (reconnect && (sco_mode == CONNECTED)) {
				force_old = force_sco;
				force_sco = 0;
			} else reconnect = 0;
			
			if(((!dr_usage && (force_sco != 1)) || (force_sco == 0)) && (sco_mode == CONNECTED)) {
				if(verbose) {
					printf("driver is not in use\n");
					fflush(stdout);
				}
				/* close bt_sco audio handle */
				bt_sco_set_fd(handle, -1);
				/* disconnect SCO stream */
				close(sd);
				if(verbose) {
					printf("disconnected SCO channel\n");
					fflush(stdout);
				}
				
				sco_mode = NOT_CONNECTED;
			}
			
			// if a reconnect has been requested, force 
			// the sco channel to be acquired again
			if (reconnect) {
				force_sco = 1;
				sleep(3);
			}
			
			if(((dr_usage && (force_sco != 0)) || (force_sco == 1)) && (sco_mode == NOT_CONNECTED)) {
				if(verbose) {
					printf("i/o needed: connecting sco...\n");
					fflush(stdout);
				}
				/* connect sco stream */
				if ((sd = sco_connect(&local, &bdaddr, &sco_handle, &sco_mtu)) < 0) {
					perror ("Can't connect SCO audio channel\n");
				} else {
					if(verbose) {
						printf("connected SCO channel\n");
						fflush(stdout);
					}
					bt_sco_set_fd (handle, sd);
					
					if(verbose) {
						printf ("Done setting sco fd\n");
						fflush(stdout);
					}
					sco_mode = CONNECTED;
				}
			}
			
			// restore original program status
			if (reconnect) {
				force_sco = force_old;
				reconnect = 0;
			}
			
			if (ring) {
				write(rd, "\r\nRING\r\n", 8);
				ring = 0;
			}
			
			if (hupped) {
				free_actions(actions);
				actions = read_actions();
				hupped = 0;
			}
		}
		if(conn_status) headset_available(0);
		if(rfreconnect) {
			rfreconnect = 0;
			terminate = 0;
		}
	} while (!terminate);
	
	if (sco_mode == CONNECTED) {
		close(sd);

		bt_sco_set_fd(handle, -1);

	}

	sleep(1);
	close(rd);

	snd_hwdep_close(handle);

	return 0;
}
