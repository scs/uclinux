/*
 * Bluetooth Headset ALSA Plugin
 *
 * Copyright (c) 2006 by Fabien Chevalier
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <errno.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

/* For bluetooth addresses manipulation functions */
#include <bluetooth/bluetooth.h>

#include <config.h>

/* Debug */

#define NDEBUG

#ifdef NDEBUG
	#define DBG(fmt, arg...)
	#define PRINTTIME
#else
	#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
	#define PRINTTIME  { \
		struct timespec ts; \
		clock_gettime(CLOCK_REALTIME, &ts); \
		DBG("time: seconds=%lu nseconds=%lu", ts.tv_sec, ts.tv_nsec); \
	} 
#endif

/* Defines */

#define PCM_SERVER_SOCKET "\0bluez-headset-pcm"

#define SCO_PACKET_LEN        48
#define SCO_RATE              8000
#define SCO_SAMPLE_SIZE       2
  /* interval between 2 SCO packets in nanoseconds */
#define SCO_PACKET_NSEC  (1000000000 / SCO_RATE * SCO_PACKET_LEN / SCO_SAMPLE_SIZE)

#define OPENED_PLAYBACK 1
#define OPENED_CAPTURE  2

#define PERIODS_MIN 2
#define PERIODS_MAX 334

  /* IPC packet types */
#define PKT_TYPE_CFG_BDADDR        0
#define PKT_TYPE_CFG_PAGINGTIMEOUT 1
#define PKT_TYPE_CFG_ACK           2
#define PKT_TYPE_CFG_NACK          3
#define PKT_TYPE_ERROR_IND         4
#define PKT_TYPE_STREAMING_IND     5

/* Macros */
#define ARRAY_NELEMS(a) (sizeof(a) / sizeof(a[0]) )

/* Constants */
const struct timespec sco_pkt_interval = {.tv_sec = 0, .tv_nsec = SCO_PACKET_NSEC};		

/* Data types */

typedef struct ipc_packet {
	unsigned char type;
	union {
		bdaddr_t     bdaddr;	               /* PKT_TYPE_CFG_BDADDR        */
		long         timeout;                  /* PKT_TYPE_CFG_PAGINGTIMEOUT */
		int	     errorcode;		       /* PKT_TYPE_ERROR_IND        */
	};
} ipc_packet_t;

typedef struct sco_packet {
	char sco_data[SCO_PACKET_LEN];
} sco_packet_t;

typedef struct snd_pcm_sco {
	snd_pcm_ioplug_t io;
	snd_pcm_sframes_t hw_ptr;
	struct timespec next_pkt_time;
	sco_packet_t pkt;
	unsigned int sco_data_count;
	int started;
} snd_pcm_sco_t;

/* Global variables */
static int          serverfd   = -1;
static int          scofd      = -1;
static unsigned int opened_for =  0;

/* Function declarations */

static void timespec_add(struct timespec *t1, const struct timespec *t2); /* t1 = t1 + t2 */
static void timespec_sub(struct timespec *t1, const struct timespec *t2); /* t1 = t1 - t2 */
static int  timespec_cmp(const struct timespec *t1, const struct timespec *t2);
static int  do_cfg(int serverfd, const bdaddr_t * bdaddr, long timeout);

/* Function definitions */

static snd_pcm_sframes_t sco_write(snd_pcm_ioplug_t *io,
				   const snd_pcm_channel_area_t *areas,
				   snd_pcm_uframes_t offset,
				   snd_pcm_uframes_t size)
{
	struct timespec curtime;
	snd_pcm_sco_t *bt_headset = io->private_data;
	snd_pcm_sframes_t ret = 0;
	snd_pcm_uframes_t frames_to_read;

	DBG("areas->step=%u, areas->first=%u, offset=%lu, size=%lu, io->nonblock=%u", areas->step, areas->first, offset, size, io->nonblock);

	clock_gettime(CLOCK_REALTIME, &curtime);

	if(!bt_headset->started) {
		unsigned long i;
		bt_headset->started = 1;
		bt_headset->sco_data_count = 0;
		clock_gettime(CLOCK_REALTIME, &bt_headset->next_pkt_time);
		for(i = 0; i < (io->buffer_size / io->period_size); i++) {
			timespec_sub(&bt_headset->next_pkt_time, &sco_pkt_interval);
		}
	}

	if(timespec_cmp(&curtime, &bt_headset->next_pkt_time) > 0) {
		if(!io->nonblock) {
			struct timespec wait = bt_headset->next_pkt_time;
			timespec_sub(&wait, &curtime);
			//DBG("Sleeping for %lu nanoseconds", wait.tv_nsec);
			ret = nanosleep(&wait, 0);
			if(ret == -1) {
				return -errno;
			}
		}
		else { /* non blocking playback */
			return -EAGAIN;
		}
	}

	if((bt_headset->sco_data_count + 2 * size) <= SCO_PACKET_LEN) {
		frames_to_read = size;
	}
	else {
		frames_to_read = (SCO_PACKET_LEN - bt_headset->sco_data_count) / 2;
	}

	/* Ready for more data */
	unsigned char *buff;
	buff = (unsigned char *) areas->addr + (areas->first + areas->step * offset) / 8;
	memcpy(bt_headset->pkt.sco_data + bt_headset->sco_data_count, buff, areas->step / 8 * frames_to_read);	
	bt_headset->sco_data_count += areas->step / 8 * frames_to_read;

	if(bt_headset->sco_data_count == SCO_PACKET_LEN) {
		int rsend;
		/* Actually send packet */
		PRINTTIME
		rsend = send(scofd, &bt_headset->pkt, sizeof(sco_packet_t), 0);
		if(rsend > 0) {
			ret = frames_to_read;
		}
		else {
			/* EPIPE means device underrun in ALSA world. But we mean we lost contact
                           with server, so we have to find another error code */
			ret = (errno == EPIPE ? -EIO : -errno);
			SYSERR("Lost contact with headsetd");
		}	
		/* Reset sco_data_count pointer */		
		bt_headset->sco_data_count = 0;
	
		/* We just sent a packet - increment the date when we must send next packet */
		timespec_add(&bt_headset->next_pkt_time, &sco_pkt_interval);
		/* Increment hardware transmition pointer */
		bt_headset->hw_ptr = (bt_headset->hw_ptr + SCO_PACKET_LEN / 2) % io->buffer_size;
	}
	else {
		/* Ask for more */
		ret = frames_to_read;
	}

	DBG("returning %d", (int)ret);
	return ret;
}

static snd_pcm_sframes_t sco_read(snd_pcm_ioplug_t *io,
				  const snd_pcm_channel_area_t *areas,
				  snd_pcm_uframes_t offset,
				  snd_pcm_uframes_t size)
{
	snd_pcm_sco_t *bt_headset = io->private_data;
	snd_pcm_sframes_t ret = 0;
	DBG("areas->step=%u, areas->first=%u, offset=%lu, size=%lu, io->nonblock=%u", areas->step, areas->first, offset, size, io->nonblock);
	if(bt_headset->sco_data_count == 0) {
		int nrecv = recv(scofd, &bt_headset->pkt, sizeof(sco_packet_t),
			MSG_WAITALL | (io->nonblock ? MSG_DONTWAIT : 0 ));
		if(nrecv == sizeof(sco_packet_t)) {
			ret = 0;
			/* Increment hardware transmition pointer */
			bt_headset->hw_ptr = (bt_headset->hw_ptr + SCO_PACKET_LEN / 2) % io->buffer_size;
		}
		else if(nrecv > 0) {
			ret = -EIO;
			SNDERR(strerror(-ret));
		}
		else if(nrecv == -1 && errno == EAGAIN) {
			ret = -EAGAIN;
		}
		else { /* nrecv < 0 */
			/* EPIPE means device underrun in ALSA world. But we mean we lost contact
                           with server, so we have to find another error code */
			ret = (errno == EPIPE ? -EIO : -errno);
			SYSERR("Lost contact with headsetd");
		}	
	}
	if(ret == 0) { /* Still ok, proceed */
		snd_pcm_uframes_t frames_to_write;
		unsigned char *buff;
		buff = (unsigned char *) areas->addr + (areas->first + areas->step * offset) / 8;
		
		if((bt_headset->sco_data_count + 2 * size) <= SCO_PACKET_LEN) {
			frames_to_write = size;
		}
		else {
			frames_to_write = (SCO_PACKET_LEN - bt_headset->sco_data_count) / 2;
		}
		memcpy(buff, bt_headset->pkt.sco_data + bt_headset->sco_data_count, areas->step / 8 * frames_to_write);	
		bt_headset->sco_data_count += (areas->step / 8 * frames_to_write);
		bt_headset->sco_data_count %= SCO_PACKET_LEN;
		/* Return written frames count */
		ret = frames_to_write;
	}

	DBG("returning %d", (int)ret);
	return ret;
}

static snd_pcm_sframes_t sco_pointer(snd_pcm_ioplug_t *io)
{
	snd_pcm_sco_t *bt_headset = io->private_data;
	struct timespec curtime;
	clock_gettime(CLOCK_REALTIME, &curtime);

	DBG("returning bt_headset->hw_ptr=%lu", bt_headset->hw_ptr);
	return bt_headset->hw_ptr;
}

static int sco_start(snd_pcm_ioplug_t *io)
{
	DBG("");
	return 0;
}

static int sco_stop(snd_pcm_ioplug_t *io)
{
	DBG("");
	snd_pcm_sco_t *bt_headset = io->private_data;
	bt_headset->started = 0;
	return 0;
}

static int sco_prepare(snd_pcm_ioplug_t *io)
{
	snd_pcm_sco_t *bt_headset = io->private_data;

	DBG("Preparing with io->period_size = %lu, io->buffer_size = %lu", io->period_size, io->buffer_size);

	if(io->stream == SND_PCM_STREAM_PLAYBACK) {
		/* If not null for playback, xmms doesn't display time correctly */
		bt_headset->hw_ptr = 0;
	}
	else {
		/* ALSA library is really picky on the fact hw_ptr is not null. If it is, capture won't start */
		bt_headset->hw_ptr = io->period_size;
	}
	return 0;
}

static int sco_hw_constraint(snd_pcm_sco_t *bt_headset, long max_periods)
{
	snd_pcm_ioplug_t *io = &bt_headset->io; 
	static const snd_pcm_access_t access_list[] = {
		SND_PCM_ACCESS_RW_INTERLEAVED,
		/* Mmap access is really useless from this driver point of view, 
                   but we support it because some pieces of software out there insist on using it */
		SND_PCM_ACCESS_MMAP_INTERLEAVED
	};
	static const unsigned int format[] = {
		SND_PCM_FORMAT_S16_LE
	};
	int err;

	/* Access type */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
		ARRAY_NELEMS(access_list), access_list);
	if (err < 0)
		return err;	

	/* supported formats */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
		ARRAY_NELEMS(format), format);
	if (err < 0)
		return err;

	/* supported channels */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
		1, 1);
	if (err < 0)
		return err;

	/* supported rates */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE, SCO_RATE, SCO_RATE);
	if (err < 0)
		return err;

	/* period size */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES,
					    SCO_PACKET_LEN, SCO_PACKET_LEN);
	if (err < 0)
		return err;
	/* periods */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS, 2, max_periods);
	if (err < 0)
		return err;
	if (err < 0)
		return err;

	return 0;
}


static int sco_close(snd_pcm_ioplug_t *io)
{
	snd_pcm_sco_t *bt_headset = io->private_data;
	DBG("closing ioplug=%p", io);
	switch(io->stream) {
	case SND_PCM_STREAM_PLAYBACK:
		DBG("Closing Playback stream");
		opened_for &= ~OPENED_PLAYBACK;
		break;
	case SND_PCM_STREAM_CAPTURE:
		DBG("Closing Capture stream");
		opened_for &= ~OPENED_CAPTURE;
		break;
	default:
		SNDERR("Unexpected ioplug received !!");
		return -EINVAL;	
	}

	/* If not any opened stream anymore, close files */
	if(opened_for == 0) {
		close(scofd);
		scofd = -1;
		close(serverfd);
		serverfd = -1;
	}
	io->private_data = 0;
	free(bt_headset);
	return 0;
}

static void timespec_sub(struct timespec *t1, const struct timespec *t2)
{
	while(t1->tv_nsec < t2->tv_nsec) {
		t1->tv_nsec += 1000000000;
		t1->tv_sec--;
	}
	t1->tv_nsec -= t2->tv_nsec;
	t1->tv_sec  -= t2->tv_sec;
}

static void timespec_add(struct timespec *t1, const struct timespec *t2)
{
	if(t1->tv_nsec >= 1000000000) {
		t1->tv_nsec -= 1000000000;
		t1->tv_sec++;
	}
	t1->tv_nsec += t2->tv_nsec;
	t1->tv_sec += t2->tv_sec;
}

static int timespec_cmp(const struct timespec *t1, const struct timespec *t2)
{
	signed long s = t2->tv_sec - t1->tv_sec;
	if(s != 0) {
		return s;
	}
	else {
		return t2->tv_nsec - t1->tv_nsec;
	}
}

static int  do_cfg(int serverfd, const bdaddr_t * bdaddr, long timeout)
{
	ipc_packet_t pkt;
	int res;

	/* Sending bd_addr */
	pkt.type = PKT_TYPE_CFG_BDADDR;
	bacpy(&pkt.bdaddr, bdaddr);
	res = send(serverfd, &pkt, sizeof(ipc_packet_t), 0);	
	if(res < 0) {
		return errno;
	}
	do {
		res = recv(serverfd, &pkt, sizeof(ipc_packet_t), 0);
	} while((res < 0) && (errno == EINTR));
	if(res < 0) {
		return errno;
	}
	if((pkt.type != PKT_TYPE_CFG_ACK) && (pkt.type != PKT_TYPE_CFG_NACK)) {
		SNDERR("Unexpected packet type received: type = %d", pkt.type);
		return EINVAL;
	}

	/* Sending timeout */
	pkt.type = PKT_TYPE_CFG_PAGINGTIMEOUT;
	pkt.timeout = timeout;
	res = send(serverfd, &pkt, sizeof(ipc_packet_t), 0);	
	if(res < 0) {
		return errno;
	}
	do {
		res = recv(serverfd, &pkt, sizeof(ipc_packet_t), 0);
	} while((res < 0) && (errno == EINTR));
	if(res < 0) {
		return errno;
	}
	if((pkt.type != PKT_TYPE_CFG_ACK) && (pkt.type != PKT_TYPE_CFG_NACK)) {
		SNDERR("Unexpected packet type received: type = %d", pkt.type);
		return EINVAL;
	}

	/* receiving SCO fd through ancilliary data*/	
        char cmsg_b[CMSG_SPACE(sizeof(int))];  /* ancillary data buffer */
 	struct iovec iov =  {
              .iov_base = &pkt,        /* Starting address */
              .iov_len  = sizeof(pkt)  /* Number of bytes  */
        };
	struct msghdr msgh = {
		.msg_name       = 0,
		.msg_namelen    = 0,
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = &cmsg_b,
		.msg_controllen = CMSG_LEN(sizeof(int)),
		.msg_flags      = 0
	};

	if(recvmsg(serverfd, &msgh, 0) >= 0) {
		if(pkt.type == PKT_TYPE_STREAMING_IND) {
			struct cmsghdr *cmsg;
			/* Receive auxiliary data in msgh */
			for (cmsg = CMSG_FIRSTHDR(&msgh);
				cmsg != NULL;
				cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
				if (cmsg->cmsg_level == SOL_SOCKET
					&& cmsg->cmsg_type == SCM_RIGHTS) {
					/* yep - got it !! */
					scofd = (*(int *) CMSG_DATA(cmsg));
					return 0;
				}
			}
			return EINVAL;
		}
		else if(pkt.type == PKT_TYPE_ERROR_IND){
			return pkt.errorcode;
		}
		else {
			SNDERR("Unexpected packet type received: type = %d", pkt.type);
			return EINVAL;
		}
	}
	else {
		int err = errno;
		SNDERR("Unable to receive SCO fd: %s", strerror(errno));
		return err;
	}
}

static snd_pcm_ioplug_callback_t sco_playback_callback = {
	.close = sco_close,
	.start = sco_start,
	.stop = sco_stop,
	.prepare = sco_prepare,
	.transfer = sco_write,
	.pointer = sco_pointer,
};

static snd_pcm_ioplug_callback_t sco_capture_callback = {
	.close = sco_close,
	.start = sco_start,
	.stop = sco_stop,
	.prepare = sco_prepare,
	.transfer = sco_read,
	.pointer = sco_pointer,
};


SND_PCM_PLUGIN_DEFINE_FUNC(sco)
{
	snd_config_iterator_t i, next;
	int read_bdaddr = 0;
	int err;
	snd_pcm_sco_t *headset = 0;
	bdaddr_t     hs_bdaddr;
	long timeout = -1;
	struct sockaddr_un  socket_location = {
		AF_UNIX, PCM_SERVER_SOCKET
	};
	long max_periods = PERIODS_MIN;
	
	DBG("Starting pcm_sco plugin.");
	DBG("Open mode is for %s.", stream == SND_PCM_STREAM_PLAYBACK ? "Playback" : "Capture");

	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id;
		if (snd_config_get_id(n, &id) < 0)
			continue;
		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0)
			continue;
		if (!strcmp(id, "bdaddr")) {
			const char *addr;
			if (snd_config_get_string(n, &addr) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			read_bdaddr = 1;
			str2ba(addr, &hs_bdaddr);
			continue;
		}
		if (!strcmp(id, "timeout")) {
			if (snd_config_get_integer(n, &timeout) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			continue;
		}
		if (!strcmp(id, "max_periods")) {
			if (snd_config_get_integer(n, &max_periods) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			else if(max_periods < PERIODS_MIN || max_periods > PERIODS_MAX) {
				SNDERR("Invalid range for %s : must be between %d and %d", id, PERIODS_MIN, PERIODS_MAX);
				return -EINVAL;
			}
			continue;
		}
		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	if((stream == SND_PCM_STREAM_PLAYBACK) && (opened_for & OPENED_PLAYBACK)) {
		SNDERR("Cannot open Bluetooth Headset PCM plugin twice for playback.");
		return -EINVAL;
	}
	if((stream == SND_PCM_STREAM_CAPTURE) && (opened_for & OPENED_CAPTURE)) {
		SNDERR("Cannot open Bluetooth Headset PCM plugin twice for capture.");
		return -EINVAL;
	}

	if(!read_bdaddr) {
		SNDERR("Bluetooth Device Address must be supplied.");
		return -EINVAL;
	}

	opened_for |= (stream == SND_PCM_STREAM_PLAYBACK ? OPENED_PLAYBACK : OPENED_CAPTURE);
	
	if(serverfd == -1) {
		/* First PCM to be opened, try to connect socket to headsetd */
		serverfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	
		err = connect(serverfd,
			(struct sockaddr *)&socket_location, sizeof(socket_location));
		if(err == 0) {
			err = do_cfg(serverfd, &hs_bdaddr, timeout);
			if(err != 0) {
				close(serverfd);
				serverfd = -1;
				return -err;
			}	
		}
		else {
			err = errno;
			SNDERR("Socket connection returned %s", strerror(err));
			close(serverfd);
			serverfd = -1;
			return -err;
		}
	}

	headset = calloc(1, sizeof(snd_pcm_sco_t));

	headset->io.version = SND_PCM_IOPLUG_VERSION;
	headset->io.name = "Bluetooth Headset";
	headset->io.mmap_rw     =  0; /* No direct mmap com */
	headset->io.poll_fd     =  1; /* Do not use poll !! */
	headset->io.poll_events =  POLLOUT; /* Do not use poll !! */
	headset->io.callback = stream == SND_PCM_STREAM_PLAYBACK ?
		&sco_playback_callback : &sco_capture_callback;
	
	err = snd_pcm_ioplug_create(&headset->io, name, stream, mode);
	if (err < 0)
		goto error;

	if ((err = sco_hw_constraint(headset, max_periods)) < 0) {
		goto error2; 
	}
	
	headset->io.private_data = headset;
	*pcmp = headset->io.pcm;

	DBG("opened as ioplug=%p, pcm=%p, ioplug->callback = %p", &headset->io, headset->io.pcm, headset->io.callback);

	return 0;

error2:
	snd_pcm_ioplug_delete(&headset->io);

error:
	opened_for &= (stream == SND_PCM_STREAM_PLAYBACK ? ~OPENED_PLAYBACK : ~OPENED_CAPTURE);
	if(!opened_for) {
		close(serverfd);
		serverfd = -1;
	}
	free(headset);
	return -err;
}

SND_PCM_PLUGIN_SYMBOL(sco);
