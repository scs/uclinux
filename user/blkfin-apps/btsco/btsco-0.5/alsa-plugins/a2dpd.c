/*
*
*  A2DPD - Bluetooth A2DP daemon for Linux
*
*  Copyright (C) 2006  Frédéric DALLEAU <frederic.dalleau@palmsource.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <linux/input.h>
#include <linux/uinput.h>

#include "a2dplib.h"
#include "alsalib.h"
#include "a2dpd_protocol.h"
#include "a2dp_timer.h"
#include "a2dp_ipc.h"
#include "../avrcp.h"
#include "resample.h"

#define MAXBLUETOOTHDEVICES    (3)
#define MAXCLIENTSPERDEVICE    (8)
#define MAXCLIENTSRINGSIZE     (32)
#define POOLENTRYSIZE          (A2DPD_BLOCK_SIZE)
#define PIDFILE                "/var/run/a2dp.pid"
#define UINPUT_DEVICE          "/dev/input/uinput"
#define A2DPD_CONFIG_FILE      ".a2dpdrc"

static char g_sOutputFilename[512];
static char g_srcfilename[512];
static char g_sCmdPlay[512];
static char g_sCmdPause[512];
static char g_sCmdPrev[512];
static char g_sCmdNext[512];
static char g_sCmdNew[512];
static int g_nbdeviceconnected = 0;
static int uinput_fd = -1;
static int g_bavrcp = 0;
static int g_brereadconfig = 0;
static int g_breversestereo = 0;

#define CHECKVAL ((uint32_t)0xFDFDFDFD)

void* mymalloc(int size)
{
	char* buffer = malloc(size+8);
	
	if(buffer)
	{
		*((uint32_t*)buffer) = ((uint32_t)size);
		buffer+=4;
		*((uint32_t*)(buffer+size)) = CHECKVAL;
	}
	return buffer;
}

void myfree(void* p, int line)
{
	char* buffer = p;
	if(buffer)
	{
		uint32_t size  = *((uint32_t*)(buffer-4));
		uint32_t check = *((uint32_t*)(buffer+size));
		if(check != CHECKVAL || size>2048)
			printf("buffer overflow line %d (size=%d check=%X)\n", line, size, check);
		buffer-=4;
		free(buffer);
	}
}

int checkbuffer__(void* p, int line)
{
	int result = 0;
	char* buffer = p;
	if(buffer)
	{
		uint32_t size  = *((uint32_t*)(buffer-4));
		uint32_t check = *((uint32_t*)(buffer+size));
		if(check != CHECKVAL || size>2048)
		{
			printf("buffer failed check line %d (size=%d check=%X)\n", line, size, check);
			result = 1;
		}
	}
	return result;
}

#define safefree(buf) do { if(buf) { myfree(buf, __LINE__); (buf) = NULL; } } while (0)
#define checkbuffer(buf) checkbuffer__(buf, __LINE__)

// This function is needed to destroy zombies processes
// On Unix, any forked process which terminate before its parent create a zombie until parent call waitpid()
// We do not want to wait as we just need to "fire and forget" processes
// Found that on the web, hope it works
// http://www.erlenstar.demon.co.uk/unix/faq_2.html
void ignore_child_processes_return_values()
{
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
#ifdef SA_NOCLDWAIT
	sa.sa_flags = SA_NOCLDWAIT;
#else
	sa.sa_flags = 0;
#endif
	sigemptyset(&sa.sa_mask);
	sigaction(SIGCHLD, &sa, NULL);
}

void make_daemon_process(int bFork, int bVerbose, char *output_file_name)
{
	// Fork to background process if needed
	if (bFork == 1) {
#ifdef __uClinux__
		switch (vfork()) {
#else
		switch (fork()) {
#endif
		case -1:
#ifdef __uClinux__
			_exit(-1);
#else
			exit(-1);
#endif
		case 0:
			break;
		default:
#ifdef __uClinux__
			_exit(0);
#else
			exit(0);
#endif
		}

		setsid();
		chdir("/");
	}
	// Redirect output to file (default /dev/null) in silent mode, verbose will print output to stdin/out/err
	if (!bVerbose) {
		int fd;
		if ((fd = open(output_file_name, O_CREAT | O_APPEND | O_RDWR, 0)) != -1) {
			fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
			(void) dup2(fd, STDIN_FILENO);
			(void) dup2(fd, STDOUT_FILENO);
			(void) dup2(fd, STDERR_FILENO);
			if (fd > 2)
				(void) close(fd);
		} else {
			perror("a2dpd: Couldn't redirect output");
		}
	}

	printf("a2dpd [%s %s] starting ...", __DATE__, __TIME__);
}

static int lock_fd(int fd)
{
	struct flock lock;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	return fcntl(fd, F_SETLK, &lock);
}

//////////////////////////////////////////
//////////////////////////////////////////
// AVRCP CODE BEGIN //////////////////////
//////////////////////////////////////////
//////////////////////////////////////////

// Prepare packet headers
static void init_response(struct avctp_header *header)
{
	header->ipid = 0;
	header->cr = AVCTP_RESPONSE_FRAME;
	header->packet_type = PACKET_TYPE_SINGLE;
}

static int init_uinput()
{
	int fd, i;
	struct uinput_user_dev dev = {
		.id = {
		.bustype = BUS_BLUETOOTH,
		.version = 0x0001,
		}
	};

	if ((fd = open(UINPUT_DEVICE, O_WRONLY)) < 0) {
		perror("Cannot open " UINPUT_DEVICE);
		goto shutdown;
	}

	if (write(fd, &dev, sizeof(dev)) < sizeof(dev)) {
		perror("Cannot create a uinput device");
		goto release;
	}

	if (ioctl(fd, UI_SET_EVBIT, EV_KEY))
		goto release;

	for (i = 0; i <= KEY_MAX; i++)
		if (ioctl(fd, UI_SET_KEYBIT, i))
			goto release;
	if (ioctl(fd, UI_DEV_CREATE))
		goto release;

	uinput_fd = fd;

	return 0;
release:
	ioctl(fd, UI_DEV_DESTROY);
shutdown:
	close(fd);
	return 1;
}

static void kill_uinput()
{
	if (uinput_fd == -1)
		return;

	ioctl(uinput_fd, UI_DEV_DESTROY);
	close(uinput_fd);
}

static void send_key(unsigned short code)
{
	struct input_event ev = {
		.type = EV_KEY,
		.code = code,
		.time = {0,}
	};

	if (uinput_fd == -1)
		return;

	if (code > KEY_MAX)
		return;

	ev.value = 1;		// press...
	write(uinput_fd, &ev, sizeof(ev));

	ev.value = 0;		// then release
	write(uinput_fd, &ev, sizeof(ev));
}

// This function handle the bluetooth connection
int a2dp_handle_avrcp_message(int sockfd)
{
	char lpFrame[A2DPMAXIMUMTRANSFERUNITSIZE];
	int iReceived = recv(sockfd, lpFrame, sizeof(lpFrame), 0);
	if (iReceived > 0) {
		struct avc_frame frame = *((struct avc_frame *) lpFrame);

		// Handle message
		if (frame.ctype == CMD_PASSTHROUGH) {
			switch (frame.operand0) {
			case PLAY_OP:
				printf("[play] %s\n", g_sCmdPlay);
				if (g_sCmdPlay[0])
					async_run_process(g_sCmdPlay);
				else
					send_key(KEY_PLAY);
				break;
			case PAUSE_OP:
				printf("[pause] %s\n", g_sCmdPause);
				if (g_sCmdPause[0])
					async_run_process(g_sCmdPause);
				else
					send_key(KEY_PAUSE);
				break;
			case NEXT_OP:
				printf("[next] %s\n", g_sCmdNext);
				if (g_sCmdNext[0])
					async_run_process(g_sCmdNext);
				else
					send_key(KEY_NEXTSONG);
				break;
			case PREV_OP:
				printf("[previous] %s\n", g_sCmdPrev);
				if (g_sCmdPrev[0])
					async_run_process(g_sCmdPrev);
				else
					send_key(KEY_PREVIOUSSONG);
				break;
			default:
				printf("received passthrough %d bytes:\n", iReceived);
				//dump_packet(&frame, iReceived);
			}
		} else {
			printf("received %d bytes:\n", iReceived);
			//dump_packet(&frame, iReceived);
		}
		// Send response
		if (iReceived > 0) {
			if (frame.ctype == CMD_ACCEPTED) {
				printf("(ack)\n");
			} else if (frame.ctype == CMD_PASSTHROUGH) {
				init_response(&frame.header);
				frame.ctype = CMD_ACCEPTED;
				write(sockfd, &frame, iReceived);
			} else {
				printf("only passthrough ctype command is implemented. doh!\n");
				// ierk!!! exit(0);
			}
		}
	} else {
		if (errno != EAGAIN)
			perror("AVRCP Receive failed");
	}

	return iReceived;
}

//////////////////////////////////////////
//////////////////////////////////////////
// AVRCP CODE END ////////////////////////
//////////////////////////////////////////
//////////////////////////////////////////

// if 1 then quit gently
static sig_atomic_t bSigINTReceived = 0;

// count the number of client running
static sig_atomic_t iThreadsRunning = 0;

#define max(x,y) ((x)>(y)?(x):(y))

// Data used to mix audio
typedef struct {
	void* lpVoid;
	uint32_t index_to_construct;
	uint32_t index_0;
	uint32_t size;
} CONVERTBUFFER;

typedef struct {
	int len;
	char* buf;
} RINGINFO;

// Data used to mix audio
typedef struct {
	int lives;
	pthread_mutex_t mutex;
	CONVERTBUFFER conv;
	int ring_in;
	int ring_out;
	RINGINFO ring[MAXCLIENTSRINGSIZE];
} BTA2DPPERCLIENTDATA;

// Data to keep per Bluetooth device
typedef struct {
	char addr[20];
	char plug[20];
	pthread_t thread;
	pthread_t receiverthread;
	pthread_mutex_t mutex;
	AUDIOMIXERDATA mixer;
	int nb_clients;
	int bredirectalsa;
	int a2dp_rate;
	int a2dp_channels;
	int a2dp_bitspersample;
	int sbcbitpool;
	BTA2DPPERCLIENTDATA clients[MAXCLIENTSPERDEVICE];
} BTA2DPPERDEVICEDATA, *LPBTA2DPPERDEVICEDATA;

// Data needed per Audio Streaming Client
typedef struct {
	LPBTA2DPPERDEVICEDATA lpDevice;
	int sockfd;
	pthread_t thread;
} A2DPDCLIENT, *LPA2DPDCLIENT;

// Allocate a new device
LPBTA2DPPERDEVICEDATA bta2dpdevicenew(char *addr)
{
	int i = 0;
	LPBTA2DPPERDEVICEDATA lpDevice = mymalloc(sizeof(BTA2DPPERDEVICEDATA));
	if (lpDevice) {
		memset(lpDevice, 0, sizeof(BTA2DPPERDEVICEDATA));
		strncpy(lpDevice->addr, addr, sizeof(lpDevice->addr));
		lpDevice->addr[sizeof(lpDevice->addr) - 1] = 0;
		lpDevice->mixer.volume_speaker_left = A2DPD_VOLUME_MAX;
		lpDevice->mixer.volume_speaker_right = A2DPD_VOLUME_MAX;
		lpDevice->mixer.volume_micro_left = A2DPD_VOLUME_MAX;
		lpDevice->mixer.volume_micro_right = A2DPD_VOLUME_MAX;
		pthread_mutex_init(&lpDevice->mutex, NULL);
		for (i = 0; i < MAXCLIENTSPERDEVICE; i++) {
			pthread_mutex_init(&lpDevice->clients[i].mutex, NULL);
		}
	}
	return lpDevice;
}

// Free a device
void bta2dpdevicefree(LPBTA2DPPERDEVICEDATA lpDevice)
{
	int i = 0;
	if (lpDevice) {
		for (i = 0; i < MAXCLIENTSPERDEVICE; i++) {
			pthread_mutex_destroy(&lpDevice->clients[i].mutex);
		}
		pthread_mutex_destroy(&lpDevice->mutex);
		safefree(lpDevice);
	}
}

// handle sigterm to terminate properly
void sigint_handler(int sig)
{
	// User wants to force quit
	if (bSigINTReceived == 1) {
		printf("handling SIGINT again: exit forced\n");
		exit(0);
	} else {
		// Now we must quit properly
		bSigINTReceived = 1;
		printf("handling SIGINT\n");

		// Dummy connection to unlock server (currently accepting)
		close_socket(make_client_socket());
	}
}

// This function append data received from a client to the device ring buffer
void append_to_ring_buffer(BTA2DPPERCLIENTDATA* lpClientData, CONVERTBUFFER* lpConvert)
{
	if(lpConvert->lpVoid != NULL) {
		// Enqueue in bluetooth headset if we can else loose packet
		pthread_mutex_lock(&lpClientData->mutex);
	
		// Append data to ring
		int this_ring = lpClientData->ring_in;
		int next_ring = ((this_ring + 1) % MAXCLIENTSRINGSIZE);

		if (next_ring != lpClientData->ring_out) {
			lpClientData->ring[this_ring].buf = lpConvert->lpVoid;
			lpClientData->ring[this_ring].len = lpConvert->size;
			lpClientData->ring_in = next_ring;
			// We will not free that buffer, it's the bthandler thread which will do it
			lpConvert->lpVoid = NULL;
			lpConvert->size = 0;
			lpConvert->index_to_construct = 0;
			lpConvert->index_0 = 0;
		}

		pthread_mutex_unlock(&lpClientData->mutex);
	}
	// Reintegrate data in pool if not transmitted via bthandler thread
	safefree(lpConvert->lpVoid);
}

// Convert individual sample
void convert_sample(AUDIOSTREAMINFOS* lpStreamInfos, void* lpSample, void* lpConvertedSample, BTA2DPPERDEVICEDATA* lpDevice)
{
	// Signed 32bits pivot
	int32_t channel_1=0;
	int32_t channel_2=0;
	// Convert to pivot format
	if(lpStreamInfos->channels==1) {
		if(lpStreamInfos->format==A2DPD_PCM_FORMAT_S8) {
			channel_1 = (*(((int8_t*)lpSample)+0))*256;
			channel_2 = (*(((int8_t*)lpSample)+0))*256;
		} else if(lpStreamInfos->format==A2DPD_PCM_FORMAT_U8) {
			channel_1 = ((*(((int8_t*)lpSample)+0))-(int)128)*256;
			channel_2 = ((*(((int8_t*)lpSample)+0))-(int)128)*256;
		} else if(lpStreamInfos->format==A2DPD_PCM_FORMAT_S16_LE) {
			channel_1 = *(((int16_t*)lpSample)+0);
			channel_2 = *(((int16_t*)lpSample)+0);
		}
	} else if(lpStreamInfos->channels==2) {
		if(lpStreamInfos->format==A2DPD_PCM_FORMAT_S8) {
			channel_1 = (*(((int8_t*)lpSample)+0))*256;
			channel_2 = (*(((int8_t*)lpSample)+1))*256;
		} else if(lpStreamInfos->format==A2DPD_PCM_FORMAT_U8) {
			channel_1 = ((*(((int8_t*)lpSample)+0))-(int)128)*256;
			channel_2 = ((*(((int8_t*)lpSample)+1))-(int)128)*256;
		} else if(lpStreamInfos->format==A2DPD_PCM_FORMAT_S16_LE) {
			channel_1 = *(((int16_t*)lpSample)+0);
			channel_2 = *(((int16_t*)lpSample)+1);
		}
	} else {
		if(lpStreamInfos->format==A2DPD_PCM_FORMAT_S8) {
			channel_1 = (*(((int8_t*)lpSample)+0))*256;
			channel_2 = (*(((int8_t*)lpSample)+1))*256;
		} else if(lpStreamInfos->format==A2DPD_PCM_FORMAT_U8) {
			channel_1 = ((*(((int8_t*)lpSample)+0))-(int)128)*256;
			channel_2 = ((*(((int8_t*)lpSample)+1))-(int)128)*256;
		} else if(lpStreamInfos->format==A2DPD_PCM_FORMAT_S16_LE) {
			channel_1 = *(((int16_t*)lpSample)+0);
			channel_2 = *(((int16_t*)lpSample)+1);
		}
	}

	// Convert to destination format
	if(lpDevice->a2dp_channels==1) {
		if(lpDevice->a2dp_bitspersample==1) {
			*(int8_t*)lpConvertedSample=(channel_1+channel_2)/(2*256);
		} else if(lpDevice->a2dp_bitspersample==2) {
			*(int16_t*)lpConvertedSample=(channel_1+channel_2)/(2);
		}
	} else if(lpDevice->a2dp_channels==2) {
		if(lpDevice->a2dp_bitspersample==1) {
			*(((int8_t*)lpConvertedSample)+0)=channel_1/256;
			*(((int8_t*)lpConvertedSample)+1)=channel_2/256;
		} else if(lpDevice->a2dp_bitspersample==2) {
			*(((int16_t*)lpConvertedSample)+0)=channel_1;
			*(((int16_t*)lpConvertedSample)+1)=channel_2;
		}
	} else {
		memset(lpConvertedSample, 0, lpDevice->a2dp_bitspersample*lpDevice->a2dp_channels);
		if(lpDevice->a2dp_bitspersample==1) {
			*(((int8_t*)lpConvertedSample)+0)=channel_1/256;
			*(((int8_t*)lpConvertedSample)+1)=channel_2/256;
		} else if(lpDevice->a2dp_bitspersample==2) {
			*(((int16_t*)lpConvertedSample)+0)=channel_1;
			*(((int16_t*)lpConvertedSample)+1)=channel_2;
		}
	}
}

// This function convert a buffer to sample rate and format needed for device
void convert_rate(BTA2DPPERDEVICEDATA* lpDevice, BTA2DPPERCLIENTDATA* lpClientData, void* pcm_buffer, int pcm_buffer_size, AUDIOSTREAMINFOS* lpStreamInfos)
{
	// We need this structure accross calls
	CONVERTBUFFER* lpConvert = &lpClientData->conv;

	if(lpConvert && lpStreamInfos && lpStreamInfos->bitspersample) {
		unsigned int pcm_buffer_index = 0;
		unsigned int pcm_buffer_index_0 = 0;
		unsigned int pcm_buffer_frame_bytes = (lpStreamInfos->channels*lpStreamInfos->bitspersample);
		unsigned int pcm_buffer_nframes = pcm_buffer_size/pcm_buffer_frame_bytes;
		unsigned int rate_multiplier = ((unsigned int)lpStreamInfos->rate)*256 / ((unsigned int)lpDevice->a2dp_rate);
		unsigned int convert_frame_bytes = (lpDevice->a2dp_channels*lpDevice->a2dp_bitspersample);
		void* lpConvertedSample = mymalloc(convert_frame_bytes);
		void* lpSample = NULL;
		//int i;

		lpConvert->index_0 = lpConvert->index_to_construct;
		lpConvert->index_to_construct = 0;
		while(pcm_buffer_index<pcm_buffer_nframes) {
			// Allocate destination if needed
			if(lpConvert->lpVoid==NULL) {
				lpConvert->lpVoid = mymalloc(POOLENTRYSIZE);
				lpConvert->size = POOLENTRYSIZE;
				/*
				for(i=0; i<lpConvert->size; i++)
				{
					((char*)lpConvert->lpVoid)[i]=(char)0xFA;
				}
				*/
				lpConvert->index_to_construct = 0;
				lpConvert->index_0 = 0;
			}

			// Get pointer to sample to convert
			lpSample = pcm_buffer+(pcm_buffer_index*pcm_buffer_frame_bytes);

			// Conversion of individual samples
			convert_sample(lpStreamInfos, lpSample, lpConvertedSample, lpDevice);

			// Append converted sample to constructed blocks, Can be avoided by converting in destination buffer
			void* lpDest = lpConvert->lpVoid+((lpConvert->index_0+lpConvert->index_to_construct)*convert_frame_bytes);
			memcpy(lpDest, lpConvertedSample, convert_frame_bytes);

			// Fill next index
			lpConvert->index_to_construct++;

			// The index to fill will be mapped according to rates
			pcm_buffer_index = pcm_buffer_index_0 + ((lpConvert->index_to_construct*rate_multiplier)/256);

			// If constructed block is full, enqueue and allocate new
			if(((lpConvert->index_0+lpConvert->index_to_construct)*convert_frame_bytes)>=lpConvert->size) {
				/*
				if(checkbuffer(lpConvert->lpVoid))
				{
					printf("Buffer overflow: %d,%d\n", lpConvert->index_0+lpConvert->index_to_construct, POOLENTRYSIZE/convert_frame_bytes);
				}
				int state=0;
				int count=0;
				int total=0;
				for(i=0; i<lpConvert->size/2; i+=2) {
					if(state==0) {
						//printf("%08X | %08X   %d | %d\n", ((int16_t*)lpConvert->lpVoid)[i], ((int16_t*)lpConvert->lpVoid)[i+1], ((int16_t*)lpConvert->lpVoid)[i], ((int16_t*)lpConvert->lpVoid)[i+1]);
						if(((int16_t*)lpConvert->lpVoid)[i]==(int16_t)0xFAFA) {
							state=1;
							count++;
							total++;
						} else {
							state=0;
						}
					} else if(state==1) {
						if(((int16_t*)lpConvert->lpVoid)[i]==(int16_t)0xFAFA) {
							count++;
							total++;
						} else {
							//printf("Gap in the data %d,%d\n", count, i);
							state=0;
							count=0;
						}
					}
				}
				if(state==1) {
					printf("Gap in the data: %d, total=%d\n", count, total);
				}
				//exit(0);
				*/

				// Enqueue in ring buffer
				append_to_ring_buffer(lpClientData, lpConvert);

				// Store next index to read
				pcm_buffer_index_0 = pcm_buffer_index;
				pcm_buffer_index = pcm_buffer_index_0;
			}
		}

		safefree(lpConvertedSample);
	}
}

// This function convert a buffer to sample rate and format needed for device
void convert_rateX(BTA2DPPERDEVICEDATA* lpDevice, BTA2DPPERCLIENTDATA* lpClientData, void* pcm_buffer, int pcm_buffer_size, AUDIOSTREAMINFOS* lpStreamInfos)
{
	// We need this structure accross calls
	CONVERTBUFFER* lpConvert = &lpClientData->conv;

	if(lpConvert && lpStreamInfos && lpStreamInfos->bitspersample) {
		unsigned int pcm_buffer_index = 0;
//		unsigned int pcm_buffer_index_0 = 0;
		unsigned int pcm_buffer_frame_bytes = (lpStreamInfos->channels*lpStreamInfos->bitspersample);
		unsigned int pcm_buffer_nframes = pcm_buffer_size/pcm_buffer_frame_bytes;
		//unsigned int rate_multiplier = ((unsigned int)lpStreamInfos->rate)*256 / ((unsigned int)lpDevice->a2dp_rate);
		unsigned int convert_frame_bytes = (lpDevice->a2dp_channels*lpDevice->a2dp_bitspersample);
		int convert_nframes = POOLENTRYSIZE/convert_frame_bytes;
		ReSampleContext* ctx = audio_resample_init(lpDevice->a2dp_channels, lpStreamInfos->channels, lpDevice->a2dp_rate, lpStreamInfos->rate);

		// We must convert pcm_buffer
		while(pcm_buffer_index<pcm_buffer_nframes) {
			printf("Converting: idx=%d, ctx=%d\n", pcm_buffer_index, lpConvert->index_0);
			int nframes_to_convert = 0;
			if(lpConvert->lpVoid==NULL) {
				lpConvert->size = POOLENTRYSIZE;
				lpConvert->lpVoid = mymalloc(POOLENTRYSIZE);
				lpConvert->index_0 = 0;
				lpConvert->index_to_construct = 0;
			}
			#define min(x,y) ((x)<(y)?(x):(y))
			nframes_to_convert = min((convert_nframes-lpConvert->index_0),(pcm_buffer_nframes*lpDevice->a2dp_rate/lpStreamInfos->rate));
			nframes_to_convert = nframes_to_convert*lpStreamInfos->rate/lpDevice->a2dp_rate;
			
			int converted = audio_resample(ctx, lpConvert->lpVoid+(lpConvert->index_0*convert_frame_bytes), pcm_buffer, nframes_to_convert);
			printf("Converted: %d frames to %d (%d)\n", nframes_to_convert, converted, (nframes_to_convert*lpDevice->a2dp_rate/lpStreamInfos->rate));
			lpConvert->index_0 += converted;
			if(lpConvert->index_0 >= convert_nframes) {
				append_to_ring_buffer(lpClientData, lpConvert);
			}

			pcm_buffer_index += nframes_to_convert;
		}

		audio_resample_close(ctx);
	}
}

// This function manage volume change wanted by clients
void a2dpd_plugin_ctl_write(LPA2DPDCLIENT lpClient)
{
	AUDIOMIXERDATA AudioMixerData = INVALIDAUDIOMIXERDATA;

	printf("CTL WRITE thread %d started\n", lpClient->sockfd);

	if (recv_socket(lpClient->sockfd, &AudioMixerData, sizeof(AudioMixerData)) == sizeof(AudioMixerData)) {
		pthread_mutex_lock(&lpClient->lpDevice->mutex);
		if (AudioMixerData.volume_speaker_left != -1)
			lpClient->lpDevice->mixer.volume_speaker_left = AudioMixerData.volume_speaker_left;
		if (AudioMixerData.volume_speaker_left != -1)
			lpClient->lpDevice->mixer.volume_speaker_right = AudioMixerData.volume_speaker_right;
		if (AudioMixerData.volume_micro_left != -1)
			lpClient->lpDevice->mixer.volume_micro_left = AudioMixerData.volume_micro_left;
		if (AudioMixerData.volume_micro_left != -1)
			lpClient->lpDevice->mixer.volume_micro_right = AudioMixerData.volume_micro_right;
		pthread_mutex_unlock(&lpClient->lpDevice->mutex);
		// Notify other clients
		int notifyfd = make_udp_socket();
		send_socket(notifyfd, &AudioMixerData, sizeof(AudioMixerData));
		close_socket(notifyfd);
	}
}

// This function manage volume read for client
void a2dpd_plugin_ctl_read(LPA2DPDCLIENT lpClient)
{
	AUDIOMIXERDATA AudioMixerData = INVALIDAUDIOMIXERDATA;
	printf("CTL READ thread %d started\n", lpClient->sockfd);

	pthread_mutex_lock(&lpClient->lpDevice->mutex);
	AudioMixerData = lpClient->lpDevice->mixer;
	pthread_mutex_unlock(&lpClient->lpDevice->mutex);

	send_socket(lpClient->sockfd, &AudioMixerData, sizeof(AudioMixerData));
}

// This function manage pcm streams sent by clients
int a2dpd_plugin_pcm_write(LPA2DPDCLIENT lpClient)
{
	int client_index = -1;
	int bError = 0;
	AUDIOSTREAMINFOS StreamInfos = INVALIDAUDIOSTREAMINFOS;

	// Find an index in clients table for the mixer
	pthread_mutex_lock(&lpClient->lpDevice->mutex);
	for (client_index = 0; client_index < MAXCLIENTSPERDEVICE; client_index++) {
		if (lpClient->lpDevice->clients[client_index].lives == 0) {
			// FIXME Not sure this is safe but this is very unlikely to happen
			lpClient->lpDevice->clients[client_index].lives = 1;
			lpClient->lpDevice->clients[client_index].ring_in = 0;
			lpClient->lpDevice->clients[client_index].ring_out = 0;
			break;
		}
	}

	pthread_mutex_unlock(&lpClient->lpDevice->mutex);

	if (client_index >= MAXCLIENTSPERDEVICE) {
		perror("Too many clients");
		return 0;
	}

	if(recv_socket(lpClient->sockfd, &StreamInfos, sizeof(StreamInfos))==sizeof(StreamInfos))
	{
		printf("PCM thread %d.%d started (%d Hz, %d channels, %d bits)\n", client_index, lpClient->sockfd, StreamInfos.rate, StreamInfos.channels, StreamInfos.bitspersample*8);

		// Loop while we receive data
		while (!bSigINTReceived && !bError) {
			// Receive data
			int32_t pcm_buffer_size = 0;
			int result = recv_socket(lpClient->sockfd, &pcm_buffer_size, sizeof(pcm_buffer_size));
			if (result == sizeof(pcm_buffer_size) && pcm_buffer_size <= A2DPD_BLOCK_SIZE) {
				char *pcm_buffer = mymalloc(pcm_buffer_size);
				if(pcm_buffer) {
					/*
					int i;
					for(i = 0; i<pcm_buffer_size; i++)
					{
						pcm_buffer[i]=0xFB;
					}
					*/
					result = recv_socket(lpClient->sockfd, pcm_buffer, pcm_buffer_size);
					if (result <= pcm_buffer_size) {
						// Rate conversion
						convert_rate(lpClient->lpDevice, &lpClient->lpDevice->clients[client_index], pcm_buffer, result, &StreamInfos);
					} else {
						perror("Receiving failed on socket");
						bError = 1;
					}
					/*
					int state=0;
					int count=0;
					int total=0;
					
					for(i=0; i<pcm_buffer_size/2; i+=2) {
						if(state==0) {
							//printf("%08X | %08X   %d | %d\n", ((int16_t*)lpConvert->lpVoid)[i], ((int16_t*)lpConvert->lpVoid)[i+1], ((int16_t*)lpConvert->lpVoid)[i], ((int16_t*)lpConvert->lpVoid)[i+1]);
							if(((int16_t*)pcm_buffer)[i]==(int16_t)0xFAFA) {
								state=1;
								count++;
								total++;
							} else {
								state=0;
							}
						} else if(state==1) {
							if(((int16_t*)pcm_buffer)[i]==(int16_t)0xFAFA) {
								count++;
								total++;
							} else {
								//printf("Gap in the data %d,%d\n", count, i);
								state=0;
								count=0;
							}
						}
					}
					if(state==1) {
						//printf("Gap in the data: %d, total=%d\n", count, total);
					}
					*/
					safefree(pcm_buffer);
				} else {
					perror("Not enough memory");
					bError = 1;
				}
			} else {
				if (result == sizeof(pcm_buffer_size)) {
					perror("Receiving will not fit pool");
				} else {
					perror("Receiving failed");
				}
				bError = 1;
			}
		}
	} else {
		perror("Receiving stream informations failed");
	}

	safefree(lpClient->lpDevice->clients[client_index].conv.lpVoid);

	pthread_mutex_lock(&lpClient->lpDevice->mutex);
	if (client_index >= 0)
		lpClient->lpDevice->clients[client_index].lives = 0;
	pthread_mutex_unlock(&lpClient->lpDevice->mutex);

	printf("Client thread %d ending: %s\n", lpClient->sockfd, (bError ? (errno == EAGAIN ? "timeout" : "error") : "no error"));

	return 0;
}

// This function handles a client
void *client_handler(void *param)
{
	int32_t client_type = INVALID_CLIENT_TYPE;
	LPA2DPDCLIENT lpClient = (LPA2DPDCLIENT) param;

	// We should not terminate the process if clients are still running
	iThreadsRunning++;

	pthread_detach(lpClient->thread);

	setup_socket(lpClient->sockfd);

	// Receive type of client
	recv_socket(lpClient->sockfd, &client_type, sizeof(client_type));

	// This client wants to send us pcm control data
	if (client_type == A2DPD_PLUGIN_CTL_WRITE) {
		a2dpd_plugin_ctl_write(lpClient);
	}
	// This client wants to read our control status
	if (client_type == A2DPD_PLUGIN_CTL_READ) {
		a2dpd_plugin_ctl_read(lpClient);
	}
	// This client wants to send us pcm stream
	if (client_type == A2DPD_PLUGIN_PCM_WRITE) {
		a2dpd_plugin_pcm_write(lpClient);
	}

	// Say goodbye
	pthread_mutex_lock(&lpClient->lpDevice->mutex);
	lpClient->lpDevice->nb_clients--;
	pthread_mutex_unlock(&lpClient->lpDevice->mutex);

	// Close socket
	close_socket(lpClient->sockfd);

	// Free client data
	safefree(lpClient);

	// Decrease thread count
	iThreadsRunning--;

	return 0;
}

/////////////////////////////////
int audio_mixer(void *pcm_buffer, char **pcm_buffers, int *pcm_buffers_size, int vol_left, int vol_right)
/////////////////////////////////
{
	int i, j;
	int satured = 0;

	// Mix audio streams 16 bits stereo channels
	// We require little endianness here
	int pcm_buffer_filed_size = 0;
	for (j = 0; j < POOLENTRYSIZE / 4; j++) {
		int32_t *pBuffer = (int32_t *) pcm_buffer;
		int32_t channel_1 = 0;
		int32_t channel_2 = 0;
		for (i = 0; i < MAXCLIENTSPERDEVICE; i++) {
			int32_t *pBuffers = (int32_t *) (pcm_buffers[i]);
			if (pBuffers != NULL && (j < pcm_buffers_size[i] / 4)) {
				int16_t i1 = *(((int16_t *) (pBuffers + j)) + 0);
				int16_t i2 = *(((int16_t *) (pBuffers + j)) + 1);
				channel_1 += i1;
				channel_2 += i2;
				pcm_buffer_filed_size = max(pcm_buffer_filed_size, pcm_buffers_size[i]);
			}
		}
		//printf("Value %08X|%08X %d|%d\n", channel_1, channel_2, channel_1, channel_2);
		// Stay within 16 bits per channel range
		if (channel_1 > +32767) {
			channel_1 = +32767;
			satured++;
		}
		if (channel_1 < -32768) {
			channel_1 = -32768;
			satured++;
		}
		if (channel_2 > +32767) {
			channel_2 = +32767;
			satured++;
		}
		if (channel_2 < -32768) {
			channel_2 = -32768;
			satured++;
		}

		channel_1 *= vol_left;
		channel_2 *= vol_right;
		// yes this can be rewritten with << if we consider max volume of 2^x
		// Isn't it already done by compiler?
		channel_1 /= A2DPD_VOLUME_MAX;
		channel_2 /= A2DPD_VOLUME_MAX;
		if(g_breversestereo) {
			pBuffer[j] = (((channel_1 & 0x0000FFFF) << 16) | (channel_2 & 0x0000FFFF));
		} else {
			//FIXME We have a reverse stereo I don't know why
			// The following line corrects the problem but I miss the cause so be aware
			pBuffer[j] = (((channel_2 & 0x0000FFFF) << 16) | (channel_1 & 0x0000FFFF));
		}
	}
	return pcm_buffer_filed_size;
}

/////////////////////////////////
// This function handle the bluetooth connection
void *bt_handler(void *param)
/////////////////////////////////
{
	int i;
	// We should not terminate the process if clients are still running
	iThreadsRunning++;

	LPBTA2DPPERDEVICEDATA lpDevice = (LPBTA2DPPERDEVICEDATA) param;
	pthread_detach(lpDevice->thread);

	// As long as daemon is running
	while (!bSigINTReceived) {
		int bError = 0;
		int destroy_count = 0;

		// Connect to the A2DP device
		void *lpA2dp = NULL;
		char *pcm_buffer = mymalloc(POOLENTRYSIZE);
		enum { NOSOUND, SOUND };
		int state_previous = NOSOUND;
		TIMERINFO TimerInfos;
		lpDevice->a2dp_rate = read_config_int(g_srcfilename, "a2dpd", "rate", A2DPD_FRAME_RATE);
		lpDevice->a2dp_channels = read_config_int(g_srcfilename, "a2dpd", "channels", 2);
		lpDevice->a2dp_bitspersample = 16/8;//(read_config_int(g_srcfilename, "a2dpd", "bitspersample", 16))/8;
		lpDevice->sbcbitpool = read_config_int(g_srcfilename, "a2dpd", "sbcbitpool", 32);
		printf("New connection to bluetooth [%d hz, %d channels, %d bits]\n", lpDevice->a2dp_rate, lpDevice->a2dp_channels, lpDevice->a2dp_bitspersample*8);

		// This timer is used to sync bluetooth sound emission
		// This is because not all device have a queue for incoming sample
		// And device who have a queue won't react correctly
		memset(&TimerInfos, 0, sizeof(TimerInfos));
		TimerInfos.fps = (float)(((float) (lpDevice->a2dp_rate*lpDevice->a2dp_channels*lpDevice->a2dp_bitspersample)/((float) POOLENTRYSIZE))/1.0);

		// As long as we can send sound
		while (!bSigINTReceived && !bError) {
			int pcm_buffer_filed_size = 0;
			char *pcm_buffers[MAXCLIENTSPERDEVICE];
			int pcm_buffers_size[MAXCLIENTSPERDEVICE];
			int state_current = NOSOUND;
			memset(pcm_buffers, 0, sizeof(pcm_buffers));
			memset(pcm_buffers_size, 0, sizeof(pcm_buffers_size));

			// If there are BT data, send them
			//FIXME Since we read nb_clients, we should lock mutex, but it may create timer issues
			// degrading sound
			// pthread_mutex_lock(&lpDevice->mutex);

			if (lpDevice->nb_clients > 0) {
				// Retrieve data for client where it is available
				for (i = 0; i < MAXCLIENTSPERDEVICE; i++) {
					if (lpDevice->clients[i].lives) {
						pthread_mutex_lock(&lpDevice->clients[i].mutex);

						if (lpDevice->clients[i].ring_in != lpDevice->clients[i].ring_out) {
							// Get ring buffer
							pcm_buffers[i] = lpDevice->clients[i].ring[lpDevice->clients[i].ring_out].buf;
							pcm_buffers_size[i] = lpDevice->clients[i].ring[lpDevice->clients[i].ring_out].len;
							// Tell client we got them
							lpDevice->clients[i].ring[lpDevice->clients[i].ring_out].buf = NULL;
							lpDevice->clients[i].ring[lpDevice->clients[i].ring_out].len = 0;

							// Move to next ring
							int next_ring = ((lpDevice->clients[i].ring_out + 1) % MAXCLIENTSRINGSIZE);

							//printf("Reading pool %d[ %d] = %p\n", i, lpDevice->clients[i].ring_out, pcm_buffers[i]);

							lpDevice->clients[i].ring_out = next_ring;

							// Remember we got some sound
							state_current = SOUND;
						}

						pthread_mutex_unlock(&lpDevice->clients[i].mutex);
					}
				}
			}
			//FIXME 
			// pthread_mutex_unlock(&lpDevice->mutex);

			// Send mixed audio stream to clients
			switch (state_current) {
			case SOUND:
				pcm_buffer_filed_size = audio_mixer(pcm_buffer, pcm_buffers, pcm_buffers_size, lpDevice->mixer.volume_speaker_left, lpDevice->mixer.volume_speaker_right);

				// Free no longer used audio blocks
				for (i = 0; i < MAXCLIENTSPERDEVICE; i++) {
					if (pcm_buffers[i]) {
						// Reintegrate data where they come from
						safefree(pcm_buffers[i]);
					}
				}

				/////////////////////////////////
				// Transfer data to bluetooth
				/////////////////////////////////

				if (pcm_buffer && pcm_buffer_filed_size > 0) {
					// Transfer takes place by POOLENTRYSIZE bytes blocks
					int blockstart = 0;
					int blocksize = POOLENTRYSIZE;

					// Allocate A2DP if we are not connected
					if (!lpA2dp) {
						// Select the good device
						lpDevice->bredirectalsa = read_config_int(g_srcfilename, "a2dpd", "enableredirectalsa", 0);
						read_config_string(g_srcfilename, "a2dpd", "address", lpDevice->addr, sizeof(lpDevice->addr), "");
						read_config_string(g_srcfilename, "a2dpd", "alsaoutput", lpDevice->plug, sizeof(lpDevice->plug), "");
						// Allocate it
						if (lpDevice->bredirectalsa) {
							lpA2dp = alsa_new(lpDevice->plug, lpDevice->a2dp_rate);
						} else {
							A2DPSETTINGS settings;
							memset(&settings, 0, sizeof(settings));
							strncpy(settings.bdaddr, lpDevice->addr, sizeof(settings.bdaddr)-1);
							settings.framerate=lpDevice->a2dp_rate;
							settings.channels=lpDevice->a2dp_channels;
							settings.sbcbitpool=lpDevice->sbcbitpool;
							lpA2dp = a2dp_new(&settings);
						}
						// Do not spin if connection failed, this appear if no bluetooth device is installed
						if(!lpA2dp) {
							sleep(1);
						}
						g_nbdeviceconnected++;
						destroy_count = 0;
					}

					if (lpA2dp) {
						// Send data to BT headset
						while (!bError && blockstart < pcm_buffer_filed_size) {
							int transfer;

							blocksize = (pcm_buffer_filed_size < POOLENTRYSIZE) ? pcm_buffer_filed_size : POOLENTRYSIZE;

							if (lpDevice->bredirectalsa)
								transfer = alsa_transfer_raw(lpA2dp, pcm_buffer + blockstart, blocksize);
							else
								transfer = a2dp_transfer_raw(lpA2dp, pcm_buffer + blockstart, blocksize);

							if (transfer >= 0) {
								destroy_count = 0;
								blockstart += transfer;
								a2dp_timer_notifyframe(&TimerInfos);
							} else {
								printf("Error in a2dp_transfer_raw\n");
								bError = 1;
							}
						}
					}
				}
				break;
			case NOSOUND:
				if (state_previous == SOUND) {
					//printf("Sound stream ran dry!!!\n");
				}
				break;
			}

			// Wait must take place after sending a packet
			// This way, you will allow the plugin to send it's data
			// And you will collect the new data
			// Time reference floating because of 44100/1000 error in integer calculation
			a2dp_timer_sleep(&TimerInfos, A2DPTIMERPREDELAY);

			// Read config file changes each second
			if (TimerInfos.display > 0) {
				if(g_brereadconfig) {
					char addr[20];
					char plug[20];
					int bredirectalsa = read_config_int(g_srcfilename, "a2dpd", "enableredirectalsa", 0);
					read_config_string(g_srcfilename, "a2dpd", "address", addr, sizeof(addr), "");
					read_config_string(g_srcfilename, "a2dpd", "alsaoutput", plug, sizeof(plug), "");
					if((strcmp(addr, lpDevice->addr) != 0) || (strcmp(plug, lpDevice->plug) != 0) || (bredirectalsa != lpDevice->bredirectalsa)) {
						// Force destroy, device will be recreated upon audio incoming
						destroy_count=10000;
					}
				}
				/*
				char* lpszFormat = "A2DPD: [%d,%d|%d,%d] %s %s clients=%d freq=%d[%d b/s] sleep=%d satur=%d\n";
				if(satured==0) lpszFormat = "A2DPD: [%d,%d|%d,%d] %s %s clients=%d freq=%d[%d b/s]\n";
				printf(lpszFormat, 
				lpDevice->mixer.volume_speaker_left,
				lpDevice->mixer.volume_speaker_right,
				lpDevice->mixer.volume_micro_left,
				lpDevice->mixer.volume_micro_right,
				(state_current==SOUND)?"playing":"silent",
				lpA2dp?"connected":"disconnected", lpDevice->nb_clients, TimerInfos.display,
				satured);
				// Reset all variables used
				satured=0;
				*/
			}

			// Free the A2DP device if needed
			// When destroy_count reaches 2000 we will destroy the A2DP link
			// However, destroy_count is reset whenever data are sent
			destroy_count++;
			if (lpA2dp && destroy_count > 2000) {
				printf("Destroying lpA2dp, destroy_count is %d\n", destroy_count);
				g_nbdeviceconnected--;
				if (lpDevice->bredirectalsa)
					alsa_destroy(lpA2dp);
				else
					a2dp_destroy(lpA2dp);
				lpA2dp = NULL;
			}

			state_previous = state_current;
		}
		safefree(pcm_buffer);

		// Sleep a little bit before retrying
		if (!bSigINTReceived)
			sleep(1);

		// Free A2DP
		if (lpA2dp) {
			printf("Destroying lpA2dp, end of loop\n");
			g_nbdeviceconnected--;
			if (lpDevice->bredirectalsa)
				alsa_destroy(lpA2dp);
			else
				a2dp_destroy(lpA2dp);
			lpA2dp = NULL;
		}
	}

	iThreadsRunning--;

	return 0;
}

// This function handle the bluetooth connection
void *avdtp_listener(void *param)
{
	// We should not terminate the process if clients are still running
	iThreadsRunning++;

	LPBTA2DPPERDEVICEDATA lpDevice = (LPBTA2DPPERDEVICEDATA) param;
	pthread_detach(lpDevice->thread);

	// As long as daemon is running
	printf("avdtp: Accepting incoming connection\n");
	while (!bSigINTReceived) {
		int sockfd = a2dp_make_listen_socket(25);
		if (sockfd >= 0) {
			while (!bSigINTReceived) {
				// Wait for incoming connections
				char szRemote[64];
				uint16_t iMTU = 0;

				int new_fd = a2dp_wait_connection(sockfd, szRemote, sizeof(szRemote), &iMTU);

				if (new_fd > 0) {
					printf("avdtp: socket %d: Connection from %s, mtu=%d\n", new_fd, szRemote, iMTU);

					// Loop and manage what the client sends
					setup_socket(new_fd);
					int iReceived = 0;
					int play = 0;
					int count = 0;
					do {
						iReceived = a2dp_handle_avdtp_message(NULL, new_fd, NULL, NULL, 0);
						if (iReceived == 0) {
							printf("avdtp: socket %d: Received frame, start %s\n", new_fd, g_sCmdNew);
							play = 1;
							count = 0;
							break;
						} else if (iReceived < 0) {
							if (errno != EAGAIN)
								perror("avdtp: Received failed");
						}
						count++;
					}
					// AVDTP do not need to have a device connected, since it can establish device connection
					while (!bSigINTReceived && (iReceived >= 0 || errno == EAGAIN)
					&& count < 10);
					printf("avdtp: socket %d: timed out\n", new_fd);
					close_socket(new_fd);

					if (play && g_sCmdNew[0]) {
						async_run_process(g_sCmdNew);
					}
				} else {
					if (errno != EAGAIN) {
						perror("avdtp: a2dp_wait_connection failed");
						break;
					}
				}
			}

			close_socket(sockfd);
		}
		// Sleep a little bit if we must retry
		sleep(bSigINTReceived ? 1 : 0);
	}

	iThreadsRunning--;

	return 0;
}

// This function handle the bluetooth connection
void *avrcp_listener(void *param)
{
	// We should not terminate the process if clients are still running
	iThreadsRunning++;

	LPBTA2DPPERDEVICEDATA lpDevice = (LPBTA2DPPERDEVICEDATA) param;
	pthread_detach(lpDevice->thread);

	// As long as daemon is running
	printf("avrcp: Accepting incoming connection\n");
	while (!bSigINTReceived) {
		int sockfd = a2dp_make_listen_socket(23);
		if (sockfd >= 0) {
			while (!bSigINTReceived) {
				// Wait for incoming connections
				char szRemote[64];
				uint16_t iMTU = 0;

				int new_fd = a2dp_wait_connection(sockfd, szRemote,
								sizeof(szRemote),
								&iMTU);

				if (new_fd > 0) {
					printf("avrcp: socket %d: Connection from %s, mtu=%d\n", new_fd, szRemote, iMTU);
					// Loop and manage what the client sends
					setup_socket(new_fd);
					int iReceived = 0;
					do {
						errno = 0;
						iReceived = a2dp_handle_avrcp_message(new_fd);
					}
					while (!bSigINTReceived && (iReceived > 0 || errno == EAGAIN));
					printf("avrcp: socket %d: timed out\n", new_fd);
					close_socket(new_fd);
				} else if (errno != EAGAIN) {
					perror("avrcp: a2dp_wait_connection failed");
					break;
				}
			}

			close_socket(sockfd);
		}
		// Sleep a little bit if we must retry
		sleep(bSigINTReceived ? 1 : 0);
	}

	iThreadsRunning--;

	return 0;
}

// server processing loop
void main_loop(char *addr)
{
	while (!bSigINTReceived) {
		// Master socket
		int sockfd = make_server_socket();

		if (sockfd > 0) {
			LPBTA2DPPERDEVICEDATA lpDevice = bta2dpdevicenew(addr);
			// Set pthread stack size to decrease unused memory usage
			pthread_attr_t tattr;
			pthread_t havrcp, havdtp;
			size_t size = PTHREAD_STACK_MIN;
			int ret = pthread_attr_init(&tattr);
			ret = pthread_attr_setstacksize(&tattr, size);
			pthread_create(&lpDevice->thread, &tattr, bt_handler, lpDevice);
			if (g_bavrcp)
				pthread_create(&havrcp, &tattr, avrcp_listener, lpDevice);
			if (g_bavrcp)
				pthread_create(&havdtp, &tattr, avdtp_listener, lpDevice);

			while (!bSigINTReceived) {
				int new_fd = -1;
				new_fd = accept_socket(sockfd);

				// Handle connection if it is not the final dummy client
				if (!bSigINTReceived && new_fd > 0) {
					LPA2DPDCLIENT lpClient = mymalloc(sizeof(A2DPDCLIENT));
					lpClient->lpDevice = lpDevice;
					lpClient->sockfd = new_fd;

					pthread_mutex_lock(&lpClient->lpDevice->mutex);
					lpClient->lpDevice->nb_clients++;
					pthread_mutex_unlock(&lpClient->lpDevice->mutex);

					pthread_create(&lpClient->thread, &tattr, client_handler, lpClient);
				} else if (new_fd > 0) {
					close_socket(new_fd);
				}
				usleep(10000);
			}

			close_socket(sockfd);

			// Very minor race condition here
			// No dramatic consequences
			// But we Must wait all client termination
			// We will pthread_join one day
			int icount = 0;
			while (iThreadsRunning > 0 /*&& icount < 30*/) {
				printf("A2DPD still %d clients running\n", iThreadsRunning);
				icount++;
				sleep(1);
			}

			// Free informations on the device
			bta2dpdevicefree(lpDevice);
			pthread_attr_destroy(&tattr);
		} else {
			perror("a2dpd: Cannot get the socket");
		}

		sleep(1);
	}
}



// main function
int main(int argc, char *argv[])
{
	int i = 0;
	struct timespec timer_resolution = { 0, 0 };
	char address[256] = "";
	char *addr = &address[0];
	char *sonorix = "00:0A:56:00:C0:C2";
	//char* iphono420= "C2:00:08:F4:30:07:64";
	//char* hpheadphone= "00:0D:44:2A:17:C7";
	struct sched_param schedparam = { sched_get_priority_max(SCHED_FIFO) };
	int res = 0, bFork = 0, bVerbose = 1, bKill = 0, fd = 0, bRealtime = 0;
	FILE *fp;
	pid_t pid;

	// Read config values from config file
	get_config_filename(g_srcfilename, sizeof(g_srcfilename));
	read_config_string(g_srcfilename, "a2dpd", "address", address, sizeof(address), sonorix);
	read_config_string(g_srcfilename, "a2dpd", "cmdplay", g_sCmdPlay, sizeof(g_sCmdPlay), "");
	read_config_string(g_srcfilename, "a2dpd", "cmdpause", g_sCmdPause, sizeof(g_sCmdPause), "");
	read_config_string(g_srcfilename, "a2dpd", "cmdprev", g_sCmdPrev, sizeof(g_sCmdPrev), "");
	read_config_string(g_srcfilename, "a2dpd", "cmdnext", g_sCmdNext, sizeof(g_sCmdNext), "");
	read_config_string(g_srcfilename, "a2dpd", "cmdnew", g_sCmdNew, sizeof(g_sCmdNew), "");
	read_config_string(g_srcfilename, "a2dpd", "logfile", g_sOutputFilename, sizeof(g_sOutputFilename), "/dev/null");
	g_brereadconfig = read_config_int(g_srcfilename, "a2dpd", "enablerereadconfig", 1);
	g_breversestereo = read_config_int(g_srcfilename, "a2dpd", "enablereversestereo", 0);
	g_bavrcp = read_config_int(g_srcfilename, "a2dpd", "enableavrcp", 1);

	// Parse command line parameters
	for (i = 1; i < argc && argv[i] != NULL; i++) {
		char c;
		// Search a bluetooth addr
		if (sscanf(argv[i], "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", &c, &c, &c, &c, &c, &c, &c, &c, &c, &c, &c, &c) == 12) {
			addr = argv[i];
		} else if (!strcmp(argv[i], "-n")) {
			bFork = 0;
		} else if (!strcmp(argv[i], "-d")) {
			bFork = 1;
		} else if (!strcmp(argv[i], "-v")) {
			bVerbose = 1;
		} else if (!strcmp(argv[i], "-k")) {
			bKill = 1;
		} else if (!strcmp(argv[i], "+n")) {
			bFork = 1;
		} else if (!strcmp(argv[i], "+d")) {
			bFork = 0;
		} else if (!strcmp(argv[i], "+v")) {
			bVerbose = 0;
		} else if (!strcmp(argv[i], "-r")) {
			bRealtime = 1;
		} else {
			printf("Parameter not handled: %s\r\n", argv[i]);
		}
	}
	clock_getres(CLOCK_REALTIME, &timer_resolution);

	init_uinput();

	ignore_child_processes_return_values();

	// Redirect outputs
	make_daemon_process(bFork, bVerbose, g_sOutputFilename);
	// Generate the lockfile
	fd = open(PIDFILE, O_RDWR | O_CREAT | O_EXCL, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);

	if (fd == -1) {
		if (errno != EEXIST)	// If we can't write the lock, then ignore
			goto post_lock;

		if ((fd = open(PIDFILE, O_RDWR)) < 0)
			goto post_lock;

		fp = fdopen(fd, "rw");
		if (fp == NULL)
			goto post_lock;

		pid = -1;
		if ((fscanf(fp, "%d", &pid) != 1) || (pid == getpid())
		|| (lock_fd(fileno(fp)) == 0)) {
			unlink(PIDFILE);
		} else {
			if (bKill) {
				kill(pid, 15);
				sleep(5);	// let the other daemon die
			} else
				goto shutdown;
		}
		fclose(fp);

		unlink(PIDFILE);
		fd = open(PIDFILE, O_RDWR | O_CREAT | O_EXCL, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);

		if (fd == -1)
			goto post_lock;

	}

	lock_fd(fd);

	fp = fdopen(fd, "w");
	fprintf(fp, "%d\n", getpid());
	fflush(fp);
	fcntl(fd, F_SETFD, (long) 1);

post_lock:
	printf("%s addr=%s timer=%d us [%s %s]\n", argv[0], addr, (int) (timer_resolution.tv_nsec / 1000), __DATE__, __TIME__);

	// If we can be realtime it will be better
	if(bRealtime)
	{
		// After some trouble while developping, a2dpd started spining 100%cpu
		// In realtime, this led me with the only option of rebooting my PC
		res = sched_setscheduler(0, SCHED_FIFO, &schedparam);
		if(res != 0)
			perror("setscheduler failed");
	}
	// set up the handler
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	// global initialisations
	a2dp_init();

	// Run main loop
	main_loop(addr);

	// global termination
	a2dp_exit();

	kill_uinput();

shutdown:
	printf("A2DPD terminated succesfully\n");

	return 0;
}
