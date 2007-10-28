/****************************************************************************
 ** hw_iguanaIR.c ***********************************************************
 ****************************************************************************
 *
 * routines for interfacing with Iguanaworks USB IR devices
 *
 * Copyright (C) 2006, Joseph Dunn <jdunn@iguanaworks.net>
 *
 * Distribute under GPL version 2.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <wait.h>

#include "lircd.h"
#include "ir_remote_types.h"

#include "iguanaIR.h"

#include "hardware.h"
#include "transmit.h"
#include "receive.h"

static int iguana_init();
static int iguana_deinit();
static char *iguana_rec(struct ir_remote *remotes);
static int iguana_send(struct ir_remote *remote,struct ir_ncode *code);
static int sendConn = -1;
static pid_t child = 0;
static int recvDone = 0;

static lirc_t readdata(lirc_t timeout)
{
	lirc_t code = 0;
	struct timeval tv = {0, timeout};
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(hw.fd, &fds);

	/* attempt a read with a timeout using select */
	if (select(hw.fd + 1, &fds, NULL, &fds, &tv) > 0)
		/* if we failed to get data return 0 */
		if (read(hw.fd, &code, sizeof(lirc_t)) <= 0)
			code = 0;

	return code;
}

struct hardware hw_iguanaIR =
{
	"0",				/* default device */
	-1,				/* fd */
	LIRC_CAN_REC_MODE2 | 
		LIRC_CAN_SEND_PULSE,	/* features */
	LIRC_MODE_PULSE,		/* send_mode */
	LIRC_MODE_MODE2,		/* rec_mode */
	sizeof(int),			/* code_length */
	iguana_init,			/* init_func */
	NULL,				/* config_func */
	iguana_deinit,			/* deinit_func */
	iguana_send,			/* send_func */
	iguana_rec,			/* rec_func */
	receive_decode,			/* decode_func */
	NULL,				/* ioctl_func */
	readdata,			/* readdata */
	"iguanaIR"
};

static void quitHandler(int sig)
{
	recvDone = 1;
}

static void recv_loop(int fd)
{
	int conn;

	alarm(0);
	signal(SIGTERM, quitHandler);
	/*    signal(SIGPIPE, SIG_DFL);*/
	signal(SIGINT, quitHandler);
	signal(SIGHUP, SIG_IGN);
	signal(SIGALRM, SIG_IGN);

	conn = iguanaConnect(hw.device);
	if (conn != -1)
	{
		iguanaPacket request, response;
		lirc_t prevCode = -1;

		request = iguanaCreateRequest(IG_DEV_RECVON, 0, NULL);
		if (iguanaWriteRequest(request, conn))
			while(! recvDone)
			{
				/* read from device */
				response = iguanaReadResponse(conn, 1000);

				/* this will be the exit condition */
				if (response == NULL)
					continue;
				else if (iguanaResponseIsError(response))
				{
					logprintf(LOG_ERR,
						  "error response: %s\n", strerror(errno));
					break;
				}
				else if (iguanaCode(response) == IG_DEV_RECV)
				{
					uint32_t *code;
					unsigned int length, x, y = 0;
					lirc_t buffer[8]; /* we read 8 bytes max at a time
							   * from the device, i.e. packet
							   * can only contain 8
							   * signals. */

					/* pull the data off the packet */
					code = iguanaRemoveData(response, &length);
					length /= sizeof(uint32_t);

					/* translate the code into lirc_t pulses (and make
					 * sure they don't split across iguana packets. */
					for(x = 0; x < length; x++)
					{
						if (prevCode == -1)
						{
							prevCode = (code[x] & IG_PULSE_MASK);
							if(prevCode > PULSE_MASK) prevCode = PULSE_MASK;
							if(code[x] & IG_PULSE_BIT) prevCode |= PULSE_BIT;
						}
						else if (((prevCode & PULSE_BIT) && (code[x]  & IG_PULSE_BIT)) ||
							 (!(prevCode & PULSE_BIT) && !(code[x]  & IG_PULSE_BIT)))
						{
							/* can overflow pulse mask, so just set to
							 * largest possible */
							if ((prevCode & PULSE_MASK) + (code[x] & IG_PULSE_MASK) >
							    PULSE_MASK)
								prevCode = (prevCode & PULSE_BIT) | PULSE_MASK;
							else
								prevCode += code[x] & IG_PULSE_MASK;
						}
						else
						{
							buffer[y] = prevCode;
							y++;

							prevCode = (code[x] & IG_PULSE_MASK);
							if(prevCode > PULSE_MASK) prevCode = PULSE_MASK;
							if(code[x] & IG_PULSE_BIT) prevCode |= PULSE_BIT;
						}
					}

					/* write the data and free it */
					if (y > 0)
						write(fd, buffer, sizeof(lirc_t) * y);
					free(code);
				}

				iguanaFreePacket(response);
			}

		iguanaFreePacket(request);
	}

	iguanaClose(conn);
	close(fd);
}

int iguana_init()
{
	int recv_pipe[2], retval = 0;

	init_rec_buffer();

	if (pipe(recv_pipe) != 0)
        {
		logprintf(LOG_ERR, "couldn't open pipe: %s", strerror(errno));
        }
	else
	{
		hw.fd = recv_pipe[0];

		child = fork();
		if (child == -1)
		{
			logprintf(LOG_ERR, "couldn't fork child process: %s", strerror(errno));
		}
		else if (child == 0)
		{
			recv_loop(recv_pipe[1]);
			exit(0);
		}
		else
		{
			sendConn = iguanaConnect(hw.device);
			if (sendConn == -1)
				logprintf(LOG_ERR, "couldn't open connection to iguanaIR daemon: %s", strerror(errno));
			else
				retval = 1;
		}
        }

	return retval;
}

int iguana_deinit()
{
	int retval = 1;

	/* close the connection to the iguana daemon */
	if (sendConn != -1)
	{
		iguanaClose(sendConn);
		sendConn = -1;
	}

	/* signal the child process to exit */
	if (child > 0 && (kill(child, SIGTERM) == -1 ||
			  waitpid(child, NULL, 0) != 0))
	{
		retval = 0;
		child = 0;
	}

	return retval;
}

char *iguana_rec(struct ir_remote *remotes)
{
	char *retval = NULL;
	if (clear_rec_buffer())
		retval = decode_all(remotes);
	return retval;
}

int iguana_send(struct ir_remote *remote, struct ir_ncode *code)
{
	int retval = 0;

	if (init_send(remote, code))
	{
		int length, x;
		lirc_t *signals;
		uint32_t *igsignals;

		length = send_buffer.wptr;
		signals = send_buffer.data;

		igsignals = (uint32_t*)malloc(sizeof(uint32_t) * length);
		if (igsignals != NULL)
		{
			iguanaPacket request, response = NULL;

			/* must pack the data into a unit32_t array */
			for(x = 0; x < length; x++)
			{
				igsignals[x] = signals[x] & PULSE_MASK;
				if (signals[x] & PULSE_BIT)
					igsignals[x] |= IG_PULSE_BIT;
			}

			/* construct a request and send it to the daemon */
			request = iguanaCreateRequest(IG_DEV_SEND,
						      sizeof(uint32_t) * length,
						      igsignals);
			if (iguanaWriteRequest(request, sendConn))
			{
				/* response will only come back after the device has
				 * transmitted */
				response = iguanaReadResponse(sendConn, 10000);
				if (! iguanaResponseIsError(response))
				{
					remote->last_code = code;
					retval = 1;
				}

				iguanaFreePacket(response);
			}

			/* free the packet and the data */
			iguanaFreePacket(request);
		}
	}

	return retval;
}
