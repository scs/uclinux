/*
 *
 *  Headset Profile support for Linux
 *
 *  Copyright (C) 2006  Fabien Chevalier
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/sco.h>

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#include <config.h>
#include "states.h"
#include "sdp.h"
#include "volctl.h"
#include "dbus.h"

/* Local defines */
  /* Size for sco packets we send/receive */
#define SCO_PACKET_LEN        48
#define CTL_LRU_ARRAY_SIZE    5

  /* PCM Appl IPC packet types */
#define PKT_TYPE_CFG_BDADDR        0
#define PKT_TYPE_CFG_PAGINGTIMEOUT 1
#define PKT_TYPE_CFG_ACK           2
#define PKT_TYPE_CFG_NACK          3
#define PKT_TYPE_ERROR_IND         4
#define PKT_TYPE_STREAMING_IND     5

/* Local structures definition */
typedef struct ipc_packet {
	unsigned char type;
	union {
		bdaddr_t     bdaddr;	               /* PKT_TYPE_CFG_BDADDR        */
		long         timeout;                  /* PKT_TYPE_CFG_PAGINGTIMEOUT */
		int	     errorcode;		       /* PKT_TYPE_ERROR_IND         */
	};
} ipc_packet_t;

/* Local variables */

  /* Stores SDP session used to scan for Headset Profile */
static sdp_session_t *hs_sdp_session;
  /* Stores the bd address for the device we are connected to */
static bdaddr_t       hs_bdaddr;
static long           hs_pagingtimeout;
  /* Stores if we are in/or just came out from a state where we
     are connected to the headset */
static int            hs_connected;
/* Functions shared by all states */

static void appl_send_error_pkt(int error)
{
	ipc_packet_t pkt = {.type = PKT_TYPE_ERROR_IND};
	int bckp = errno; /* backing up errno */
	pkt.errorcode = error;
	send(hspd_sockets[IDX_PCM_APPL_SOCK], &pkt, sizeof(pkt), MSG_NOSIGNAL);
	errno = bckp;
}

   /* This one is shared by all states, as it is not supposed to alter / depend on the state in which we are */
static void process_at_command(const char* data, unsigned int datalen);


void connectedReadCtlAppl(struct State *s, short revents)
{
	volctl_ReadCtlApplSocket(s, revents, volctl_write_fromappl);
}

void unconnectedReadCtlAppl(struct State *s, short revents)
{
	volctl_ReadCtlApplSocket(s, revents, volctl_write_fromappl_unconnected);
}

static struct State * genericGetNextState(struct State *this)
{
	return this->_next_state;
}

static void genericReadRfcomm(struct State *this, short revents)
{
	if((revents & (POLLHUP | POLLERR)) == 0) {
		char buffer[32];
		int size;
		if((size = recv(hspd_sockets[IDX_RFCOMM_SOCK], buffer, sizeof(buffer) - 1, 0)) > 0) {
			buffer[size] = 0;
			process_at_command(buffer, size);
		}
		this->_next_state = this;
	}
	else {
		syslog(LOG_NOTICE, "Headset disconnected as RFCOMM socket died");
		/* back to Idle */
		this->_next_state = &HeadsetIdleState;
	}
}

static void genericReadSco(struct State *this, short revents)
{
	if((revents & (POLLHUP | POLLERR)) == 0) {
		this->_next_state = this;
	}
	else {
		syslog(LOG_NOTICE, "Headset disconnected as SCO socket died");
		/* back to Idle */
		this->_next_state = &HeadsetIdleState;
	}
}

static int rfcommConnectAsync(const bdaddr_t * dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0) {
		return -1;
	}

	/* Set socket as non blocking */
	if(fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		close(s);
		return -1;	
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	if ((connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) && (errno != EAGAIN) && (errno != EINPROGRESS) ) {
		close(s);
		return -1;
	}

	return s;
}

static int scoConnectAsync(const bdaddr_t * dst)
{
	struct sockaddr_sco addr;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0) {
		return -1;
	}

	/* Set socket as non blocking */
	if(fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		close(s);
		return -1;	
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, dst);
	if ((connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) && (errno != EAGAIN) && (errno != EINPROGRESS) ) {
		close(s);
		return -1;
	}

	return s;
}

static int recv_cfg(int applsockfd, bdaddr_t* bdaddr, long *timeout)
{
	int ret;
	int expected_configs = 2;
	const int CFG_TIMEOUT = 1000;
	struct pollfd pfd = {.fd = applsockfd, .events = POLLIN};
	
	while(expected_configs > 0) {
		ret = poll(&pfd, 1, CFG_TIMEOUT);
		if(ret == 1 && (!(pfd.revents & (POLLHUP | POLLERR))) ) {
			expected_configs--;
			ipc_packet_t pkt;
			recv(applsockfd, &pkt, sizeof(ipc_packet_t), 0);
			switch(pkt.type) {
			case PKT_TYPE_CFG_BDADDR:
				if(bdaddr != 0) {
					bacpy(bdaddr, &pkt.bdaddr);
					pkt.type = PKT_TYPE_CFG_ACK;
				}
				else {
					pkt.type = PKT_TYPE_CFG_NACK;
				}
				send(applsockfd, &pkt, sizeof(ipc_packet_t), MSG_NOSIGNAL); 
				break;
			case PKT_TYPE_CFG_PAGINGTIMEOUT:
				if(timeout != 0) {
					if(pkt.timeout <= 0) {
						*timeout = -1;	
					}
					else {
						*timeout = pkt.timeout;
					}
					pkt.type = PKT_TYPE_CFG_ACK;
				}
				else {
					pkt.type = PKT_TYPE_CFG_NACK;
				}
				send(applsockfd, &pkt, sizeof(ipc_packet_t), MSG_NOSIGNAL); 
				break;
			default:
				syslog(LOG_WARNING, "ignoring packet from local appli: type = %d", pkt.type);
			}
		}
		else if (ret == 0) {
			syslog(LOG_ERR, "Timeout retrieving configuration from local appli.");
			return -1;
		}
		else {
			syslog(LOG_ERR, "unable to retrieve configuration from local appli: %s", strerror(errno));
			return -1;
		}	
	}

	return 0;
}

/* Idle State */

static void headsetIdleEnter(struct State *this)
{
	if(hs_connected) {
		signalHeadsetDisconnected(&hs_bdaddr);
	}
	hs_connected = 0;

	/* killing client sockets */
	if(hspd_sockets[IDX_PCM_APPL_SOCK] != 0) {
		close(hspd_sockets[IDX_PCM_APPL_SOCK]);
		hspd_sockets[IDX_PCM_APPL_SOCK] = 0;
	}
	if(hspd_sockets[IDX_SCO_SOCK] != 0) {
		close(hspd_sockets[IDX_SCO_SOCK]);
		hspd_sockets[IDX_SCO_SOCK] = 0;
	}
	if(hspd_sockets[IDX_RFCOMM_SOCK] != 0) {
		close(hspd_sockets[IDX_RFCOMM_SOCK]);
		hspd_sockets[IDX_RFCOMM_SOCK] = 0;
	}
	if(hspd_sockets[IDX_SDP_SOCK] != 0) {
		close(hspd_sockets[IDX_SDP_SOCK]);
		hspd_sockets[IDX_SDP_SOCK] = 0;
	}
	memset(&hs_bdaddr, 0, sizeof(bdaddr_t));
	/* This is not a transitional state */
	this->_next_state = this;	
}

static void headsetIdleHandleApplConnReq(struct State *this)
{
	struct sockaddr_un client_addr;
	unsigned int client_addr_len = sizeof(client_addr);
	/* Per default stay in same state */
	this->_next_state = this;
	
	/* Connect Appli to us */
	int _appl_sock = accept(hspd_sockets[IDX_PCM_APPL_SRV_SOCK], (struct sockaddr *)&client_addr, &client_addr_len);
	if(_appl_sock != -1) {
		/* Retrieve configuration parameters */

		fcntl(_appl_sock, F_SETFL, O_NONBLOCK);

		if(recv_cfg(_appl_sock, &hs_bdaddr, &hs_pagingtimeout) >= 0) {
			char remoteaddr[32];
			ba2str(&hs_bdaddr, remoteaddr);
			syslog(LOG_INFO, "Configuration phase ended: target bdaddr is %s, timeout is %ld ms", remoteaddr, hs_pagingtimeout);

			/* Launch SDP on bluetooth headset */
			hs_sdp_session = sdp_connect_async(BDADDR_ANY, &hs_bdaddr, 0);
	
			if(hs_sdp_session != 0) {
				hspd_sockets[IDX_PCM_APPL_SOCK] = _appl_sock;
				hspd_sockets[IDX_SDP_SOCK] = sdp_get_socket(hs_sdp_session);
				this->_next_state = &HeadsetPagingState;
			}
			else {
				appl_send_error_pkt(errno);
				syslog(LOG_ERR, "unable to create bluetooth L2CAP socket: %s", strerror(errno));
				close(_appl_sock);
			}
		}
		else {
			close(_appl_sock);
			return;
		}
	}
}

static void headsetIdleHandleRfcommConnReq(struct State *this)
{
	struct sockaddr_rc client_addr;
	unsigned int client_addr_len = sizeof(client_addr);
	/* Per default stay in same state */
	this->_next_state = this;
	
	/* Connect Appli to us */
	int _rfcomm_sock = accept(hspd_sockets[IDX_RFCOMM_SRV_SOCK], (struct sockaddr *)&client_addr, &client_addr_len);
	if(_rfcomm_sock != -1) {
		char remoteaddr[32];
		ba2str(&client_addr.rc_bdaddr, remoteaddr);
		syslog(LOG_INFO, "Incoming RFCOMM hs connection from %s accepted",
				remoteaddr);
		hspd_sockets[IDX_RFCOMM_SOCK] = _rfcomm_sock;
		bacpy(&hs_bdaddr, &client_addr.rc_bdaddr);
		hs_connected = 1;
		signalHeadsetConnected(&hs_bdaddr);
		this->_next_state = &HeadsetConnectedState;
	}
	else {
		appl_send_error_pkt(errno);
		syslog(LOG_ERR, "unable to accept bluetooth RFCOMM socket : %s", strerror(errno));
		close(_rfcomm_sock);
	}
}

struct State HeadsetIdleState = {
	.name = "Idle",
	.pollEvents = {
		[IDX_PCM_APPL_SRV_SOCK]   = POLLIN,
		[IDX_CTL_APPL_SRV_SOCK]   = POLLIN,
		[IDX_RFCOMM_SRV_SOCK] = POLLIN
	 },
	.enter               = headsetIdleEnter,
	.handleApplConnReq   = headsetIdleHandleApplConnReq,
	.handleRfcommConnReq = headsetIdleHandleRfcommConnReq,
	.readCtlAppl         = unconnectedReadCtlAppl,
	.getNextState        = genericGetNextState,
};

/* Paging State */

static void headsetPagingReadSdp(struct State *this, short revents)
{
	/* Fetching result code */
	int errcode = -1;
	unsigned int opt_size = sizeof(int);
	/* Per default stay in same state */
	this->_next_state = &HeadsetIdleState;
	
	if(getsockopt(hspd_sockets[IDX_SDP_SOCK], SOL_SOCKET, SO_ERROR, &errcode, &opt_size) == 0) {
		if(errcode == 0) {
			/* Retrieving sdp info */
			uint32_t range = 0x0000ffff;
			sdp_list_t *attrid, *search, *seq, *next;
			uuid_t group;
			int searchresult;
			uint8_t channel = 1;
			
			sdp_uuid16_create(&group, HEADSET_PROFILE_ID);
			
			attrid = sdp_list_append(0, &range);
			search = sdp_list_append(0, &group);
			searchresult =
			sdp_service_search_attr_req(hs_sdp_session, search, SDP_ATTR_REQ_RANGE,
							attrid, &seq);
			sdp_list_free(attrid, 0);
			sdp_list_free(search, 0);
		
			if (searchresult == 0) {
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
			}
			else {
				syslog(LOG_WARNING, "Service search failed: %s", strerror(errno));
			}
			sdp_close(hs_sdp_session);
			/* Socket is already closed by sdp_close, so we only zero it */
			hspd_sockets[IDX_SDP_SOCK] = 0;

			/* Try connecting to bluetooth headset */
			int _rfcomm_sock = rfcommConnectAsync(&hs_bdaddr, channel);
			
			if(_rfcomm_sock >= 0) {
				hspd_sockets[IDX_RFCOMM_SOCK] = _rfcomm_sock;
				this->_next_state = &HeadsetConnectingState;
			}
			else {
				appl_send_error_pkt(errno);
				syslog(LOG_ERR, "unable to create bluetooth RFCOMM socket: %s", strerror(errno));
			}
		}
		else {
			appl_send_error_pkt(errcode);
			syslog(LOG_NOTICE, "unable to connect L2CAP socket to headset: %s", strerror(errcode));
			/* go to default state : idle */
		}
	}
	else {
		sdp_close(hs_sdp_session);
		hspd_sockets[IDX_SDP_SOCK] = 0;
	}
}

void headsetPagingTimedout(struct State *this)
{
	appl_send_error_pkt(EHOSTUNREACH);
	syslog(LOG_NOTICE, "Timeout connecting L2CAP socket to headset, aborting.");
	this->_next_state = &HeadsetIdleState;
}

int headsetPagingGetTimeout(struct State *this)
{
	return hs_pagingtimeout;
}

struct State HeadsetPagingState = {
	.name = "Paging",
	.pollEvents = {
		[IDX_CTL_APPL_SRV_SOCK]   = POLLIN,
		[IDX_SDP_SOCK] = POLLOUT,
	 },
	.readSdp       = headsetPagingReadSdp,
	.timedout      = headsetPagingTimedout,
	.getTimeout    = headsetPagingGetTimeout,
	.readCtlAppl   = unconnectedReadCtlAppl,
	.getNextState  = genericGetNextState,
};

/* Connecting State */

static void headsetConnectingReadRfcomm(struct State *this, short revents)
{
	/* Fectching result code */
	int errcode;
	unsigned int opt_size = sizeof(int);
	/* default next state is back to home : idle */
	this->_next_state = &HeadsetIdleState;

	if(getsockopt(hspd_sockets[IDX_RFCOMM_SOCK], SOL_SOCKET, SO_ERROR, &errcode, &opt_size) == 0) {
		if(errcode == 0) {
			hs_connected = 1;
			signalHeadsetConnected(&hs_bdaddr);
			/* Go to HeadsetReady state */
			this->_next_state = &HeadsetReadyState;
		}
		else {
			appl_send_error_pkt(errcode);
			syslog(LOG_NOTICE, "unable to connect to headset: %s", strerror(errcode));
			/* go to default state : idle */
		}
	}
}

struct State HeadsetConnectingState = {
	.name = "Connecting",
	.pollEvents = {
		[IDX_CTL_APPL_SRV_SOCK]   = POLLIN,
		[IDX_RFCOMM_SOCK] = POLLOUT,
	 },
	.readRfcomm    = headsetConnectingReadRfcomm,
	.readCtlAppl   = unconnectedReadCtlAppl,
	.getNextState  = genericGetNextState,
};

/* Connected State */

static void headsetConnectedEnter(struct State *this)
{
	/* killing useless sockets */
	if(hspd_sockets[IDX_PCM_APPL_SOCK] != 0) {
		close(hspd_sockets[IDX_PCM_APPL_SOCK]);
		hspd_sockets[IDX_PCM_APPL_SOCK] = 0;
	}
	if(hspd_sockets[IDX_SCO_SOCK] != 0) {
		close(hspd_sockets[IDX_SCO_SOCK]);
		hspd_sockets[IDX_SCO_SOCK] = 0;
	}
	/* This is not a transitional state */
	this->_next_state = this;	
}

static void headsetConnectedHandleApplConnReq(struct State *this)
{
	struct sockaddr_un client_addr;
	unsigned int client_addr_len = sizeof(client_addr);
	/* Per default stay in same state */
	this->_next_state = this;
	
	/* Connect Appli to us */
	int _appl_sock = accept(hspd_sockets[IDX_PCM_APPL_SRV_SOCK], (struct sockaddr *)&client_addr, &client_addr_len);
	if(_appl_sock != -1) {
		fcntl(_appl_sock, F_SETFL, O_NONBLOCK);
		if(recv_cfg(_appl_sock, 0, 0) >= 0) {
			hspd_sockets[IDX_PCM_APPL_SOCK] = _appl_sock;
			/* Go to HeadsetReady state */
			this->_next_state = &HeadsetReadyState;
		}
		else {
			/* else : stay where we are */
			close(_appl_sock);
		}
	}
	else {
		syslog(LOG_ERR, "unable to accept local application connection, %s", strerror(errno));
	}
}

struct State HeadsetConnectedState = {
	.name = "Connected",
	.pollEvents = {
		[IDX_PCM_APPL_SRV_SOCK] = POLLIN,
		[IDX_CTL_APPL_SRV_SOCK] = POLLIN,
		[IDX_RFCOMM_SOCK] = POLLIN
	 },
	.enter             = headsetConnectedEnter,
	.handleApplConnReq = headsetConnectedHandleApplConnReq,
	.readRfcomm        = genericReadRfcomm,
	.readCtlAppl       = unconnectedReadCtlAppl,
	.getNextState      = genericGetNextState,
};

/* Ready State */

static void headsetReadyEnter(struct State *this)
{
	/* Check if application socket is still there */
	struct pollfd pfd = {.fd = hspd_sockets[IDX_PCM_APPL_SOCK], .events = POLLOUT};
	int ret = poll(&pfd, 1, 0);

	if((ret == 1) && !(pfd.revents & (POLLHUP | POLLERR))) {
		/* Application still there : go go go !!! */
		/* Launch SCO connection */
		int _sco_sock = scoConnectAsync(&hs_bdaddr);
		if(_sco_sock >= 0) {
			hspd_sockets[IDX_SCO_SOCK] = _sco_sock;
			/* Go to HeadsetOpeningState state */
			this->_next_state = &HeadsetOpeningState;
		}
		else {
			appl_send_error_pkt(errno);
			syslog(LOG_ERR, "unable to open bluetooth SCO socket");
			close(_sco_sock);
			this->_next_state = &HeadsetConnectedState;
		}
	}
	else {
		/* Application closed connection : keep headset connection */
		this->_next_state = &HeadsetConnectedState;
	}
}

struct State HeadsetReadyState = {
	.name          = "Ready",
	.pollEvents    = {}, /* Empty pollEvents : this state is purely transitionnal */
	.enter         = headsetReadyEnter,
	.readCtlAppl   = unconnectedReadCtlAppl,
	.getNextState  = genericGetNextState,
};

/* Opening State */

static void headsetOpeningReadSco(struct State *this, short revents)
{
	/* Fetching result code */
	int errcode;
	unsigned int opt_size = sizeof(int);
	/* default next state is back to Connected */
	this->_next_state = &HeadsetConnectedState;

	if(getsockopt(hspd_sockets[IDX_SCO_SOCK], SOL_SOCKET, SO_ERROR, &errcode, &opt_size) == 0) {
		if(errcode == 0) {
			struct sco_conninfo conn;
			struct sco_options opts;
			unsigned int size;

			size = sizeof(conn);
			if (getsockopt(hspd_sockets[IDX_SCO_SOCK], SOL_SCO, SCO_CONNINFO, &conn, &size) == 0) {
				size = sizeof(opts);
				if (getsockopt(hspd_sockets[IDX_SCO_SOCK], SOL_SCO, SCO_OPTIONS, &opts, &size) == 0) {
					/* Make sure we will block per default - clear 0_NONBLOCK flag */
					fcntl(hspd_sockets[IDX_SCO_SOCK], F_SETFL, 0);
					syslog(LOG_INFO, "SCO channel opened handle=0x%04x mtu=%d", conn.hci_handle, opts.mtu);
					this->_next_state = &HeadsetStreamingState;
				}
				else {
					appl_send_error_pkt(errno);
					syslog(LOG_ERR, "unable to query SCO channel info: %s", strerror(errno));
					/* go to default state : idle */
				}
			}
			else {
				appl_send_error_pkt(errno);
				syslog(LOG_ERR, "unable to query SCO channel info: %s", strerror(errno));
				/* go to default state : idle */
			}
		}
		else {
			appl_send_error_pkt(errcode);
			syslog(LOG_ERR, "unable to open SCO channel to headset: %s", strerror(errcode));
			/* go to default state : idle */
		}
	}
	else {
		appl_send_error_pkt(errno);
	}
}

struct State HeadsetOpeningState = {
	.name = "Opening",
	.pollEvents = {
		[IDX_CTL_APPL_SRV_SOCK] = POLLIN,
		[IDX_RFCOMM_SOCK] = POLLIN,
		[IDX_SCO_SOCK]    = POLLOUT,
	 },
	.readSco       = headsetOpeningReadSco,
	.readRfcomm    = genericReadRfcomm,
	.readCtlAppl   = unconnectedReadCtlAppl,
	.getNextState  = genericGetNextState,
};

/* Streaming State */
static void headsetStreamingEnter(struct State *this)
{
	/* Send sco socket to application using ancilliary data - see man 7 unix*/
        char cmsg_b[CMSG_SPACE(sizeof(int))];  /* ancillary data buffer */
	struct cmsghdr *cmsg;
	ipc_packet_t pkt = {.type = PKT_TYPE_STREAMING_IND};

	struct iovec iov =  {
              .iov_base = &pkt,        /* Starting address */
              .iov_len  = sizeof(pkt)   /* Number of bytes */
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

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type  = SCM_RIGHTS;
	cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
	/* Initialize the payload */
        (*(int *)CMSG_DATA(cmsg)) = hspd_sockets[IDX_SCO_SOCK];

	/* finally send it -we ignore PIPE signal & return code, as any errors will be caught later */
	int ret = sendmsg(hspd_sockets[IDX_PCM_APPL_SOCK], &msgh, MSG_NOSIGNAL);
	if(ret == -1) {
		syslog(LOG_ERR, "Unable to send SCO socket to appl: %s", strerror(errno));
	}
	/* This is not a transitional state */
	this->_next_state = this;	
}

static void headsetStreamingReadAppl(struct State *this, short revents)
{
	if((revents & (POLLHUP | POLLERR)) == 0) {
		/* Should not happen, treat as error */
		this->_next_state = &HeadsetConnectedState;
	}
	else {
		syslog(LOG_INFO, "Appli closed socket");
		/* go to Closewaiting state */
		this->_next_state = &HeadsetClosewaitingState;
	}
}

struct State HeadsetStreamingState = {
	.name = "Streaming",
	.pollEvents = {
		[IDX_CTL_APPL_SRV_SOCK] = POLLIN,
		[IDX_PCM_APPL_SOCK]   = POLLIN,
		[IDX_RFCOMM_SOCK] = POLLIN,
		[IDX_SCO_SOCK]    = POLLERR, /* We are interested in nothing but errors */
	 },
	.enter         = headsetStreamingEnter,
	.readRfcomm    = genericReadRfcomm,
	.readPcmAppl      = headsetStreamingReadAppl,
	.readSco       = genericReadSco,
	.readCtlAppl   = connectedReadCtlAppl,
	.getNextState  = genericGetNextState,
};

/* Closewaiting State */

static void headsetClosewaitingEnter(struct State *this)
{
	if(hspd_sockets[IDX_PCM_APPL_SOCK] != 0) {
		close(hspd_sockets[IDX_PCM_APPL_SOCK]);
		hspd_sockets[IDX_PCM_APPL_SOCK] = 0;
	}
	/* This is not a transitional state */
	this->_next_state = this;	
}

static void headsetClosewaitingHandleApplConnReq(struct State *this)
{
	struct sockaddr_un client_addr;
	unsigned int client_addr_len = sizeof(client_addr);
	/* Per default stay in same state */
	this->_next_state = this;
	
	/* Connect Appli to us */
	int _appl_sock = accept(hspd_sockets[IDX_PCM_APPL_SRV_SOCK], (struct sockaddr *)&client_addr, &client_addr_len);
	if(_appl_sock != -1) {
		fcntl(_appl_sock, F_SETFL, O_NONBLOCK);
		if((recv_cfg(_appl_sock, 0, 0) >= 0)) { 
			hspd_sockets[IDX_PCM_APPL_SOCK] = _appl_sock;
			this->_next_state = &HeadsetStreamingState;
		}
		else {
			/* else : stay where we are */
			close(_appl_sock);
		}
	}
	else {
		syslog(LOG_ERR, "unable to accept local application connection");
	}
}

void headsetClosewaitingTimedout(struct State *this)
{
	appl_send_error_pkt(EHOSTUNREACH);
	syslog(LOG_NOTICE, "Nobody uses SCO channel anymore, closing it.");
	this->_next_state = &HeadsetConnectedState;
}

int headsetClosewaitingGetTimeout(struct State *this)
{
	return 4000;
}

struct State HeadsetClosewaitingState = {
	.name = "Closewaiting",
	.pollEvents = {
		[IDX_PCM_APPL_SRV_SOCK] = POLLIN,
		[IDX_CTL_APPL_SRV_SOCK] = POLLIN,
		[IDX_RFCOMM_SOCK]   = POLLIN,
		[IDX_SCO_SOCK]      = POLLERR,
	 },
	.enter             = headsetClosewaitingEnter,
	.readRfcomm        = genericReadRfcomm,
	.readSco           = genericReadSco,
	.handleApplConnReq = headsetClosewaitingHandleApplConnReq,
	.timedout          = headsetClosewaitingTimedout,
	.getTimeout        = headsetClosewaitingGetTimeout,
	.readCtlAppl       = connectedReadCtlAppl,
	.getNextState      = genericGetNextState,
};

/* AT commands processing */

struct commands_table {
	const char * command;
	int (*process_func)(const char *cmd);
};

static void respOK()
{
	const char resp_ok[] = "\r\nOK\r\n";
	send(hspd_sockets[IDX_RFCOMM_SOCK], resp_ok, sizeof(resp_ok) - 1, MSG_NOSIGNAL);
}

static void respError()
{
	const char resp_error[] = "\r\nERROR\r\n";
	send(hspd_sockets[IDX_RFCOMM_SOCK], resp_error, sizeof(resp_error) - 1, MSG_NOSIGNAL);
}

static int doVolChanged(const char * cmd)
{
	return volctl_write_fromhs(cmd);
}

static int doBtnPushed(const char * cmd)
{
	signalHeadsetButtonPushed(&hs_bdaddr);
	return 0;
}

static void process_at_command(const char* buffer, unsigned int datalen)
{
	int i;
	int answered = 0;

	const struct commands_table tbl[] = {
		{"AT+CKPD=200", doBtnPushed },
		{"AT+VGS=",     doVolChanged },
		{"AT+VGM=",     doVolChanged },
		{0,             0 },
	};

	#ifndef NDEBUG
	fprintf(stderr, "Received from HS: %s\n", buffer);
	#endif
	
	for(i = 0; tbl[i].command != 0; i++) {
		if(strncmp(buffer, tbl[i].command, strlen(tbl[i].command)) == 0) {
			if(tbl[i].process_func(buffer) != 0) {
				/* Error happened while processing */
				respError();
			}
			else {
				/* Everything's fine */
				respOK();
			}
			answered = 1;
			break;
		}
	}
	if(!answered) {
		/* command not found in list */
		respError();
	}
}
