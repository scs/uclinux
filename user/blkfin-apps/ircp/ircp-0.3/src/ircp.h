#ifndef IRCP_H
#define IRCP_H

#define ircp_return_if_fail(test)       do { if (!(test)) return; } while(0);
#define ircp_return_val_if_fail(test, val)      do { if (!(test)) return val; } while(0);

typedef void (*ircp_info_cb_t)(int event, char *param);

enum {
	IRCP_EV_ERRMSG,

	IRCP_EV_OK,
	IRCP_EV_ERR,

	IRCP_EV_CONNECTING,
	IRCP_EV_DISCONNECTING,
	IRCP_EV_SENDING,

	IRCP_EV_LISTENING,
	IRCP_EV_CONNECTIND,
	IRCP_EV_DISCONNECTIND,
	IRCP_EV_RECEIVING,
};

/* Number of bytes passed at one time to OBEX */
#define STREAM_CHUNK 4096

#endif
