#ifndef RADIUS_CLIENT_H
#define RADIUS_CLIENT_H

typedef enum {
	RADIUS_AUTH,
	RADIUS_ACCT
} RadiusType;

/* RADIUS message retransmit list */
struct radius_msg_list {
	struct radius_msg *msg;
	RadiusType msg_type;
	time_t first_try;
	time_t next_try;
	int attempts;
	int next_wait;

	u8 *shared_secret;
	size_t shared_secret_len;

	/* TODO: server config with failover to backup server(s) */

	struct radius_msg_list *next;
};


typedef enum {
	RADIUS_RX_PROCESSED,
	RADIUS_RX_QUEUED,
	RADIUS_RX_UNKNOWN
} RadiusRxResult;

struct radius_rx_handler {
	RadiusRxResult (*handler)(hostapd *hapd, struct radius_msg *msg,
				  struct radius_msg *req,
				  u8 *shared_secret, size_t shared_secret_len,
				  void *data);
	void *data;
};

struct radius_client_data {
	int auth_serv_sock; /* socket for authentication RADIUS messages */
	int acct_serv_sock; /* socket for accounting RADIUS messages */

	struct radius_rx_handler *auth_handlers;
	size_t num_auth_handlers;
	struct radius_rx_handler *acct_handlers;
	size_t num_acct_handlers;

	struct radius_msg_list *msgs;
	size_t num_msgs;

	u8 next_radius_identifier;
	u32 acct_session_id_hi;
	u32 acct_session_id_lo;

	/* TODO: remove separate acct list */
	int acct_retransmit_list_len;
	struct accounting_list *acct_retransmit_list;
};


int radius_client_register(hostapd *hapd, RadiusType msg_type,
			   RadiusRxResult (*handler)
			   (hostapd *hapd,
			    struct radius_msg *msg, struct radius_msg *req,
			    u8 *shared_secret, size_t shared_secret_len,
			    void *data),
			   void *data);
int radius_client_send(hostapd *hapd, struct radius_msg *msg,
		       RadiusType msg_type);
u8 radius_client_get_id(hostapd *hapd);

void radius_client_flush(hostapd *hapd);
int radius_client_init(hostapd *hapd);
void radius_client_deinit(hostapd *hapd);

#endif /* RADIUS_CLIENT_H */
