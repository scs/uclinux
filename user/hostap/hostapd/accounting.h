#ifndef ACCOUNTING_H
#define ACCOUNTING_H


/* Accounting message retransmit list */
struct accounting_list {
	struct radius_msg *msg;
	time_t first_try;
	time_t next_try;
	int attempts;
	int next_wait;
	struct accounting_list *next;
};


void accounting_sta_start(hostapd *hapd, struct sta_info *sta);
void accounting_sta_interim(hostapd *hapd, struct sta_info *sta);
void accounting_sta_stop(hostapd *hapd, struct sta_info *sta);
int accounting_init(hostapd *hapd);
void accounting_deinit(hostapd *hapd);


#endif /* ACCOUNTING_H */
