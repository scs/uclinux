#ifndef STA_INFO_H
#define STA_INFO_H

struct sta_info* ap_get_sta(hostapd *hapd, u8 *sta);
struct sta_info* ap_get_sta_radius_identifier(hostapd *hapd,
					      u8 radius_identifier);
void ap_sta_hash_add(hostapd *hapd, struct sta_info *sta);
void ap_free_sta(hostapd *hapd, struct sta_info *sta);
void ap_free_sta(hostapd *hapd, struct sta_info *sta);
void hostapd_free_stas(hostapd *hapd);
void ap_handle_timer(void *eloop_ctx, void *timeout_ctx);
void ap_sta_session_timeout(hostapd *hapd, struct sta_info *sta,
			    u32 session_timeout);
void ap_sta_no_session_timeout(hostapd *hapd, struct sta_info *sta);

#endif /* STA_INFO_H */
