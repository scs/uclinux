#ifndef UTIL_H
#define UTIL_H

#include <endian.h>
#include <byteswap.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le_to_host16(n) (n)
#define host_to_le16(n) (n)
#define be_to_host16(n) bswap_16(n)
#define host_to_be16(n) bswap_16(n)
#else
#define le_to_host16(n) bswap_16(n)
#define host_to_le16(n) bswap_16(n)
#define be_to_host16(n) (n)
#define host_to_be16(n) (n)
#endif


#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#include "hostap_common.h"

void hostap_show_nicid(u8 *data, int len);
void hostap_show_priid(u8 *data, int len);
void hostap_show_staid(u8 *data, int len);
int hostapd_ioctl(const char *dev, struct prism2_hostapd_param *param,
		  int len, int show_err);
int hostapd_get_rid(const char *dev, struct prism2_hostapd_param *param,
		    u16 rid, int show_err);
int hostapd_set_rid(const char *dev, u16 rid, u8 *data, size_t len,
		    int show_err);
int hostap_ioctl_readmif(const char *dev, int cr);


#define PRISM2_PDA_SIZE 1024

struct prism2_pdr {
	unsigned int pdr, len;
	unsigned char *data;
};

struct prism2_pda {
	char pda_buf[PRISM2_PDA_SIZE];
	struct prism2_pdr *pdrs;
	int pdr_count;
};

int read_wlan_pda(const char *fname, struct prism2_pda *pda_info);

#endif /* UTIL_H */
