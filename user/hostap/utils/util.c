/*
 * Common functions for Host AP utils
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>

#include "wireless_copy.h"
#include "util.h"

struct hostap_nicid_rec {
	u16 id;
	char *txt;
};

static struct hostap_nicid_rec hostap_nicids[] =
{
	{ 0x8000, "EVB2 (HFA3841EVAL1) with PRISM I (3860B) Radio" },
	{ 0x8001, "HWB3763 Rev B" },
	{ 0x8002, "HWB3163-01,02,03,04 Rev A" },
	{ 0x8003, "HWB3163 Rev B, Samsung PC Card Rev. B" },
	{ 0x8004, "EVB3 (HFA3843EVAL1, Rev B1)" },
	{ 0x8006, "Nortel Sputnik I" },
	{ 0x8007, "HWB1153 PRISM I Ref" },
	{ 0x8008, "HWB3163, Prism II reference with SSF Flash" },
	{ 0x800A, "3842 Evaluation Board" },
	{ 0x800B, "PRISM II (2.5) PCMCIA (AMD parallel flash)" },
	{ 0x800C, "PRISM II (2.5) PCMCIA (SST parallel flash)" },
	{ 0x800D, "PRISM II (2.5) PCMCIA (AT45DB011 compatible large serial "
	  "flash)" },
	{ 0x800E, "PRISM II (2.5) PCMCIA (AT24C08 compatible small serial "
	  "flash)" },
	{ 0x8012, "PRISM II (2.5) Mini-PCI (AMD parallel flash)" },
	{ 0x8013, "PRISM II (2.5) Mini-PCI (SST parallel flash)" },
	{ 0x8014, "PRISM II (2.5) Mini-PCI (AT45DB011 compatible large serial "
	  "flash)" },
	{ 0x8015, "PRISM II (2.5) Mini-PCI (AT24C08 compatible small serial "
	  "flash)" },
	{ 0x8016, "PCI-bridge (AMD parallel flash)" },
	{ 0x8017, "PCI-bridge (SST parallel flash)" },
	{ 0x8018, "PCI-bridge (AT45DB011 compatible large serial flash)" },
	{ 0x8019, "PCI-bridge (AT24C08 compatible small serial flash)" },
	{ 0x801A, "PRISM III PCMCIA (AMD parallel flash)" },
	{ 0x801B, "PRISM III PCMCIA (SST parallel flash)" },
	{ 0x801C, "PRISM III PCMCIA (AT45DB011 compatible large serial flash)"
	},
	{ 0x801D, "PRISM III PCMCIA (AT24C08 compatible small serial flash)" },
	{ 0x8021, "PRISM III Mini-PCI (AMD parallel flash)" },
	{ 0x8022, "PRISM III Mini-PCI (SST parallel flash)" },
	{ 0x8023, "PRISM III Mini-PCI (AT45DB011 compatible large serial "
	  "flash)" },
	{ 0x8024, "PRISM III Mini-PCI (AT24C08 compatible small serial flash)"
	},
};

void hostap_show_nicid(u8 *data, int len)
{
	struct hfa384x_comp_ident *comp;
	int i;
	u16 id;
	char *txt = "unknown";

	if (len != sizeof(*comp)) {
		printf("Invalid NICID length %d\n", len);
		return;
	}

	comp = (struct hfa384x_comp_ident *) data;

	id = le_to_host16(comp->id);
	for (i = 0; i < sizeof(hostap_nicids) / sizeof(hostap_nicids[0]); i++)
	{
		if (hostap_nicids[i].id == id) {
			txt = hostap_nicids[i].txt;
			break;
		}
	}

	printf("NICID: id=0x%04x v%d.%d.%d (%s)", id,
	       le_to_host16(comp->major),
	       le_to_host16(comp->minor),
	       le_to_host16(comp->variant), txt);
	printf("\n");
}


void hostap_show_priid(u8 *data, int len)
{
	struct hfa384x_comp_ident *comp;

	if (len != sizeof(*comp)) {
		printf("Invalid PRIID length %d\n", len);
		return;
	}

	comp = (struct hfa384x_comp_ident *) data;
	printf("PRIID: id=0x%04x v%d.%d.%d\n",
	       le_to_host16(comp->id),
	       le_to_host16(comp->major),
	       le_to_host16(comp->minor),
	       le_to_host16(comp->variant));
	if (le_to_host16(comp->id) != HFA384X_COMP_ID_PRI)
		printf("   Unknown primary firmware component id!\n");
}


void hostap_show_staid(u8 *data, int len)
{
	struct hfa384x_comp_ident *comp;
	u16 id, major, minor, variant;

	if (len != sizeof(*comp)) {
		printf("Invalid STAID length %d\n", len);
		return;
	}

	comp = (struct hfa384x_comp_ident *) data;

	id = le_to_host16(comp->id);
	major = le_to_host16(comp->major);
	minor = le_to_host16(comp->minor);
	variant = le_to_host16(comp->variant);

	printf("STAID: id=0x%04x v%d.%d.%d", id, major, minor, variant);

	switch (id) {
	case HFA384X_COMP_ID_STA:
		printf(" (station firmware)\n");
		break;
	case HFA384X_COMP_ID_FW_AP:
		printf(" (tertiary firmware)\n");
		break;
	default:
		printf(" (unknown component id!)\n");
		break;
	}
}


int hostapd_ioctl(const char *dev, struct prism2_hostapd_param *param,
		  int len, int show_err)
{
	int s;
	struct iwreq iwr;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = len;

	if (ioctl(s, PRISM2_IOCTL_HOSTAPD, &iwr) < 0) {
		int ret;
		close(s);
		ret = errno;
		if (show_err) 
			perror("ioctl[PRISM2_IOCTL_HOSTAPD]");
		return ret;
	}
	close(s);

	return 0;
}


int hostapd_get_rid(const char *dev, struct prism2_hostapd_param *param,
		    u16 rid, int show_err)
{
	int res;
	memset(param, 0, PRISM2_HOSTAPD_MAX_BUF_SIZE);
	param->cmd = PRISM2_HOSTAPD_GET_RID;
	param->u.rid.rid = rid;
	param->u.rid.len = PRISM2_HOSTAPD_MAX_BUF_SIZE -
		PRISM2_HOSTAPD_RID_HDR_LEN;
	res = hostapd_ioctl(dev, param, PRISM2_HOSTAPD_MAX_BUF_SIZE, show_err);

	if (res >= 0 && param->u.rid.len >
	    PRISM2_HOSTAPD_MAX_BUF_SIZE - PRISM2_HOSTAPD_RID_HDR_LEN)
		return -1;

	return res;
}


int hostapd_set_rid(const char *dev, u16 rid, u8 *data, size_t len,
		    int show_err)
{
	struct prism2_hostapd_param *param;
	int res;
	size_t blen = PRISM2_HOSTAPD_RID_HDR_LEN + len;
	if (blen < sizeof(*param))
		blen = sizeof(*param);

	param = (struct prism2_hostapd_param *) malloc(blen);
	if (param == NULL)
		return -1;

	memset(param, 0, blen);
	param->cmd = PRISM2_HOSTAPD_SET_RID;
	param->u.rid.rid = rid;
	param->u.rid.len = len;
	memcpy(param->u.rid.data, data, len);
	res = hostapd_ioctl(dev, param, blen, show_err);

	free(param);

	return res;
}


int hostap_ioctl_readmif(const char *dev, int cr)
{
	int s;
	struct iwreq iwr;
	u8 val;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev, IFNAMSIZ);
	iwr.u.name[0] = cr * 2;

	if (ioctl(s, PRISM2_IOCTL_READMIF, &iwr) < 0) {
		perror("ioctl[PRISM2_IOCTL_READMIF]");
		close(s);
		return -1;
	}
	close(s);

	val = iwr.u.name[0];
	return (int) val;
}


static const u16 crc16_table[256] =
{
	0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
	0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
	0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
	0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
	0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
	0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
	0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
	0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
	0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
	0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
	0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
	0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
	0x2800, 0xe8c1, 0xe981, 0x2940, 0xeb01, 0x2bc0, 0x2a80, 0xea41,
	0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
	0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
	0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
	0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
	0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
	0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
	0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
	0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
	0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
	0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
	0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
	0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
	0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
	0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
	0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
	0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
	0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
	0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
	0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
};


static int crc16(u8 *buf, int len)
{
	u16 crc;
	int i;

	crc = 0;
	for (i = 0; i < len; i++)
		crc = (crc >> 8) ^ crc16_table[(crc & 0xff) ^ *buf++];
	return crc;
}


int read_wlan_pda(const char *fname, struct prism2_pda *pda_info)
{
	FILE *f;
	int pos;
	u16 *pda, len, pdr;

	memset(pda_info, 0, sizeof(struct prism2_pda));
	f = fopen(fname, "r");
	if (f == NULL)
		return 1;

	if (fread(pda_info->pda_buf, 1, PRISM2_PDA_SIZE, f) !=
	    PRISM2_PDA_SIZE) {
		fclose(f);
		return 1;
	}

	fclose(f);

	pda = (u16 *) pda_info->pda_buf;
	pos = 0;
	while (pos + 1 < PRISM2_PDA_SIZE / 2) {
		len = le_to_host16(pda[pos]);
		pdr = le_to_host16(pda[pos + 1]);
		if (len == 0 || pos + len > PRISM2_PDA_SIZE / 2)
			return 1;

		pda_info->pdrs = (struct prism2_pdr *)
			realloc(pda_info->pdrs,
				(pda_info->pdr_count + 1) *
				sizeof(struct prism2_pdr));
		assert(pda_info->pdrs != NULL);
		pda_info->pdrs[pda_info->pdr_count].pdr = pdr;
		pda_info->pdrs[pda_info->pdr_count].len = (len - 1) * 2;
		pda_info->pdrs[pda_info->pdr_count].data =
			(unsigned char *) (&pda[pos + 2]);
		pda_info->pdr_count++;

		if (pdr == 0x0000 && len == 2) {
			/* PDA end found */
			if (crc16(pda_info->pda_buf, (pos + 3) * 2) != 0) {
				printf("PDA checksum incorrect.\n");
				return 1;
			}
			return 0;
		}

		pos += len + 1;
	}

	return 1;
}
