/* src/prism2/include/prism2/prism2mgmt.h
*
* Declares the mgmt command handler functions
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by 
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*
* This file contains the constants and data structures for interaction
* with the hfa384x Wireless LAN (WLAN) Media Access Contoller (MAC).  
* The hfa384x is a portion of the Harris PRISM(tm) WLAN chipset.
*
* [Implementation and usage notes]
*
* [References]
*   CW10 Programmer's Manual v1.5
*   IEEE 802.11 D10.0
*
*    --------------------------------------------------------------------
*/

#ifndef _PRISM2MGMT_H
#define _PRISM2MGMT_H


/*=============================================================*/
/*------ Constants --------------------------------------------*/

#define	MAX_GRP_ADDR		(32)
#define	MAX_PRISM2_GRP_ADDR	(16)

#define MM_SAT_PCF		(BIT14)
#define MM_GCSD_PCF		(BIT15)
#define MM_GCSD_PCF_EB		(BIT14 | BIT15)

#define WLAN_STATE_STOPPED	0   /* Network is not active. */
#define WLAN_STATE_STARTED	1   /* Network has been started. */

#define WLAN_AUTH_MAX           60  /* Max. # of authenticated stations. */
#define WLAN_ACCESS_MAX		60  /* Max. # of stations in an access list. */
#define WLAN_ACCESS_NONE	0   /* No stations may be authenticated. */
#define WLAN_ACCESS_ALL		1   /* All stations may be authenticated. */
#define WLAN_ACCESS_ALLOW	2   /* Authenticate only "allowed" stations. */
#define WLAN_ACCESS_DENY	3   /* Do not authenticate "denied" stations. */

#define WLAN_COMMENT_MAX	80  /* Max. length of user comment string. */

/*=============================================================*/
/*------ Macros -----------------------------------------------*/


/*=============================================================*/
/*------ Types and their related constants --------------------*/

typedef struct prism2sta_authlist
{
	UINT	cnt;
	UINT8	addr[WLAN_AUTH_MAX][WLAN_ADDR_LEN];
	UINT8	assoc[WLAN_AUTH_MAX];
} prism2sta_authlist_t;

typedef struct prism2sta_accesslist
{
	UINT	modify;
	UINT	cnt;
	UINT8	addr[WLAN_ACCESS_MAX][WLAN_ADDR_LEN];
	UINT	cnt1;
	UINT8	addr1[WLAN_ACCESS_MAX][WLAN_ADDR_LEN];
} prism2sta_accesslist_t;

typedef struct prism2sta_priv
{
#if (WLAN_HOSTIF == WLAN_PCMCIA)
	dev_node_t	node;
	dev_link_t	*cs_link;
#elif (WLAN_HOSTIF==WLAN_PLX || WLAN_HOSTIF==WLAN_PCI || WLAN_HOSTIF==WLAN_USB)
	char		name[WLAN_DEVNAMELEN_MAX];
#endif

	/* Structure for MAC data */
	hfa384x_t	*hw;

	/* Component Identities */
	hfa384x_compident_t	ident_nic;
	hfa384x_compident_t	ident_pri_fw;
	hfa384x_compident_t	ident_sta_fw;
	hfa384x_compident_t	ident_ap_fw;
	UINT16			mm_mods;

	/* Supplier compatibility ranges */
	hfa384x_caplevel_t	cap_sup_mfi;
	hfa384x_caplevel_t	cap_sup_cfi;
	hfa384x_caplevel_t	cap_sup_pri;
	hfa384x_caplevel_t	cap_sup_sta;
	hfa384x_caplevel_t	cap_sup_ap;

	/* Actor compatibility ranges */
	hfa384x_caplevel_t	cap_act_pri_cfi; /* pri f/w to controller interface */
	hfa384x_caplevel_t	cap_act_sta_cfi; /* sta f/w to controller interface */
	hfa384x_caplevel_t	cap_act_sta_mfi; /* sta f/w to modem interface */
	hfa384x_caplevel_t	cap_act_ap_cfi;  /* ap f/w to controller interface */
	hfa384x_caplevel_t	cap_act_ap_mfi;  /* ap f/w to modem interface */

	/* PDA */
	UINT8			pda[HFA384x_PDA_LEN_MAX];
	hfa384x_pdrec_t		*pdrec[HFA384x_PDA_RECS_MAX];
	UINT			npdrec;

	/* The following are dot11StationConfigurationTable mibitems
	maintained by the driver; there are no Prism2 RID's */
	UINT32		dot11_desired_bss_type;
	UINT32		dot11_disassoc_reason;
	UINT8		dot11_disassoc_station[WLAN_ADDR_LEN];
	UINT32		dot11_deauth_reason;
	UINT8		dot11_deauth_station[WLAN_ADDR_LEN];
	UINT32		dot11_auth_fail_status;
	UINT8		dot11_auth_fail_station[WLAN_ADDR_LEN];

	/* Group Addresses - right now, there are up to a total
	of MAX_GRP_ADDR group addresses */
	UINT8		dot11_grp_addr[MAX_GRP_ADDR][WLAN_ADDR_LEN];
	UINT		dot11_grpcnt;

	/* Channel Info request results (AP only) */
	struct {
		atomic_t		done;
		UINT8			count;
		hfa384x_ChInfoResult_t	results;
	} channel_info;

	/* State variables */
	UINT		presniff_port_type;
	UINT16		presniff_wepflags;

	int		ap;	/* AP flag: 0 - Station, 1 - Access Point. */
	int		state;	/* Network state: 0 - Stopped, 1 - Started. */
	int		log;	/* Log flag: 0 - No, 1 - Log events. */

        prism2sta_authlist_t	authlist;     /* Authenticated station list. */
	UINT			accessmode;   /* Access mode. */
        prism2sta_accesslist_t	allow;        /* Allowed station list. */
        prism2sta_accesslist_t	deny;         /* Denied station list. */
	UINT32			psusercount;  /* Power save user count. */
	hfa384x_CommTallies32_t	tallies;      /* Communication tallies. */
	UINT8			comment[WLAN_COMMENT_MAX+1]; /* User comment */

	hfa384x_InfFrame_t      *scanresults;
} prism2sta_priv_t;


/*=============================================================*/
/*------ Static variable externs ------------------------------*/

#if (WLAN_HOSTIF != WLAN_USB)
extern int      prism2_bap_timeout;
#endif
extern int	prism2_debug;
extern int	prism2_irq_evread_max;

/*=============================================================*/
/*--- Function Declarations -----------------------------------*/
/*=============================================================*/

UINT32
prism2sta_ifstate(wlandevice_t *wlandev, UINT32 ifstate);

void
prism2sta_ev_dtim(wlandevice_t *wlandev);
void
prism2sta_ev_infdrop(wlandevice_t *wlandev);
void
prism2sta_ev_info(wlandevice_t *wlandev, hfa384x_InfFrame_t *inf);
void
prism2sta_ev_txexc(wlandevice_t *wlandev, UINT16 status);
void
prism2sta_ev_tx(wlandevice_t *wlandev, UINT16 status);
void
prism2sta_ev_rx(wlandevice_t *wlandev, struct sk_buff *skb);
void
prism2sta_ev_alloc(wlandevice_t *wlandev);


int prism2mgmt_mibset_mibget(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_powermgmt(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_scan(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_scan_results(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_join(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_p2_join(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_authenticate(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_deauthenticate(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_associate(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_reassociate(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_disassociate(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_reset(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_start(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_wlansniff(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_readpda(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_readcis(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_auxport_state(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_auxport_read(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_auxport_write(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_low_level(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_test_command(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_mmi_read(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_mmi_write(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_ramdl_state(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_ramdl_write(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_flashdl_state(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_flashdl_write(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_mm_state(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_dump_state(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_enable(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_channel_info(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_channel_info_results(wlandevice_t *wlandev, void *msgp);
int prism2mgmt_autojoin(wlandevice_t *wlandev, void *msgp);

/*---------------------------------------------------------------
* conversion functions going between wlan message data types and
* Prism2 data types 
---------------------------------------------------------------*/
/* byte area conversion functions*/
void prism2mgmt_pstr2bytearea(UINT8 *bytearea, p80211pstrd_t *pstr);
void prism2mgmt_bytearea2pstr(UINT8 *bytearea, p80211pstrd_t *pstr, int len);

/* byte string conversion functions*/
void prism2mgmt_pstr2bytestr(hfa384x_bytestr_t *bytestr, p80211pstrd_t *pstr);
void prism2mgmt_bytestr2pstr(hfa384x_bytestr_t *bytestr, p80211pstrd_t *pstr);

/* integer conversion functions */
void prism2mgmt_prism2int2p80211int(UINT16 *prism2int, UINT32 *wlanint);
void prism2mgmt_p80211int2prism2int(UINT16 *prism2int, UINT32 *wlanint);

/* enumerated integer conversion functions */
void prism2mgmt_prism2enum2p80211enum(UINT16 *prism2enum, UINT32 *wlanenum, UINT16 rid);
void prism2mgmt_p80211enum2prism2enum(UINT16 *prism2enum, UINT32 *wlanenum, UINT16 rid);

/* functions to convert a bit area to/from an Operational Rate Set */
void prism2mgmt_get_oprateset(UINT16 *rate, p80211pstrd_t *pstr);
void prism2mgmt_set_oprateset(UINT16 *rate, p80211pstrd_t *pstr);

/* functions to convert Group Addresses */
void prism2mgmt_get_grpaddr(UINT32 did, 
	p80211pstrd_t *pstr, prism2sta_priv_t *priv );
int prism2mgmt_set_grpaddr(UINT32 did, 
	UINT8 *prism2buf, p80211pstrd_t *pstr, prism2sta_priv_t *priv );
int prism2mgmt_get_grpaddr_index( UINT32 did );


#ifdef DECLARE_TASKLET
void prism2sta_linkstatus_defer(unsigned long data);
#else
void prism2sta_linkstatus_defer(void *data);
#endif

/*=============================================================*/
/*--- Inline Function Definitions (if supported) --------------*/
/*=============================================================*/



#endif
