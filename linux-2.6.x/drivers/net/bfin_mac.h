// -----------------------------------------------------------------------
//                     PHY REGISTER NAMES                               //
// -----------------------------------------------------------------------
#define PHYREG_MODECTL          0x0000
#define PHYREG_MODESTAT         0x0001
#define PHYREG_PHYID1           0x0002
#define PHYREG_PHYID2           0x0003
#define PHYREG_ANAR                     0x0004
#define PHYREG_ANLPAR           0x0005
#define PHYREG_ANER                     0x0006
#define PHYREG_NSR                      0x0010
#define PHYREG_LBREMR           0x0011
#define PHYREG_REC                      0x0012
#define PHYREG_10CFG            0x0013
#define PHYREG_PHY1_1           0x0014
#define PHYREG_PHY1_2           0x0015
#define PHYREG_PHY2                     0x0016
#define PHYREG_TW_1                     0x0017
#define PHYREG_TW_2                     0x0018
#define PHYREG_TEST                     0x0019


#define PHY_RESET               0x8000
#define PHY_ANEG_EN             0x1000
#define PHY_DUPLEX              0x0100
#define PHY_SPD_SET             0x2000

/* #define BFIN_MAC_CSUM_OFFLOAD */

typedef struct _DMA_CONFIG
{
  unsigned short b_DMA_EN:1;      //Bit 0 : DMA Enable
  unsigned short b_WNR:1;         //Bit 1 : DMA Direction
  unsigned short b_WDSIZE:2;      //Bit 2 & 3 : DMA Tranfer Word size
  unsigned short b_DMA2D:1;       //Bit 4 : DMA Mode 2D or 1D
  unsigned short b_RESTART:1;     //Bit 5 : Retain the FIFO
  unsigned short b_DI_SEL:1;      //Bit 6 : Data Interrupt Timing Select
  unsigned short b_DI_EN:1;       //Bit 7 : Data Interrupt Enable
  unsigned short b_NDSIZE:4;      //Bit 8 to 11 : Flex descriptor Size
  unsigned short b_FLOW:3;        //Bit 12 to 14 : FLOW
} DMA_CONFIG_REG;

struct dma_descriptor {
  struct dma_descriptor *next_dma_desc;
  unsigned long  start_addr;
  DMA_CONFIG_REG config;
  unsigned short x_count;
};

/*
struct status_area {
  unsigned short ip_hdr_chksum;         // the IP header checksum
  unsigned short ip_payload_chksum;     // the IP header and payload checksum
  unsigned long  status_word;           // the frame status word
};
*/
struct status_area {
#if defined(BFIN_MAC_CSUM_OFFLOAD)
	unsigned short ip_hdr_csum;         // ip header checksum
	unsigned short ip_payload_csum;     // ip payload(udp or tcp or others) checksum
#endif
	unsigned long  status_word;         // the frame status word
};


/* use two descriptors for a packet */
struct net_dma_desc {
  struct net_dma_desc *next;
  struct sk_buff *skb;
  struct dma_descriptor desc_a;
  struct dma_descriptor desc_b;
  volatile unsigned char   packet[1560];
  volatile struct status_area status;
};

struct bf537mac_local {
  /*
   * these are things that the kernel wants me to keep, so users
   * can find out semi-useless statistics of how well the card is
   * performing
   */
  struct net_device_stats stats;

  int     version;

  int FlowEnabled;       // record if data flow is active
  int EtherIntIVG;       // IVG for the ethernet interrupt
  int RXIVG;             // IVG for the RX completion
  int TXIVG;             // IVG for the TX completion
  int PhyAddr;           // PHY address
  int OpMode;            // set these bits n the OPMODE regs
  int Port10;           // set port speed to 10 Mbit/s
  int GenChksums;       // IP checksums to be calculated
  int NoRcveLnth;       // dont insert recv length at start of buffer
  int StripPads;        // remove trailing pad bytes
  int FullDuplex;       // set full duplex mode
  int Negotiate;        // enable auto negotiation
  int Loopback;         // loopback at the PHY
  int Cache;            // Buffers may be cached
  int FlowControl;      // flow control active
  int CLKIN;             // clock in value in MHZ
  unsigned short IntMask;  // interrupt mask
  unsigned char  Mac[6];     // MAC address of the board
  spinlock_t lock;
};

