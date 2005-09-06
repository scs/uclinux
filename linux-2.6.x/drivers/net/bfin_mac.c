

static const char version[] =
"bf53mac.c: v1.0, Aug 27 2005 by Luke Yang <luke.yang@analog.com>\n";

/* Debugging level */
#ifndef BF537MAC_DEBUG
#define BF537MAC_DEBUG               0
#endif

#include <linux/config.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/crc32.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/ethtool.h>
#include <linux/mii.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/dma.h>
#include <asm/dma-mapping.h>

#include "bfin_mac.h"
#include <asm/blackfin.h>

#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/delay.h>

MODULE_LICENSE("GPL");

#define CARDNAME "bfin_mac"

static void desc_list_free(void);

/* transmit net_dma_desc numbers */
#define  INIT_DESC_NUM 8
#define  MAX_DESC_NUM 64
#define  MAX_RX_DESC_NUM 8

/* pointers to maintain transmit list */
struct net_dma_desc *tx_list_head;
struct net_dma_desc *tx_list_tail;
struct net_dma_desc *rx_list_head;
struct net_dma_desc *rx_list_tail;
struct net_dma_desc *current_rx_ptr;

u8  SrcAddr[6] = {0x02,0x80,0xAD,0x20,0x31,0xB8};
int current_desc_num;
int first_packet = 1;

/*
static int adjust_tx_list(void) 
{
  struct net_dma_desc *tmp_ptr;
  int freed_no;

  tmp_ptr = tx_list_head;
  freed_no = 0;
  
  do {
    // go through the tx list, adjust head pointer 
    for (tmp_ptr = tx_list_head; tmp_ptr != tx_list_tail; tmp_ptr = tmp_ptr->next) {
      if (tmp_ptr->status.status_word & TX_COMP) { // this packet has been sent 
	tx_list_head = tx_list_head->next;
	freed_no++;
      } else { // get to a packet which is not sent 
	break;
      }
    }
  } while (freed_no == 0);

  return 0;
}
*/

static int desc_list_init(void) 
{
  struct net_dma_desc *tmp_desc;
  int i;
  dma_addr_t dma_handle;

  /* init tx_list */
  if (current_desc_num == 0) {
    for (i=0;i < INIT_DESC_NUM;i++) {
      tmp_desc = (struct net_dma_desc *)dma_alloc_coherent(NULL, sizeof(struct net_dma_desc), &dma_handle , GFP_DMA);
      if (tmp_desc == NULL) {
	goto error;
      }

      if (i == 0) {
	tx_list_head = tmp_desc;
	tx_list_tail = tmp_desc;
      }

      tmp_desc->desc_a.start_addr = (unsigned long)tmp_desc->packet;
      tmp_desc->desc_a.x_count = 0;
      tmp_desc->desc_a.config.b_DMA_EN = 1;        //disabled
      tmp_desc->desc_a.config.b_WNR    = 0;        //read from memory
      tmp_desc->desc_a.config.b_WDSIZE = 2;        //wordsize is 32 bits
      tmp_desc->desc_a.config.b_NDSIZE = 6;        //6 half words is desc size.
      tmp_desc->desc_a.config.b_FLOW   = 7;        //large desc flow
      tmp_desc->desc_a.next_dma_desc = &(tmp_desc->desc_b);

      tmp_desc->desc_b.start_addr = (unsigned long)(&(tmp_desc->status));
      tmp_desc->desc_b.x_count = 0;
      tmp_desc->desc_b.config.b_DMA_EN = 1;        //disabled
      tmp_desc->desc_b.config.b_WNR    = 1;        //write to memory
      tmp_desc->desc_b.config.b_WDSIZE = 2;        //wordsize is 32 bits
      tmp_desc->desc_b.config.b_NDSIZE = 0;        
      tmp_desc->desc_b.config.b_FLOW   = 0;        //stop mode
      tx_list_tail->desc_b.next_dma_desc = &(tmp_desc->desc_a);      
      tx_list_tail->next = tmp_desc;

      tx_list_tail = tmp_desc;
    }
    tx_list_tail->next = tx_list_head;  /* tx_list is a circle */
    tx_list_tail->desc_b.next_dma_desc = &(tx_list_head->desc_a);
    current_desc_num = INIT_DESC_NUM;
  }

  /* init rx_list */
  for (i = 0; i < MAX_RX_DESC_NUM; i++) {
    tmp_desc = (struct net_dma_desc *)dma_alloc_coherent(NULL, sizeof(struct net_dma_desc), &dma_handle , GFP_DMA);
    if (tmp_desc == NULL) {
      goto error;
    }

    if (i == 0) {
      rx_list_head = tmp_desc;
      rx_list_tail = tmp_desc;
    }

    tmp_desc->desc_a.start_addr = (unsigned long)tmp_desc->packet;
    tmp_desc->desc_a.x_count = 0;
    tmp_desc->desc_a.config.b_DMA_EN = 1;        //enabled
    tmp_desc->desc_a.config.b_WNR    = 1;        //Write to memory
    tmp_desc->desc_a.config.b_WDSIZE = 2;        //wordsize is 32 bits
    tmp_desc->desc_a.config.b_NDSIZE = 6;        //6 half words is desc size.
    tmp_desc->desc_a.config.b_FLOW   = 7;        //large desc flow
    tmp_desc->desc_a.next_dma_desc = &(tmp_desc->desc_b);

    tmp_desc->desc_b.start_addr = (unsigned long)(&(tmp_desc->status));    
    tmp_desc->desc_b.x_count = 0;
    tmp_desc->desc_b.config.b_DMA_EN = 1;        //enabled
    tmp_desc->desc_b.config.b_WNR    = 1;        //Write to memory
    tmp_desc->desc_b.config.b_WDSIZE = 2;        //wordsize is 32 bits
    tmp_desc->desc_b.config.b_NDSIZE = 0;        
    tmp_desc->desc_b.config.b_DI_EN  = 1;        //enable interrupt
    tmp_desc->desc_b.config.b_FLOW   = 0;        //stop
    rx_list_tail->desc_b.next_dma_desc = &(tmp_desc->desc_a);
  
    rx_list_tail->next = tmp_desc;
    rx_list_tail = tmp_desc;
  }
  rx_list_tail->next = rx_list_head;  /* rx_list is a circle */
  rx_list_tail->desc_b.next_dma_desc = &(rx_list_head->desc_a);
  current_rx_ptr = rx_list_head;

  return 0;

 error:
  desc_list_free();
  printk("bf537mac: kmalloc failed. \n");
  return -ENOMEM;
}

static void desc_list_free(void)
{
  struct net_dma_desc *tmp_desc;
  int i;
  dma_addr_t dma_handle = 0;

  for (tmp_desc = tx_list_head; tmp_desc->next != tx_list_head; tmp_desc = tmp_desc->next)
    if (tmp_desc != NULL) 
      dma_free_coherent(NULL, sizeof(struct net_dma_desc), tmp_desc, dma_handle);

  tmp_desc = rx_list_head;
  for (i = 0; i < MAX_RX_DESC_NUM; i++) {
    if (tmp_desc != NULL)
      dma_free_coherent(NULL, sizeof(struct net_dma_desc), tmp_desc, dma_handle);
    tmp_desc = tmp_desc->next;
  }
}


/*---PHY CONTROL AND CONFIGURATION-----------------------------------------*/

//
//Set FER regs to MUX in Ethernet pins
//

static void SetupPinMux(void)
{
  unsigned int fer_val;
  
  // FER reg bug work-around
  // read it once
  fer_val = *pPORTH_FER;
  
  fer_val = 0xffff;
  
  // write it twice to the same value
  
  *pPORTH_FER = fer_val;
  *pPORTH_FER = fer_val;
}


//
//Wait until the previous MDC/MDIO transaction has completed
//

static void PollMdcDone(void)
{
  // poll the STABUSY bit
  while((*pEMAC_STAADD) & STABUSY) {};
}


//
//Read an off-chip register in a PHY through the MDC/MDIO port
//

static u16 RdPHYReg(u16 PHYAddr, u16 RegAddr)
{
  PollMdcDone();
  *pEMAC_STAADD = SET_PHYAD(PHYAddr) | SET_REGAD(RegAddr) | STABUSY;     // read mode 
  PollMdcDone();
  
  return (u16)*pEMAC_STADAT;
}

//
//Write an off-chip register in a PHY through the MDC/MDIO port
//

static void RawWrPHYReg(u16 PHYAddr, u16 RegAddr, u32 Data)
{
  
  *pEMAC_STADAT = Data;

  *pEMAC_STAADD = SET_PHYAD(PHYAddr) | SET_REGAD(RegAddr) |
    STAOP | STABUSY;     //write mode

  PollMdcDone();
}

static void WrPHYReg(u16 PHYAddr, u16 RegAddr, u32 Data)
{
  PollMdcDone();
  RawWrPHYReg(PHYAddr,RegAddr,Data);
}

//
//set up the phy
//
static int bf537mac_setphy(struct net_device *dev)
{
  u16 phydat;
  u32 sysctl;
  struct bf537mac_local *lp = netdev_priv(dev);
  
  printk("bf537_mac: start settting up phy\n");

  //Program PHY registers
  phydat = 0;
  
  // issue a reset
  RawWrPHYReg(lp->PhyAddr, PHYREG_MODECTL, 0x8000);

  // wait half a second
  udelay(500);

  phydat = RdPHYReg(lp->PhyAddr, PHYREG_MODECTL);
  

  // advertise flow control supported
  phydat = RdPHYReg(lp->PhyAddr, PHYREG_ANAR);
  phydat |= (1 << 10);
  WrPHYReg(lp->PhyAddr, PHYREG_ANAR, phydat);


  phydat = 0;
  if (lp->Negotiate) {
    phydat |= 0x1000;// enable auto negotiation
  } else {
    if (lp->FullDuplex) {
      phydat |= (1 << 8);// full duplex
    } else {
      phydat &= (~(1 << 8));// half duplex
    }
    if (!lp->Port10) {
      phydat |= (1 << 13);// 100 Mbps
    } else {
      phydat &= (~(1 << 13));// 10 Mbps
    }
  }

  if (lp->Loopback) {
    phydat |= (1 << 14);// enable TX->RX loopback
    //WrPHYReg(lp->PhyAddr, PHYREG_MODECTL, phydat);
  }

  WrPHYReg(lp->PhyAddr, PHYREG_MODECTL, phydat);
  udelay(500);

  phydat = RdPHYReg(lp->PhyAddr, PHYREG_MODECTL);
  // check for SMSC PHY
  if ((RdPHYReg(lp->PhyAddr, PHYREG_PHYID1) == 0x7) && ((RdPHYReg(lp->PhyAddr, PHYREG_PHYID2)&0xfff0 ) == 0xC0A0)) {
    // we have SMSC PHY so reqest interrupt on link down condition
    WrPHYReg(lp->PhyAddr, 30, 0x0ff); // enable interrupts
    // enable PHY_INT
    sysctl = *pEMAC_SYSCTL;
    sysctl |= 0x1;
    //*pEMAC_SYSCTL = sysctl;
  }
}


/**************************************************************************/
void SetupSystemRegs(struct net_device *dev)
{
  int PHYADDR;  
  unsigned short sysctl, phydat;
  struct bf537mac_local *lp = netdev_priv(dev);

  PHYADDR = lp->PhyAddr;

  /* Enable PHY output */
  *pVR_CTL |= PHYCLKOE;
  /* MDC  = 2.5 MHz */
  sysctl = SET_MDCDIV(24);
  /* Odd word alignment for Receive Frame DMA word */
  /* Configure checksum support and rcve frame word alignment */
  sysctl |= RXDWA;
  *pEMAC_SYSCTL  = sysctl;
  /* auto negotiation on  */
  /* full duplex          */
  /* 100 Mbps             */
  phydat = PHY_ANEG_EN | PHY_DUPLEX | PHY_SPD_SET;
  WrPHYReg(PHYADDR, PHYREG_MODECTL, phydat);

  //*pEMAC_MMC_CTL = RSTC | CROLL | MMCE;
  *pEMAC_MMC_CTL = RSTC | CROLL;

  /* Initialize the TX DMA channel registers */
  *pDMA2_X_COUNT  = 0;
  *pDMA2_X_MODIFY = 4;
  *pDMA2_Y_COUNT  = 0;
  *pDMA2_Y_MODIFY = 0;

  /* Initialize the RX DMA channel registers */
  *pDMA1_X_COUNT  = 0;
  *pDMA1_X_MODIFY = 4;
  *pDMA1_Y_COUNT  = 0;
  *pDMA1_Y_MODIFY = 0;
}

void SetupMacAddr(u8 *mac_addr)
{
  // this depends on a little-endian machine
  *pEMAC_ADDRLO = *(u32 *)&mac_addr[0];
  *pEMAC_ADDRHI = *(u16 *)&mac_addr[4];
}



static int bf537mac_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
  unsigned short len;
  struct net_dma_desc *tail;
  struct bf537mac_local *lp = netdev_priv(dev);
  
  len = skb->len;
  tail = tx_list_tail;

  /* adjust head and tail pointer */
  //adjust_tx_list();
  //if(!first_packet) { 
  //  while(tail->status.status_word == 0) ;
  //}

  /* add the packet to tail */
  *(tail->packet) = (unsigned short)len; 
  memcpy((char *)(tail->packet + 2),skb->data,len);
  
  /* change this packet's desc to DMA enabled */
  tail->desc_a.config.b_DMA_EN = 1;

  *pDMA2_NEXT_DESC_PTR = (&(tail->desc_a));
  *pDMA2_CONFIG  = *((unsigned short *)(&(tail->desc_a.config)));; // dma enabled, read from memory, size is 6

  
  //if (first_packet) {  
    /* Turn on the EMAC tx */
  *pEMAC_OPMODE |= TE;
    //  first_packet = 0;
    //}
  //  while(tail->status.status_word == 0);
  
  while ((*pDMA2_IRQ_STATUS & 0x01) == 0);

  //*pEMAC_OPMODE &= ~TE;
  //tail->status.status_word = 0;
 
  /* if dma is running (transferring last packets), don't need to do anything. */

  //tx_list_tail = tail->next;
  //StatusWord = 0x00000000?
  dev->trans_start = jiffies;
  lp->stats.tx_packets++;
  lp->stats.tx_bytes += len;

  dev_kfree_skb(skb);
  return 0;
}

static void bf537mac_rx(struct net_device *dev, unsigned char *pkt, int len)
{
  struct sk_buff *skb;
  struct bf537mac_local *lp = netdev_priv(dev);
  
  skb = dev_alloc_skb(len + 2);
  if (!skb) {
    printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
    lp->stats.rx_dropped++;
    goto out;
  }
  skb_reserve(skb, 2);
  memcpy(skb_put(skb, len), pkt+2, len);
  
  dev->last_rx = jiffies;
  skb->dev = dev;
  skb->protocol = eth_type_trans(skb, dev);
  netif_rx(skb);
  lp->stats.rx_packets++;
  lp->stats.rx_bytes += len;

 out:
  return;
}


/* interrupt routine to handle rx and error signal */
static irqreturn_t bf537mac_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
  struct net_device *dev = dev_id;
  unsigned short len;
  int pkt_status,mac_status, rx_status, dma_status;

  pkt_status = current_rx_ptr->status.status_word;
  mac_status = *pEMAC_SYSTAT;
  rx_status  = *pEMAC_RX_STAT;
  dma_status = *pDMA1_IRQ_STATUS;
  
  /*
  printk("next_dma_ptr reg is 0x%x, current_rx_ptr->desc_a is 0x%x, current_rx_ptr->next->desc_a is 0x%x \n", (unsigned int)(*pDMA1_NEXT_DESC_PTR), (unsigned int)&(current_rx_ptr->desc_a), (unsigned int)&(current_rx_ptr->next->desc_a));
  printk("next_dma_ptr reg is 0x%x, current_rx_ptr->desc_a is 0x%x, current_rx_ptr is 0x%x, current_rx_ptr->desc_b.startaddr is 0x%x \n", (unsigned int)(*pDMA1_NEXT_DESC_PTR), (unsigned int)&(current_rx_ptr->desc_b), (unsigned int)(current_rx_ptr->status.status_word), (unsigned int)(current_rx_ptr->desc_b.start_addr));
  printk("reg curr_dma_reg is 0x%x, curr start_add is 0x%x, next_dma_reg is 0x%x\n", (unsigned int)(*pDMA1_CURR_DESC_PTR), (unsigned int)(*pDMA1_CURR_ADDR), (unsigned int)(*pDMA1_NEXT_DESC_PTR));
  */

  if ((pkt_status & RX_COMP) == 0) { // no packet received
    printk("no packet received!, pkt_status is 0x%x, mac_status is 0x%x, rx_status is 0x%x, dma_staus 0x%x \n\n", pkt_status,mac_status,rx_status,dma_status);
    return IRQ_HANDLED;
  }
  
  while(((current_rx_ptr->status.status_word) & RX_COMP) != 0) {
    len = (unsigned short)((current_rx_ptr->status.status_word) & RX_FRLEN);
    bf537mac_rx(dev, (char *)(current_rx_ptr->packet), len);
    
    current_rx_ptr->status.status_word = 0x00000000;
    current_rx_ptr = current_rx_ptr->next;
  }

  *pDMA1_IRQ_STATUS |= DMA_DONE|DMA_ERR;
  *pDMA1_CONFIG &= ~0x01;
  *pDMA1_CONFIG = *((unsigned short *)(&(current_rx_ptr->desc_a.config)));
  
  return IRQ_HANDLED;
}


static void bf537mac_reset(void)
{
  unsigned int opmode;
  
  opmode = *pEMAC_OPMODE;
  opmode &= (~RE);
  opmode &= (~TE);
  /* Turn off the EMAC */
  *pEMAC_OPMODE &= opmode;
}

/*
 * Enable Interrupts, Receive, and Transmit
 */
static int bf537mac_enable(struct net_device *dev)
{
  u32 opmode;
  //u32 pkt_status;

  printk("%s: %s\n", dev->name, __FUNCTION__);

  /* Set RX DMA */
  *pDMA1_NEXT_DESC_PTR = &(rx_list_head->desc_a);
  *pDMA1_CONFIG = *((unsigned short *)(&(rx_list_head->desc_a.config)));

  /* Wait MII done */
  PollMdcDone();

  /* We enable only RX here */
  /* ASTP   : Enable Automatic Pad Stripping
   PR     : Promiscuous Mode for test
   PSF    : Receive frames with total length less than 64 bytes.
   FDMODE : Full Duplex Mode
   LB     : Internal Loopback for test
   RE     : Receiver Enable */
  opmode = FDMODE|PSF;
  opmode |= RE;
  /* Turn on the EMAC rx */
  *pEMAC_OPMODE = opmode;

  return 0;
}

/* Our watchdog timed out. Called by the networking layer */
static void bf537mac_timeout(struct net_device *dev)
{
  printk("%s: %s\n", dev->name, __FUNCTION__);

  bf537mac_reset();

  /* reset tx queue */
  tx_list_tail = tx_list_head->next;

  bf537mac_enable(dev);

  /* We can accept TX packets again */
  dev->trans_start = jiffies;
  netif_wake_queue(dev);
}

/*
 * Get the current statistics.
 * This may be called with the card open or closed.
 */
static struct net_device_stats *bf537mac_query_statistics(struct net_device *dev)
{
  struct bf537mac_local *lp = netdev_priv(dev);

  //printk("%s: %s\n", dev->name, __FUNCTION__);

  return &lp->stats;
}

/*
 * This routine will, depending on the values passed to it,
 * either make it accept multicast packets, go into
 * promiscuous mode (for TCPDUMP and cousins) or accept
 * a select set of multicast packets
 */
static void bf537mac_set_multicast_list(struct net_device *dev)
{

}



/*
 * this puts the device in an inactive state
 */
static void bf537mac_shutdown(struct net_device *dev)
{
  printk("Eth_shutdown: ......\n");
  
  /* Turn off the EMAC */
  *pEMAC_OPMODE = 0x00000000;
  /* Turn off the EMAC RX DMA */
  *pDMA1_CONFIG = 0x0000;
  *pDMA2_CONFIG = 0x0000;
}


/*
 * Open and Initialize the interface
 *
 * Set up everything, reset the card, etc..
 */
static int bf537mac_open(struct net_device *dev)
{
  printk("%s: %s\n", dev->name, __FUNCTION__);

  /*
   * Check that the address is valid.  If its not, refuse
   * to bring the device up.  The user must specify an
   * address using ifconfig eth0 hw ether xx:xx:xx:xx:xx:xx
   */
  if (!is_valid_ether_addr(dev->dev_addr)) {
    printk((KERN_DEBUG "bf537mac_open: no valid ethernet hw addr\n"));
    return -EINVAL;
  }


  /* initial rx and tx list */
  desc_list_init();
  
  bf537mac_setphy(dev); 
  SetupSystemRegs(dev); 
  bf537mac_reset(); 
  bf537mac_enable(dev); 
  
  printk("bf537_mac: hardware init finished\n");
  netif_start_queue(dev); 
  
  return 0;
}

/*
 *
 * this makes the board clean up everything that it can
 * and not talk to the outside world.   Caused by
 * an 'ifconfig ethX down'
 */
static int bf537mac_close(struct net_device *dev)
{
  printk("%s: %s\n", dev->name, __FUNCTION__);

  netif_stop_queue(dev);
  netif_carrier_off(dev);

  /* clear everything */
  bf537mac_shutdown(dev);

  return 0;
}


static int __init bf537mac_probe(struct net_device *dev)
{
  struct bf537mac_local *lp = netdev_priv(dev);
  unsigned long tmp;
  int retval;

  /* probe mac */
  //todo: how to proble? which is revision_register
  *pEMAC_ADDRLO = 0x12345678;
  tmp = *pEMAC_ADDRLO;
  if (tmp != 0x12345678) {
    printk("bf537_mac: can't detect bf537 mac!\n");
    retval = -ENODEV;
    goto err_out;
  }

  //GET_MAC_ADDR(dev->dev_addr);
  {
    dev->dev_addr[0] = 0x00; dev->dev_addr[1] = 0xcf;
    dev->dev_addr[2] = 0x52; dev->dev_addr[3] = 0x49;
    dev->dev_addr[4] = 0xc3; dev->dev_addr[4] = 0x01;
  }
  SetupMacAddr(dev->dev_addr);

  /* Fill in the fields of the device structure with ethernet values. */
  ether_setup(dev);

  dev->open = bf537mac_open;
  dev->stop = bf537mac_close;
  dev->hard_start_xmit = bf537mac_hard_start_xmit;
  dev->tx_timeout = bf537mac_timeout;
  dev->get_stats = bf537mac_query_statistics;
  dev->set_multicast_list = bf537mac_set_multicast_list;
  //  dev->ethtool_ops = &bf537mac_ethtool_ops;
#ifdef CONFIG_NET_POLL_CONTROLLER
  dev->poll_controller = bf537mac_poll_controller;
#endif

  /* fill in some of the fields */
  lp->version = 1;
  lp->PhyAddr = 0x01;
  lp->CLKIN = 25;
  lp->FullDuplex = 0;
  lp->Negotiate = 1;
  lp->FlowControl = 0;
  

  // set the GPIO pins to Ethernet mode
  SetupPinMux();

  /* now, enable interrupts */
  /* register irq handler */
  if (request_irq(IRQ_MAC_RX, bf537mac_interrupt, SA_INTERRUPT|SA_SHIRQ, "BFIN537_MAC_RX",dev)) {
    printk("Unable to attach BlackFin MAC RX interrupt\n");
    return -EBUSY;
  }
  

  /*
  if (request_irq(IRQ_MAC_ERROR, bf537mac_interrupt, SA_INTERRUPT|SA_SHIRQ, "BFIN537_MAC_ERROR",lp)) {
    printk("Unable to attach BlackFin MAC error interrupt\n"); 
    return -EBUSY; 
  }
  */


  retval = register_netdev(dev);
  if (retval == 0) {
    /* now, print out the card info, in a short format.. */
    printk("Blackfin 537 mac net device registered.\n");
  }
  
 err_out:
  return retval;
}

static int bf537mac_drv_probe(struct device *dev)
{
  struct net_device *ndev;
  int ret=0;
  
  ndev = alloc_etherdev(sizeof(struct bf537mac_local));

  if (!ndev) {
    printk("%s: could not allocate device.\n", CARDNAME);
    ret = -ENOMEM;
    return ret;
  }

  ret = bf537mac_probe(ndev);
  if (ret != 0) {
    dev_set_drvdata(dev, NULL);
    free_netdev(ndev);
    printk("%s: not found (%d).\n", CARDNAME, ret);
  }
  
  SET_MODULE_OWNER(ndev);
  SET_NETDEV_DEV(ndev, dev);

  dev_set_drvdata(dev, ndev);

  printk("bf537_mac: probe finished\n");
  return ret;
}


static int bf537mac_drv_remove(struct device *dev)
{
  struct net_device *ndev = dev_get_drvdata(dev);

  dev_set_drvdata(dev, NULL);

  unregister_netdev(ndev);

  free_irq(IRQ_MAC_RX, ndev);
  free_irq(IRQ_MAC_ERROR, ndev);

  free_netdev(ndev);

  return 0;
}

static int bf537mac_drv_suspend(struct device *dev, u32 state, u32 level)
{
  return 0;
}

static int bf537mac_drv_resume(struct device *dev, u32 level)
{
  return 0;
}


static struct device_driver bf537mac_driver = {
  .name           = CARDNAME,
  .bus            = &platform_bus_type,
  .probe          = bf537mac_drv_probe,
  .remove         = bf537mac_drv_remove,
  .suspend        = bf537mac_drv_suspend,
  .resume         = bf537mac_drv_resume,
};

static int __init bf537mac_init(void)
{
  return driver_register(&bf537mac_driver);
}

static void __exit bf537mac_cleanup(void)
{
  driver_unregister(&bf537mac_driver);
}

module_init(bf537mac_init);
module_exit(bf537mac_cleanup);

