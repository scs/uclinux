/* can_bf537funcs.c  - Analog Devices BlackFin CAN functions
 *
 * can4linux -- LINUX CAN device driver source
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 *
 * Copyright (c) 2003-2006 port GmbH Halle/Saale
 * (c) 2006 Heinz-Jürgen Oertel (oe@port.de)
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 *  The driver is simulating a so-called Basic CAN concept,
 *  thats can4linux was designed for.
 *  There is on the users API only one chanell to send CAN frames,
 *  the write() call, and only one to receive, the read(call).
 *
 * ???
 *  The BlackFin CAN is a Full CAN controller,
 *  providing 32 Message Buffers (Mailboxes according the doc.)
 *  The first 8 can be used only as receivers.
 *  MBs 8-23 can be configured for RX or TX.
 *  MBs 24-31 can be used as transmitters only.
 *  The driver only uses the following MBs:
 *
 *  TRAMSMIT_OBJ  - used to transmit messages, possible are:
 *  	standard, extended, standard RTR, extended RTR
 *  RECEIVE_STD_OBJ - used to receice all messages in base frame format
 *  RECEIVE_EXT_OBJ - used to receice all messages in extended frame format
 *  RECEIVE_RTR_OBJ - what be nice to have, but this doesn't work
 *        the driver is not able to receive any RTE frames.
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.1  2006/01/31 09:11:45  hennerich
 * Initial checkin can4linux driver Blackfin BF537/6/4 Task[T128]
 *
 *
 *
 *
 */
#include "defs.h"
#include <linux/delay.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
# error use the BlackFin CAN only with Kernel > 2.6
#endif

/* timing values */
static const BTR_TAB_BFCAN_T can_btr_tab_bfcan[] = {
 /* {   10, CAN_BRP_10K,   CAN_TSEG_10K  }, */
 /* {   20, CAN_BRP_20K,   CAN_TSEG_20K  }, */
 /* {   50, CAN_BRP_50K,   CAN_TSEG_50K  }, */
 {  100, CAN_BRP_125K,   CAN_TSEG_125K  },
 {  125, CAN_BRP_125K,   CAN_TSEG_125K  },
 {  250, CAN_BRP_250K,   CAN_TSEG_250K  },
 {  500, CAN_BRP_500K,   CAN_TSEG_500K  },
 /* {  800, CAN_BRP_125K,   CAN_TSEG_125K  }, */
 { 1000, CAN_BRP_1000K,   CAN_TSEG_1000K  },

 {0, 0, 0}  /* last entry */
};




/* Board reset
   means the following procedure:
  set Reset Request
  wait for Rest request is changing - used to see if board is available
  initialize board (with valuse from /proc/sys/Can)
    set output control register
    set timings
    set acceptance mask
*/


#ifdef DEBUG
int CAN_ShowStat (int minor)
{
    if (dbgMask && (dbgMask & DBG_DATA)) {
    printk("\n");
    }
    return 0;
}
#endif


/* can_GetStat - read back as many status information as possible
*
* Because the CAN protocol itself describes different kind of information
* already, and the driver has some generic information
* (e.g about it's buffers)
* we can define a more or less hardware independent format.
*
* The FlexCAN modul provides status and error-status information
* in one 16 bit register: Error and Status Flag - ESTAT.
* Therfore this content is used twice in the returned 
* CanStatusPar_t structure.
*/

int can_GetStat(
	struct inode *inode,
	CanStatusPar_t *stat
	)
{
unsigned int minor = MINOR(inode->i_rdev);
msg_fifo_t *Fifo;
unsigned long flags;


    stat->type = CAN_TYPE_BlackFinCAN;

    stat->baud = Baud[minor];
    stat->status = CANinw(minor, canstatus);
    /* BFCAN has separate RX and TX warning limits, use RX */
    stat->error_warning_limit = (CANinw(minor, canewr) & 0x00ff);
    stat->rx_errors           = (CANinw(minor, cancec) & 0x00ff);
    stat->tx_errors           = ((CANinw(minor, cancec) & 0xff00) >> 8);
    /* error code is not available, use error status */
    stat->error_code= CANinw(minor, canesr);

    /* Collect information about the RX and TX buffer usage */
    /* Disable CAN Interrupts */
    /* !!!!!!!!!!!!!!!!!!!!! */
    local_irq_save(flags);

    Fifo = &Rx_Buf[minor];
    stat->rx_buffer_size = MAX_BUFSIZE;	/**< size of rx buffer  */
    /* number of messages */
    stat->rx_buffer_used =
    	(Fifo->head < Fifo->tail)
    	? (MAX_BUFSIZE - Fifo->tail + Fifo->head) : (Fifo->head - Fifo->tail);
    Fifo = &Tx_Buf[minor];
    stat->tx_buffer_size = MAX_BUFSIZE;	/* size of tx buffer  */
    /* number of messages */
    stat->tx_buffer_used =
    	(Fifo->head < Fifo->tail)
    	? (MAX_BUFSIZE - Fifo->tail + Fifo->head) : (Fifo->head - Fifo->tail);
    /* Enable CAN Interrupts */
    /* !!!!!!!!!!!!!!!!!!!!! */
    local_irq_restore(flags);

    return 0;
}



/*
 * CAN_ChipReset - performs the first initialization or re-iniatalization of the chip
 *
 *  set INIT mode
 *  initialize the I/O pin modes as CAN TX/RX
 *  initialize the CAN bit timing
 *  initialize message buffers
 *  initialize interrut sources
 */
int CAN_ChipReset (int minor)
{
int i;
short temp_fix;		/* work-around to anomaly #22 to write PORT_MUX */

    DBGin("CAN_ChipReset");
    /* 
     * Initialize Port Pins to have CAN TX/RX signals enabled 
     * on GPIO port
     */
#if 0
/* Use defines from mach-bf537/defBF534.h
   and code from the "CAN_TX_RX_EXAMPLE/".
 */
#define PORT_MUX 0xFFC0320C	/* Port Multiplexer Control Register */
#define pPORT_MUX((volatile unsigned short *)PORT_MUX)
#endif

    temp_fix = *pPORT_MUX;   /* #22 work-around, read PORT_MUX before writing */
    __builtin_bfin_ssync();

    *pPORT_MUX = PJCE_CAN;   /* Enable CAN Pins On Port J */
    __builtin_bfin_ssync();
    *pPORT_MUX = PJCE_CAN;   /* #22 work-around: write it a few times */
    __builtin_bfin_ssync();
    *pPORT_MUX = PJCE_CAN;   /* #22 work-around: write it a few times */
    __builtin_bfin_ssync();

    temp_fix = *pPORT_MUX;   /* #22 work-around: read PORT_MUX after writing */
    __builtin_bfin_ssync();

    /* printk(KERN_INFO "Set CAN TX/RX pins at %p to %04x\n", pPORT_MUX, temp_fix); */

    /* SW Reset */
    CANoutw(minor, cancontrol, (CAN_SRS | CAN_CCR));
    __builtin_bfin_ssync();
    CANoutw(minor, cancontrol, (CAN_CCR));
    __builtin_bfin_ssync();

    /*
     * go to INIT mode
     * Any configuration change/initialization requires that the BF CAN 
     * is in configuration mode 
     */

    /* set the basic mode we want to use and go to configuration mode
	! CAN_SRS	Software Reset
	! CAN_DNM	Device Net Mode
	! CAN_ABO	Auto-Bus On Enable
	! CAN_TXPRIO	TX Priority (Priority/Mailbox*)
	! CAN_WBA	Wake-Up On CAN Bus Activity Enable
	! CAN_SMR	Sleep Mode Request
	! CAN_CSR	CAN Suspend Mode Request
	CAN_CCR		CAN Configuration Mode Request
     */
    CANoutw(minor, cancontrol, ( CAN_CCR  ));
    for( i = 10000 ; i != 0; i--) {
	if ( CANinw(minor, canstatus) & CAN_CCA) break; 
    }
    /* FIXME: use better return value ? */
    if (i == 0) {
        printk(KERN_INFO " CAN configuration mode not reached\n");
	DBGout();
	return -ENXIO; /* configuration mode not reached */
    }

    CAN_SetTiming(minor, Baud[minor]);

    /*
     * Initialize all message buffers.
     * All mailbox configurations are marked as inactive
     * by writing to CAN Mailbox Configuration Registers 1 and 2
     * For all bits: 0 - Mailbox disabled, 1 - Mailbox enabled
     */
    CANoutw(minor, canmc1, 0);
    CANoutw(minor, canmc2, 0);


    /* Create some objects, first defining data direction for RX or TX 
     *
     * For all bits, 0 - Mailbox configured as transmit mode,
     *               1 - Mailbox configured as receive mode
     */


    /* create a transmit object, that can be used for all kinds of messages
	Mailboxes 24-31 are dedicated transmitters.
	Mailboxes 8-23 can be configured as transmitters by registers mdx.
	We use a fixed mbox here choosing 24 (defs.h TRANSMIT_OBJ)
    */

    /* Set Mailbox Direction */
    CANoutw(minor, canmd1, 0xFFFF);		/* mailbox 1-16 are RX */
    CANoutw(minor, canmd2, 0x0000);	/* mailbox 17-32 enabled for TX */

    /* Remote Frame Handling needs not to be set, it's reset value is 0 */

    /* ---- RECEIVE_STD_OBJ ------------- */
    CAN_WRITE_OID(RECEIVE_STD_OBJ, 0);
    CAN_OBJ[RECEIVE_STD_OBJ].id0 = 0;      /* is unused but anyway set to 0 */
    CAN_WRITE_CTRL(RECEIVE_STD_OBJ, 0);
    CAN_MASK[RECEIVE_STD_OBJ].amh = 0x1FFF;
    CAN_MASK[RECEIVE_STD_OBJ].aml = 0xFFFF;

    /* ---- RECEIVE_EXT_OBJ ------------- */
    CAN_WRITE_XOID(RECEIVE_EXT_OBJ, 0);
    CAN_WRITE_CTRL(RECEIVE_EXT_OBJ, 0);
    CAN_MASK[RECEIVE_EXT_OBJ].amh = 0x1FFF;
    CAN_MASK[RECEIVE_EXT_OBJ].aml = 0xFFFF;
#if 0
    /* ---- RECEIVE_RTR_OBJ ------------- */
    CAN_WRITE_OID_RTR(RECEIVE_RTR_OBJ, 0);
    CAN_OBJ[RECEIVE_RTR_OBJ].id0 = 0;      /* is unused but anyway set to 0 */
    CAN_WRITE_CTRL(RECEIVE_RTR_OBJ, 0);
    CAN_MASK[RECEIVE_RTR_OBJ].amh = 0x1FFF;
    CAN_MASK[RECEIVE_RTR_OBJ].aml = 0xFFFF;
#endif

    /* Enable Mailboxes */
    CANoutw(minor, canmc2, 1 << (TRANSMIT_OBJ - 16));	/* TX mailboxes */
    CANoutw(minor, canmc1, 
	  (1 << RECEIVE_STD_OBJ)
	+ (1 << RECEIVE_EXT_OBJ)
	/* + (1 << RECEIVE_RTR_OBJ) */ );		/* RX mailboxes */


    __builtin_bfin_ssync();



#if 0  /* Test if a message is sent */
       /* if this code snipped is enabled it will prepare 
          the transmit objetc for sending 
          and issues a transmission request
        */

    CAN_WRITE_OID(TRANSMIT_OBJ, 0xaa);
    CAN_WRITE_CTRL(TRANSMIT_OBJ, 4);


    { /* Set transmission request */
    volatile bf_can_t *bf_canTmp = (bf_can_t *)(BFCAN_BASE);
    volatile int trs, trr, ta, aa;

	bf_canTmp->cantrs2 = 1 << (TRANSMIT_OBJ - 16);
	/* See what the bits are doing */
    __builtin_bfin_ssync();
	trs = bf_canTmp->cantrs2;
	trr = bf_canTmp->cantrr2;
	ta  = bf_canTmp->canta2;
	aa  = bf_canTmp->canaa2;
	printk("trs %04x, trr %04x, ta %04x, aa %04x\n", trs, trr, ta, aa);
	msleep(100);
    __builtin_bfin_ssync();
	trs = bf_canTmp->cantrs2;
	trr = bf_canTmp->cantrr2;
	ta  = bf_canTmp->canta2;
	aa  = bf_canTmp->canaa2;
	printk("trs %04x, trr %04x, ta %04x, aa %04x\n", trs, trr, ta, aa);
	msleep(200);
    __builtin_bfin_ssync();
	trs = bf_canTmp->cantrs2;
	trr = bf_canTmp->cantrr2;
	ta  = bf_canTmp->canta2;
	aa  = bf_canTmp->canaa2;
	printk("trs %04x, trr %04x, ta %04x, aa %04x\n", trs, trr, ta, aa);


    }
#endif /* Test */

    /* CAN_register_dump(); */
    /* CAN_object_dump(TRANSMIT_OBJ); */
    /* CAN_object_dump(RECEIVE_STD_OBJ); */
    /* CAN_object_dump(RECEIVE_EXT_OBJ); */
    /* CAN_object_dump(RECEIVE_RTR_OBJ); */
    /* CAN_object_dump(RECEIVE_RTR_OBJ); */

    __builtin_bfin_ssync();

#if CONFIG_TIME_MEASURE
    /* do we have some LEDS on the EVA board, use LED1*/
    /* initialize Port pins for time measurement */
    {
	*pFIO_DIR |= (1 << 6);
	*pFIO_INEN &= ~(1 << 6);
    }
#endif

    /* CAN_register_dump(); */
    DBGout();
    return 0;
}


/*
 * Configures bit timing registers directly. Chip must be in bus off state.
 */
int CAN_SetBTR (int minor, int btr0, int btr1)
{
    DBGin("CAN_SetBTR");
    DBGprint(DBG_DATA, ("[%d] btr0=%d, btr1=%d", minor, btr0, btr1));
    CANoutw(minor, canclock,  (u16)btr0 );
    CANoutw(minor, cantiming, (u16)btr1 );
    /*
     * Stay in configuration mode; a call to Start-CAN() is necessary to
     * activate the CAN controller with the new bit rate
     */
    DBGprint(DBG_DATA,("cantiming=0x%x BRP canclock=0x%x",
    		CANinw(minor, cantiming), CANinw(minor, canclock)) );
    DBGout();
    return 0;
}


/*
 * Configures bit timing of selected CAN channel.
 * Chip must be in configuration state.
 */
int CAN_SetTiming (int minor, int baud)
{
BTR_TAB_BFCAN_T * table = (BTR_TAB_BFCAN_T*)can_btr_tab_bfcan;
int i;

    DBGin("CAN_SetTiming");
    DBGprint(DBG_DATA, ("baud[%d]=%d", minor, baud));

    /* enable changing of bit timings
     *
     * Modify the CAN_CLOCK or CAN_TIMING registers ionly in
     * configuration mode. Writes to these registers have no effect
     * if not in configuration or debug mode.
     * If not coming out or processor reset or hibernate,
     * enter configuration mode by setting the CCR bit
     * in the master control (CAN_CONTROL) register
     * and poll the global status (CAN_STATUS) register
     * until the CCA bit is set.
     */
    CANsetw(minor, cancontrol, CAN_CCR);
    for( i = 10000 ; i != 0; i--) {
	if ( CANinw(minor, canstatus) & CAN_CCA) break; 
    }
    /* FIXME: use better return value ? */
    if (i == 0) return -ENXIO; /* Configuration mode not reached */

    /* search for data from table */
    while(1) {
        if (table->rate == 0 || table->rate == baud) {
    	    break;
    	}
    	table++;
    }
    if (table->rate == 0) {
	/* try to use baud  as custom specific bit rate
	 * not implemented yet
	 */
	return -ENXIO;
    }

    /*
     * Set Timing Register values.
     * Initialize the bit timing parameters
     * for the CAN_CLOCK and  CAN_TIMING registers.
     *
     * The BFxCAN module uses two 16-bit registers to set-up
     * the bit timing parameters required by the CAN protocol.
     *
     * CAN_CLOCK register sets the clock pre-scaler.
     * Although the BRP field can be set to any value,
     * it is recommended that the value be greater than
     * or equal to 4, as restrictions apply to the bit timing configuration
     * when BRP is less than 4.
     *
     * The CAN_CLOCK register defines the TQ value,
     * and multiple time quanta make up the duration of a CAN bit on the bus.
     * The CAN_TIMING register controls the nominal bit time
     * and the sample point of the individual bits in the CAN protocol.
     */
    CANoutw(minor, cantiming, table->tseg);
    CANoutw(minor, canclock,  table->brp );

    /*
     * Stay in configuration mode; a call to Start-CAN() is necessary to
     * activate the CAN controller with the new bit rate
     */
    DBGprint(DBG_DATA,("cantiming=0x%x BRP canclock=0x%x",
    		CANinw(minor, cantiming), CANinw(minor, canclock)) );

    DBGout();
    return 0;
}


int CAN_StartChip (int minor)
{
int i;

    RxErr[minor] = TxErr[minor] = 0L;
    DBGin("CAN_StartChip");
    /* printk("CAN_StartChip\n"); */




    /* first of all: leave configuration mode */
    CANresetw(minor, cancontrol, CAN_CCR);
    for( i = 10000 ; i != 0; i--) {
	if ( (CANinw(minor, canstatus) & CAN_CCA) == 0) break; 
    }
    /* FIXME: use better return value ? */
    if (i == 0) return -ENXIO; /* Configuration mode not left */

    /* clear _All_  tx and rx interrupts */
    CANoutw(minor, canmbtif1, 0xffff);	/* overwrites with '1' */
    CANoutw(minor, canmbtif2, 0xffff);	/* overwrites with '1' */
    CANoutw(minor, canmbrif1, 0xffff);	/* overwrites with '1' */
    CANoutw(minor, canmbrif2, 0xffff);	/* overwrites with '1' */
    /* clear global interrupt status register */
    CANoutw(minor, cangis, 0x07ff);	/* overwrites with '1' */

    /* Initialize Interrupts 
     * - set bits in the mailbox interrupt mask register 
     * - global interrupt mask
     */

    CANoutw(minor, canmbim1,
	  (1 << RECEIVE_STD_OBJ)
	+ (1 << RECEIVE_EXT_OBJ)
	/* + (1 << RECEIVE_RTR_OBJ) */ );		/* RX mailboxes */

    CANoutw(minor, canmbim2, 1 << (TRANSMIT_OBJ - 16));


    CANoutw(minor, cangim, CAN_EPIM | CAN_BOIM | CAN_RMLIM);



    __builtin_bfin_ssync();
    /* CAN_register_dump(); */
    DBGout();
    return 0;
}


/* Disable all CAN activities */
int CAN_StopChip (int minor)
{
    DBGin("CAN_StopChip");
    /* SW Reset ??? */
    /* enter configuration mode only
     * software reste resets the to much, even the 
     * content of the message configuration register
     * which contains the active mailboxes */
    CANoutw(minor, cancontrol, (/* CAN_SRS | */ CAN_CCR));
    /* Diasable all interrupts */
    CANoutw(minor, canmbim1, 0);
    CANoutw(minor, canmbim2, 0);
    CANoutw(minor, cangim, 0);
    /* and sync registers */
    __builtin_bfin_ssync();
    DBGout();
    return 0;
}

/* set value of the output control register
 * The register is not available, nothing happens here 
 * besides printing some debug information
 */
int CAN_SetOMode (int minor, int arg)
{

    DBGin("CAN_SetOMode");
	DBGprint(DBG_DATA,("[%d] outc=0x%x", minor, arg));
    DBGout();
    return 0;
}


/*
Listen-Only Mode
In listen-only mode, the CAN module is able to receive messages
without giving an acknowledgment.
Since the module does not influence the CAN bus in this mode
the host device is capable of functioning like a monitor
or for automatic bit-rate detection.

*/
int CAN_SetListenOnlyMode (int minor, int arg)
{
    DBGin("CAN_SetListenOnlyMode");
    /* has to be filled for the BlackFin */
    /* ================================= */
    DBGout();
    return 0;
}

/* FlexCAN only knows a 'mask' value, code is ignored */
int CAN_SetMask (int minor, unsigned int code, unsigned int mask)
{

    DBGin("CAN_SetMask");
    DBGprint(DBG_DATA,("[%d] acc=0x%x mask=0x%x",  minor, code, mask));
#if 0
    CANoutw(minor, rxgmskhi, mask >> 16);
    CANoutw(minor, rxgmsklo, mask && 16);

    DBGout();
#endif
    return 0;
}


int CAN_SendMessage (int minor, canmsg_t *tx)
{
int i = 0;

    DBGin("CAN_SendMessage");
    /*

    Wait for the transmitter to be idle
    At the Moment I don't know how to achive that.
    It might not be necessarry anyway.
    */

    tx->length %= 9;			/* limit CAN message length to 8 */

    /* fill the frame info and identifier fields , ID-Low and ID-High */
    if(tx->flags & MSG_EXT) {
    	/* use ID in extended message format */
	DBGprint(DBG_DATA, ("---> send ext message \n"));
	if( tx->flags & MSG_RTR) {
	    CAN_WRITE_XOID_RTR(TRANSMIT_OBJ, tx->id);
	} else {
	    CAN_WRITE_XOID(TRANSMIT_OBJ, tx->id);
	}
    } else {
	DBGprint(DBG_DATA, ("---> send std message \n"));
	if( tx->flags & MSG_RTR) {
	    CAN_WRITE_OID_RTR(TRANSMIT_OBJ, tx->id);
	} else {
	    CAN_WRITE_OID(TRANSMIT_OBJ, tx->id);
	}
    }

    /* - fill data ---------------------------------------------------- */
    /* very beschissen */
    /* for(i = 0; i < tx->length; i++) { */
    /* FIXME:
       Don't take care of message length for now */
    for(i = 0; i < 8; i += 2) {
    	CAN_OBJ[TRANSMIT_OBJ].msg[i] =
    		(tx->data[7 - i]) + (tx->data[6 - i] << 8);
    }
    /* - /end --------------------------------------------------------- */
    /* Writing data length code */
    CAN_WRITE_CTRL(TRANSMIT_OBJ, tx->length);
    /* set transmit request */
    CANoutw(minor, cantrs2, 1 << (TRANSMIT_OBJ - 16));
    __builtin_bfin_ssync();

    if(selfreception[minor]) {
	/* prepare for next TX Interrupt and selfreception */
	memcpy(
	    (void *)&last_Tx_object[minor],
	    (void *)tx,
	    sizeof(canmsg_t));
    }

    DBGout();return i;
}


/* look if one of the receive message objects has something received */
int CAN_GetMessage (int minor, canmsg_t *rx )
{
/* volatile unsigned int stat; */
/* volatile unsigned int ctrl; */
int i = 0;
    DBGin("CAN_GetMessage");
#if 0
    stat = CANinw(minor, estat);
    DBGprint(DBG_DATA,("0x%x: stat=0x%x iflag=0x%x imask=0x%x" ,
    			Base[minor], stat,
    			CANinw(minor, iflag),
    			CANinw(minor, imask)));

    rx->flags  = 0;
    rx->length = 0;

    /* CAN_register_dump(); */
    /* CAN_object_dump(RECEIVE_STD_OBJ); */
    i = CANinw(minor, iflag);
    if( i & (1 << RECEIVE_STD_OBJ)) {
	/* reading the control status word of the identified message
	 * buffer triggers a lock for that buffer.
	 * A new received message frame which maches the message buffer
	 * can not be written into this buffer while it is locked
	 */
        while (((ctrl = CAN_READ_CTRL(RECEIVE_STD_OBJ)) & (REC_CODE_BUSY << 4)) == (REC_CODE_BUSY << 4)) {
	    /* 20 cycles maximum wait */
	    /* printf1("CAN_int, rx REC_CODE_BUSY"); */
	}
	/* printk("message received 0x%x\n", ctrl); */
	rx->length = ctrl & 0x0f;
	rx->id =  CAN_READ_OID(RECEIVE_STD_OBJ);
	memcpy((void *)&rx->data[0],
	       (const void *)&(CAN_OBJ[RECEIVE_STD_OBJ].MSG0), 8);

	/* clear interrupts */
	/* Int is cleared when the CPU reads the intrerupt flag register iflag
	 * while the associated bit is set, and then writes it back as '1'
	 * (and no new event of the same type occurs
	 * between the read and write action.)
	 * ! This is opposit to the TouCAN module, where the iflag bit
	 * has to be written back with '0'
	 */
	CANsetw(minor, iflag, (1 << RECEIVE_STD_OBJ));
	/* Reset message object */
	CAN_WRITE_CTRL(RECEIVE_STD_OBJ, REC_CODE_EMPTY, 8);
	/* reading the free running timer will unlock any message buffers */
	(void) CANinw(minor, timer);
	i = 1; /* signal one received message */
    } else {
	i = 0;
    }
#endif
    DBGout();
    return i;

}

int CAN_VendorInit (int minor)
{
    DBGin("CAN_VendorInit");
/* 1. Vendor specific part ------------------------------------------------ */
    can_range[minor] = 0x600;
/* End: 1. Vendor specific part ------------------------------------------- */

    /* Request the controllers address space */

    /* looks like not needed in uClinux with internal ressources ? */
    /* It's Memory I/O */
    if(NULL == request_mem_region(Base[minor], can_range[minor], "CAN-IO")) {
	return -EBUSY;
    }

    /* not necessary in uClinux, but ... */
    can_base[minor] = ioremap(Base[minor], can_range[minor]);
    /* can_base[minor] += 0x80; */
    /* now the virtual address can be used for the register address macros */

/* 2. Vendor specific part ------------------------------------------------ */



/* End: 2. Vendor specific part ------------------------------------------- */

    if( IRQ[minor] > 0 ) {
        if( Can_RequestIrq( minor, IRQ[minor] , CAN_Interrupt) ) {
	     printk(KERN_ERR "Can[%d]: Can't request IRQ %d \n",
	     			minor, 		IRQ[minor]);
	     DBGout(); return -EBUSY;
        }
    }

    DBGout(); return 1;
}


int Can_RequestIrq(int minor, int irq, irq_handler_t handler)
{
int err=0;

    DBGin("Can_RequestIrq");
    /*

    int request_irq(unsigned int irq,			// interrupt number  
              void (*handler)(int, void *, struct pt_regs *), // pointer to ISR
		              irq, dev_id, registers on stack
              unsigned long irqflags, const char *devname,
              void *dev_id);

       dev_id - The device ID of this handler (see below).       
       This parameter is usually set to NULL,
       but should be non-null if you wish to do  IRQ  sharing.
       This  doesn't  matter when hooking the
       interrupt, but is required so  that,  when  free_irq()  is
       called,  the  correct driver is unhooked.  Since this is a
       void *, it can point to anything (such  as  a  device-spe­
       cific  structure,  or even empty space), but make sure you
       pass the same pointer to free_irq().

    */


    /* we don't need to share the Interrupt with any other driver 
     * request_irq doeas not need the SA_SHIRQ flag */
    err = request_irq(irq, handler, SA_INTERRUPT, \
    					"Can-RX", &Can_minors[minor]);
    err = request_irq(irq + 1, handler, SA_INTERRUPT, \
    					"Can-TX", &Can_minors[minor]);
    err = request_irq(IRQ_CAN_ERROR, handler, SA_INTERRUPT, \
    					"Can-Err", &Can_minors[minor]);
    if( !err ) {
	/* printk("Requested IRQ[%d]: %d @ 0x%x", minor, irq, handler); */

/* Now the kernel has assigned a service to the Interruptvector,
   time to enable the hardware to generate an ISR.

   here should be used a generic function e.g. can_irqsetup(minor)
   and do whatever needed for the app. hardware
   to reduce ifdef clutter
   */

	/* irq2minormap[irq] = minor; */

	/* irq2pidmap[irq] = current->pid; */
	DBGprint(DBG_BRANCH,("Requested IRQ: %d @ 0x%lx",
				irq, (unsigned long)handler));
	IRQ_requested[minor] = 1;
    }
    DBGout();
    return err;
}

int Can_FreeIrq(int minor, int irq )
{
    DBGin("Can_FreeIrq");
    IRQ_requested[minor] = 0;

    free_irq(irq, &Can_minors[minor]);
    free_irq(irq + 1, &Can_minors[minor]);
    free_irq(IRQ_CAN_ERROR, &Can_minors[minor]);

    DBGout();
    return 0;
}





#if CONFIG_TIME_MEASURE
/* switch LED on */
inline void set_led(void)
{
unsigned short portx_fer;
volatile unsigned short *set_or_clear;

    set_or_clear = ((volatile unsigned short *) FIO_FLAG_S);
    portx_fer = *pPORT_FER;
    *pPORT_FER = 0;
    __builtin_bfin_ssync();
    *set_or_clear = (1 << 6);    /* minor = 6 für LED1 */

     *pPORT_FER = portx_fer;
     __builtin_bfin_ssync();
}

/* switch LED off */
inline void reset_led(void)
{
unsigned short portx_fer;
volatile unsigned short *set_or_clear;

    set_or_clear = ((volatile unsigned short *) FIO_FLAG_C);
    portx_fer = *pPORT_FER;
    *pPORT_FER = 0;
    __builtin_bfin_ssync();
    *set_or_clear = (1 << 6);    /* minor = 6 für LED1 */

     *pPORT_FER = portx_fer;
     __builtin_bfin_ssync();
}
#endif

/*
 * The plain CAN interrupt
 *
 *
 *				RX ISR      
 *                              
 *                               _____       
 * CAN msg   Ack EOF       _____|     |____   
 *---------------------------------------------------------------------------
 * |||||||||||________________________
 *
 *
 * Interruot Latency from CAN EOF to Strt ISR app. 6 µs
 * Within the ISR, it takes about 7µs to call do_gettimeofday()
 * Using the set_led() and reset_led() functions takes app. 200ns
 * for each call.
 * The receive ISR lasts for about 15 µs (without do_gettimeofday())
 * Another time consuming thing is wake_up_interruptible() 
 * which takes about 10µs
 *
 * #define IRQ_CAN_RX          22
 * #define IRQ_CAN_TX          23
 * #define IRQ_CAN_ERROR       43
 *
 *
 *
 *
 */

irqreturn_t CAN_Interrupt ( int irq, void *dev_id, struct pt_regs *ptregs )
{
unsigned int		gis, gif;
unsigned int		stat;
/* volatile unsigned int		ctrl; */
unsigned int 		irqsrc;
static int erroractive = 1;
int		dummy;
unsigned long	flags;
int		minor;
msg_fifo_t	*RxFifo;
msg_fifo_t	*TxFifo;
int 		i;

int rxecnt, txecnt;

#if CONFIG_TIME_MEASURE
/* do we have some LEDS on the EVA board */
set_led();
#endif

    /* printk(KERN_INFO "CAN ISR%d \n", irq);  */


    minor = *(int *)dev_id;

    RxFifo = &Rx_Buf[minor];
    TxFifo = &Tx_Buf[minor];

    /* DBGprint(DBG_DATA, (" => got  IRQ[%d]: 0x%0x", minor, irq)); */

    txecnt = CANinw(minor, cancec);
    rxecnt = txecnt &0xFF;
    txecnt = txecnt >> 8;

    gis = CANinw(minor, cangis);
    gif = CANinw(minor, cangif);


    stat = CANinw(minor, canstatus) & 0xff;


    if(irq == IRQ_CAN_ERROR) {
    	/* global CAN Error  */
    	int flags = 0;

	/* Reset all global interrupts  in source and flag register */
	CANoutw(minor, cangis, 0xFFFF);
	/* CANoutw(minor, cangif, 0xFFFF); */

	/* printk("GI:  GIS 0x%04x     GIF 0x%04x\n", gis, gif); */
	/* stat = CANinw(minor, canstatus); */
	if(stat & CAN_EP) {
	    /* printk( "  ERROR PASSIVE\n"); */
	    erroractive = 0;
	    flags |= MSG_PASSIVE;
	} else {
	    /* printk( "  !ERROR PASSIVE\n"); */
	    ;
	}
	if(stat & CAN_EBO) {
	    /* printk( "  BUS_OFF\n"); */
	    erroractive = 0;
	    flags |= MSG_BUSOFF;
	} else {
	    /* printk( "  !BUS_OFF\n"); */
	    ;
	}

	if(flags) {
	/* generate a pseude message with id 0xffffffff */
	    (RxFifo->data[RxFifo->head]).id = 0xFFFFFFFF;
	    (RxFifo->data[RxFifo->head]).flags = flags; 
	    RxFifo->status = BUF_OK;
	    RxFifo->head = ++(RxFifo->head) % MAX_BUFSIZE;
	    if(RxFifo->head == RxFifo->tail) {
		    printk("CAN[%d] RXf: FIFO overrun\n", minor);
		    RxFifo->status = BUF_OVERRUN;
	    }
	    /* tell someone that there is a new error message */
	    wake_up_interruptible(  &CanWait[minor] ); 
	}
    }

	/* stat = CANinw(minor, canstatus); */
    /* printk("  Stat = 0x%04x; %d  RxEcnt = %d; TxEcnt = %d\n", */
		/* stat, erroractive, rxecnt, txecnt);  */



    /* Rx interrupts only in the Low canmbrif1 and transmit interrupts
       only in the High  canmgtif2 */
    while(   
    (irqsrc = CANinw(minor, canmbrif1) + (CANinw(minor, canmbtif2) << 16)) != 0)    {

	canmsg_t *rp = &RxFifo->data[RxFifo->head];
	/* printk("irqsrc %08x\n", irqsrc); */
	/* TODO:
	   loop through all interrupts until done */

	/* get cuurrent time stamp, this needs additional 7 µs of ISR time */
	do_gettimeofday(&(rp->timestamp));

	/* preset flags */
	rp->flags = (RxFifo->status & BUF_OVERRUN ? MSG_BOVR : 0);

	/* stat = CANinw(minor, canstatus); */
	if(erroractive == 0 && !(stat & (CAN_EP | CAN_EBO))) {
	    /* printk("going error active\n"); */
	    erroractive = 1;
	}

	if(stat & CAN_EP) {
	    rp->flags |= MSG_PASSIVE;
	    erroractive = 0;
	}
	/* else  erroractive = 1; */
	if(stat & CAN_EBO) {
	    rp->flags |= MSG_BUSOFF;
	    erroractive = 0;
	}
	/* else  erroractive = 1; */


	/*========== receive interrupt */
	/*=============================*/
	if( irqsrc & (0xffff)) {
	    /* one of the rx message boxes */
	    unsigned int oid = 0xffffffff;
	    int mrobject = 0;	/* number of the message receive object */

#if CONFIG_TIME_MEASURE
reset_led();
#endif
	    /* Reset Interrupt Flag of all rx objects
	     mal zum ersten vorsichtshalber alle */
	    CANsetw(minor, canmbrif1, 0xFFFF);

	    /* DBGprint(DBG_DATA, (" => got  RX IRQ[%d]: 0x%0x\n", minor, irqsrc)); */

	    if (irqsrc & (1 << RECEIVE_STD_OBJ)) {
		mrobject = RECEIVE_STD_OBJ;
		oid = CAN_READ_OID(RECEIVE_STD_OBJ);
	    }
	    if (irqsrc & (1 << RECEIVE_EXT_OBJ)) {
		mrobject = RECEIVE_EXT_OBJ;
		oid = CAN_READ_XOID(RECEIVE_EXT_OBJ);
		rp->flags |= MSG_EXT;
	    }

	    rp->id =  oid;
	    rp->length = CAN_OBJ[mrobject].dlc;
	    if( CAN_OBJ[mrobject].id1 & CAN_ID_RTR_BIT) {
		rp->flags |= MSG_RTR;
	    }

	    /* FIXME:
	       Don't take care of message length for now */
	    for(i = 0; i < 8; i += 2) {
		rp->data[7 - i] = CAN_OBJ[mrobject].msg[i];
		rp->data[6 - i] = CAN_OBJ[mrobject].msg[i] >> 8;
	    }
	    
	    RxFifo->status = BUF_OK;
	    RxFifo->head = ++(RxFifo->head) % MAX_BUFSIZE;

	    if(RxFifo->head == RxFifo->tail) {
		    printk("CAN[%d] RX: FIFO overrun\n", minor);
		    RxFifo->status = BUF_OVERRUN;
	    }
	    /*---------- kick the select() call  -*/
	    /* This function will wake up all processes
	       that are waiting on this event queue,
	       that are in interruptible sleep
	    */
	    wake_up_interruptible(  &CanWait[minor] );

	    /* check for CAN controller overrun */

#if CONFIG_TIME_MEASURE
set_led();
#endif
	}
    /*========== transmit interrupt */
    /*=============================*/
    if( irqsrc & (1 << TRANSMIT_OBJ)) {
	canmsg_t *tp = &TxFifo->data[TxFifo->tail];

	DBGprint(DBG_DATA, (" => got  TX IRQ[%d]: 0x%0x\n", minor, irqsrc));


	if(selfreception[minor]) {
	    /* selfreception means, placing the last transmitted frame
	     * in the rx fifo too
	     */

	    /* use time stamp sampled with last INT */
	    last_Tx_object[minor].timestamp
	    		= RxFifo->data[RxFifo->head].timestamp;
	    memcpy(  
		(void *)&RxFifo->data[RxFifo->head],
	    	(void *)&last_Tx_object[minor],
		sizeof(canmsg_t));
	    
	    /* Mark message as 'self sent/received' */
	    RxFifo->data[RxFifo->head].flags |= MSG_SELF;

	    /* increment write index */
	    RxFifo->status = BUF_OK;
	    RxFifo->head = ++(RxFifo->head) % MAX_BUFSIZE;

	    if(RxFifo->head == RxFifo->tail) {
		printk("CAN[%d] RX: FIFO overrun\n", minor);
		RxFifo->status = BUF_OVERRUN;
	    } 
	    /*---------- kick the select() call  -*/
	    /* This function will wake up all processes
	       that are waiting on this event queue,
	       that are in interruptible sleep
	    */
	    wake_up_interruptible(  &CanWait[minor] ); 

	} /* selfreception */

	/* Reset Interrupt Flag of transmit object */
	CANsetw(minor, canmbtif2, 1 << (TRANSMIT_OBJ - 16));

	/* CAN_register_dump(); */
	if( TxFifo->free[TxFifo->tail] == BUF_EMPTY ) {
	    /* printk("TXE\n"); */
	    TxFifo->status = BUF_EMPTY;
	    TxFifo->active = 0;
	    /* This function will wake up all processes
	       that are waiting on this event queue,
	       that are in interruptible sleep
	    */
	    wake_up_interruptible(  &CanOutWait[minor] ); 
	    goto Tx_done;
	} else {
	    /* printk("TX\n"); */
	}

	/* The TX message FIFO contains other CAN frames to be sent
	 * The next frame in the FIFO is copied into the last_Tx_object
	 * and directly into the hardware of the CAN controller
	 */

	/* enter critical section */
	local_irq_save(flags);

	if(selfreception[minor]) {
	    /* selfreception means, placing the last transmitted frame
	     * in the rx fifo too
	     */
	    /* prepare for next, store mesage that will be transmittet next */
	    memcpy(
	    	(void *)&last_Tx_object[minor],
		(void *)&TxFifo->data[TxFifo->tail],
		sizeof(canmsg_t));
	}

	/* fill the frame info and identifier fields , ID-Low and ID-High */
	if( tp->flags & MSG_EXT ) {
	    /* use ID in extended message format */
	    DBGprint(DBG_DATA, ("---> send ext message \n"));
	    if( tp->flags & MSG_RTR) {
		CAN_WRITE_XOID_RTR(TRANSMIT_OBJ,
		    tp->id);
	    } else {
		CAN_WRITE_XOID(TRANSMIT_OBJ,
		    tp->id);
	    }
	} else {
	    DBGprint(DBG_DATA, ("---> send std message \n"));
	    if( tp->flags & MSG_RTR) {
		CAN_WRITE_OID_RTR(TRANSMIT_OBJ,
		    tp->id);
	    } else {
		CAN_WRITE_OID(TRANSMIT_OBJ,
		    tp->id);
	    }
	}

	/* fill data bytes */

	/* FIXME:
	   Don't take care of message length for now */
	for(i = 0; i < 8; i += 2) {
	    CAN_OBJ[TRANSMIT_OBJ].msg[i] =
		    tp->data[7 - i]
		  + (tp->data[6 - i] << 8);
	}

	/* Writing data length code */
	CAN_WRITE_CTRL(TRANSMIT_OBJ, tp->length);
	/* set transmit request */
	CANsetw(minor, cantrs2, 1 << (TRANSMIT_OBJ - 16));

	/* now this entry is EMPTY */
	TxFifo->free[TxFifo->tail] = BUF_EMPTY;
	TxFifo->tail = ++(TxFifo->tail) % MAX_BUFSIZE;

	local_irq_restore(flags);
    Tx_done:
    ;
	}
    }



    /* irqsrc = CANinw(minor, canmbrif1) + (CANinw(minor, canmbtif2) << 16); */
    /* printk("irqsrc %08x\n", irqsrc); */

    /* printk("  Message Lost       %0x\n", CANinw(0, canrml1)); */
    /* printk("  Message RMP1       %0x\n", CANinw(0, canrmp1)); */

    __builtin_bfin_ssync();

#if CONFIG_TIME_MEASURE
reset_led();
#endif
    return IRQ_RETVAL(IRQ_HANDLED);
}


/* dump all global BF CAN registers to printk */
void CAN_register_dump(void)
{
volatile bf_can_t *bf_can = (bf_can_t *)(BFCAN_BASE);

    printk("BlackFin CAN register layout\n");

#define  printregister(s, name) printk(s, &name , name)

    /* printk(" %p: 0x%x \n", tou_can, *(unsigned char *)tou_can); */
    /* printk(" %p: 0x%x \n", (unsigned char *)tou_can + 1, *(((unsigned char *)tou_can) + 1)); */

    printregister
    (" Mailbox Control 1            %p %0x\n", CAN_MailboxConfig1);
    printregister
    (" Mailbox Control 2            %p %0x\n", CAN_MailboxConfig2);

    printregister
    (" Mailbox Direction 1          %p %0x\n", bf_can->canmd1);
    printregister
    (" Mailbox Direction 2          %p %0x\n", bf_can->canmd2);

    printregister
    (" TX Int Flags 1               %p %0x\n", bf_can->canmbtif1);
    printregister
    (" TX Int Flags 2               %p %0x\n", bf_can->canmbtif2);
    printregister
    (" RX Int Flags 1               %p %0x\n", bf_can->canmbrif1);
    printregister
    (" RX Int Flags 2               %p %0x\n", bf_can->canmbrif2);
    printregister
    (" MB Int Mask 1                %p %0x\n", bf_can->canmbim1);
    printregister
    (" MB Int Mask 2                %p %0x\n", bf_can->canmbim2);

    printregister
    (" STATUS Register              %p %0x\n", CAN_StatusRegister);
    printregister
    (" Master Control               %p %0x\n", CAN_ControlRegister);

    printregister
    (" CLOCK Register               %p %0x\n", CAN_ClockRegister);
    printregister
    (" TIMING Register              %p %0x\n", CAN_TimingRegister);
    printregister
    (" DEBUG Register               %p %0x\n", CAN_DebugRegister);

    printregister
    (" Error Counter Register       %p %0x\n", CAN_ErrorCounter);
    printregister
    (" Global Int Mask Register     %p %0x\n", CAN_GlobalIntMaskRegister);
    printregister
    (" Interrupt Pending Register   %p %0x\n", CAN_IntPendingRegister);
    printregister
    (" Version Code Register        %p %0x\n", CAN_VersionCodeRegister);
    printregister
    (" Error Status Register        %p %0x\n", CAN_ErrorStatusRegister);
}


/* dump the content of the selected message object (MB) to printk
 *
 * only 2byte word or short int access is allowed,
 * each register starts on a 4 byte boundary
 * Mailbox 0 starts at 0xFFC02C00
 * Each Mailbox is built from 8 word registers
 *
 * Additional information is unfortunately located on other memory
 * locations like the acceptance masks
*/

void CAN_object_dump(int object)
{
int minor = 0;   /* be prepared for an board paramter, if later on .. */
unsigned int vh;
unsigned int vl;

volatile unsigned short *cp =
		(unsigned short *)(BFCAN_BASE + 0x200 + (0x20 * object));

volatile bf_can_t *bf_can = (bf_can_t *)(BFCAN_BASE);

volatile mask_t *mask = (mask_t *)(BFCAN_BASE + 0x100);


    printk(KERN_INFO "BF CAN object %d (at %p)\n", object, cp);
    for(vl = 0; vl < 8; vl++) {
	printk("%2x ", *(cp + (vl * 2)));
	if (vl == 3) printk("| ");
    }
    printk("\n");

    vl = CAN_OBJ[object].dlc;
    printk(KERN_INFO " DLC 0x%x\n", (vl & 0x000f));
    vl = CAN_OBJ[object].id0;
    printk(KERN_INFO " ID0 0x%x\n", vl);

    /* CAN_ID1 contains the base ID and some flags */
    vh = CAN_OBJ[object].id1;
    printk(KERN_INFO " ID1 0x%x\n", vh);
    printk(KERN_INFO "   AME = %d\n", (vh & 0x8000) >> 15);
    printk(KERN_INFO "   RTR = %d\n", (vh & 0x4000) >> 14);
    printk(KERN_INFO "   IDE = %d\n", (vh & 0x2000) >> 13);
    printk(KERN_INFO "   base-ID = %d, 0x%x\n",
			    ((vh & 0x1ffc) >> 2),
			    ((vh & 0x1ffc) >> 2));
    vl = CAN_OBJ[object].id0;
    printk(KERN_INFO "    ext-ID = %d, 0x%x\n", 
    	vl + ((vh & 0x1fff) << 16),
    	vl + ((vh & 0x1fff) << 16) );

    vh = CAN_MASK[object].amh;
    printk(KERN_INFO " Mask High 0x%x\n", vh);

    vl = mask[object].aml;
    printk(KERN_INFO " Mask Low  0x%x\n", vl);

    /* TODO: zeile kann weg */
    /* printk(KERN_INFO "   Mask Low  at %p\n", &mask[object].aml); */



    /* information about direction and activity
    as enabled or not etc...*/
    if(object < 16) {
	vl = CAN_MailboxConfig1 & (1 << object);
	vh = CAN_MailboxDirection1 & (1 << object);
    }
    else {
	vl = CAN_MailboxConfig2 & (1 << (object - 16));
	vh = CAN_MailboxDirection2 & (1 << (object - 16));
    }

    printk(KERN_INFO " %s Object %s\n",
    	vh ? "RX" : "TX",
    	vl ? "Enabled" : "Disabled" );

}
