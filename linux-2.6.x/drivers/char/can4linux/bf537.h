/*
 * can_bf537.h - can4linux CAN driver module
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2003 port GmbH Halle/Saale
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.2  2006/03/30 15:21:45  hennerich
 * Apply Blackfin can4linux patch form port GmbH
 *
 * Revision 1.1  2005/11/08 11:32:16  oe
 * Initial revision
 *
 *
 *
 *--------------------------------------------------------------------------
 */
 /*




 */

#ifndef __BLACKFIN_CAN_H
#define __BLACKFIN_CAN_H

extern unsigned int Base[];


/* #define CAN_SYSCLK 32 */

/* define some types, header file comes from CANopen */
#define UNSIGNED8 u8
#define UNSIGNED16 u16


#define BFCAN_BASE (0xFFC02A00)	/* Base address BF CAN module */


/* can4linux does not use all the full CAN features, partly because it doesn't
   make sense.
 */

/* We use only one transmit object for all messages to be transmitted */
#define TRANSMIT_OBJ		24
#define RECEIVE_STD_OBJ 	0
#define RECEIVE_EXT_OBJ 	4
#define RECEIVE_RTR_OBJ 	8
#define RECEIVE_EXT_RTR_OBJ 	12


/* Makros to manipulate BF CAN control registers */
#define CAN_READ(reg)			(reg)
#define CAN_WRITE(reg, source)		((reg) = (source))
#define CAN_SET_BIT(reg, mask)		((reg) |= (mask))
#define CAN_RESET_BIT(reg, mask)	((reg) &= ~(mask))
#define CAN_TEST_BIT(breg, mask)	((breg) & (mask))

/*=== Register Layout of the BF CAN module ==============================*/
/* access is two byte, each register is on a 4 byte boundary             */
typedef struct {
    
    /* ---- mailbox control 1 ------------------ */

    volatile u16   canmc1;     /* Mailbox Configuration 1 */
    volatile u16   dummy01;

    volatile u16   canmd1;     /* Mailbox Direction 1 */
    volatile u16   dummy02;

    volatile u16   cantrs1;     /* Transmit Request Set 1 */
    /* The message is sent after mailbox n is enabled and,
       subsequently, the corresponding transmit request bit is set in cantrsX.
     */
    volatile u16   dummy03;

    volatile u16   cantrr1;     /*  */
    volatile u16   dummy04;

    volatile u16   canta1;     /* Transmit Acknowledge 1 */
    /* If transmission was successful, the corresponding bit
       in the transmit acknowledge register cantaX is set. */
    volatile u16   dummy05;

    volatile u16   canaa1;     /* Transmit Abort Acknowledge 1 */
    volatile u16   dummy06;

    volatile u16   canrmp1;     /*  */
    volatile u16   dummy07;

    volatile u16   canrml1;     /*  */
    volatile u16   dummy08;

    volatile u16   canmbtif1;     /* Mailbox Transmit Int Flag 1 */
    /* the corresponding transmit interrupt flag is set in cantifX
       after the message in mailbox n is sent correctly (TAn = 1 in CAN_TAx).
       In order to clear the MBTIRQ interrupt request,
       all of the set MBTIFn bits must be cleared by software
       by writing a 1 to those set bit locations in canmbtifX.
     */
    volatile u16   dummy09;

    volatile u16   canmbrif1;     /*  */
    volatile u16   dummy010;

    volatile u16   canmbim1;     /* Mailbox Interrupt Mask 1 */
    /* Each of the 32 mailboxes in the CAN module may generate
       a receive or transmit interrupt,
       depending on the mailbox configuration.
       To enable a mailbox to generate an interrupt,
       set the corresponding MBIMn bit in canmbimX
     */
    volatile u16   dummy011;

    volatile u16   canrfh1;     /*  */
    volatile u16   dummy012;

    volatile u16   canopss1;     /*  */
    volatile u16   dummy013[7];

    /* --- mailbox control 2 ------------------- */

    volatile u16   canmc2;     /*  */
    volatile u16   dummy014;

    volatile u16   canmd2;     /*  */
    volatile u16   dummy015;

    volatile u16   cantrs2;     /*  */
    volatile u16   dummy016;

    volatile u16   cantrr2;     /*  */
    volatile u16   dummy017;

    volatile u16   canta2;     /*  */
    volatile u16   dummy018;

    volatile u16   canaa2;     /*  */
    volatile u16   dummy019;

    volatile u16   canrmp2;     /*  */
    volatile u16   dummy020;

    volatile u16   canrml2;     /*  */
    volatile u16   dummy021;

    volatile u16   canmbtif2;     /*  */
    volatile u16   dummy022;

    volatile u16   canmbrif2;     /*  */
    volatile u16   dummy023;

    volatile u16   canmbim2;     /*  */
    volatile u16   dummy024;

    volatile u16   canrfh2;     /*  */
    volatile u16   dummy025;

    volatile u16   canopss2;     /*  */
    volatile u16   dummy026[7];

    /* ---- global registers ------------------- */

    volatile u16   canclock;     /* CAN clock register */
    volatile u16   dummy1;

    volatile u16   cantiming;    /* CAN timing register */
    volatile u16   dummy2;

    volatile u16   candebug;	    /* CAN debug register */
    volatile u16   dummy3;

    volatile u16   canstatus;    /* CAN global status register */
    volatile u16   dummy4;

    volatile u16   cancec;	    /* CAN error counter register */
    volatile u16   dummy5;

    volatile u16   cangis;	    /* CAN global Int status register */
    volatile u16   dummy6;

    volatile u16   cangim;	    /* CAN global Int mask register */
    volatile u16   dummy7;

    volatile u16   cangif;	    /* CAN global Int flag register */
    volatile u16   dummy8;

    volatile u16   cancontrol;   /* CAN control register */
    volatile u16   dummy9;

    volatile u16   canintr;	    /* CAN Int pending register */
    volatile u16   dummy10;

    volatile u16   cansfcmver;   /* Version code register */
    volatile u16   dummy11;

    volatile u16   canmbtd;	    /* Mailbox Temp. Disable */
    volatile u16   dummy12;

    volatile u16   canewr;	    /* Error Warning Level */
    volatile u16   dummy13;

    volatile u16   canesr;	    /* Error status register */
    volatile u16   dummy14;

    volatile u16   canucreg;	    /* Universal counter register */
    volatile u16   dummy15;

    volatile u16   canuccnt;	    /* Universal counter register */
    volatile u16   dummy16;

    volatile u16   canucrc;	    /* Universal counter reload */
    volatile u16   dummy17;

    volatile u16   canuccnf;	    /* Universal counter config */
    volatile u16   dummy18;
} bf_can_t;


/* We have different CAN structures for different CAN Controllers
 * like BF_CAN, TouCan, and FlexCan
 * to be used with -
 * - CANopen library without OS we use global pointers bf_can, tou_can, ...
 * - in can4linux we use the generic name canregs_t
 *   (this name is used also in the sja1000 driver)
 *
 * All basic register macros /can_def.h) are based on that name
 */

typedef bf_can_t canregs_t;


/* Register access macros */
#define CAN_MailboxConfig1		(bf_can->canmc1)
#define CAN_MailboxConfig2		(bf_can->canmc2)
#define CAN_MailboxDirection1		(bf_can->canmd1)
#define CAN_MailboxDirection2		(bf_can->canmd2)

#define CAN_ClockRegister		(bf_can->canclock)
#define CAN_TimingRegister		(bf_can->cantiming)
#define CAN_DebugRegister		(bf_can->candebug)
#define CAN_StatusRegister		(bf_can->canstatus)
#define CAN_ErrorCounter		(bf_can->cancec)
#define CAN_GlobalIntStatusRegister	(bf_can->cancis)
#define CAN_GlobalIntMaskRegister	(bf_can->cangim)
#define CAN_GlobalIntFlagRegister	(bf_can->cangif)
#define CAN_ControlRegister		(bf_can->cancontrol)
#define CAN_IntPendingRegister		(bf_can->canintr)
#define CAN_VersionCodeRegister		(bf_can->cansfcmver)
#define CAN_MailboxDisable		(bf_can->canmbtd)
#define CAN_ErrorWarningLevel		(bf_can->canewr)
#define CAN_ErrorStatusRegister		(bf_can->canesr)
#define CAN_CounterRegister		(bf_can->canuccnt)
#define CAN_CounterReloadRegister	(bf_can->canucrc)
#define CAN_CounterConfigRegister	(bf_can->canuccnf)



/* CAN register mask definitions (line 1830 deefBF534.h) */

/* CAN_CLOCK Masks	*/
#define	BRP		0x03FF	/* Bit-Rate Pre-Scaler			*/

/* CAN_CONTROL Masks	*/
#define	CAN_SRS		0x0001	/* Software Reset			*/
#define	CAN_DNM		0x0002	/* Device Net Mode			*/
#define	CAN_ABO		0x0004	/* Auto-Bus On Enable			*/
#define	CAN_TXPRIO	0x0008	/* TX Priority (Priority/Mailbox*)	*/
#define	CAN_WBA		0x0010	/* Wake-Up On CAN Bus Activity Enable	*/
#define	CAN_SMR		0x0020	/* Sleep Mode Request			*/
#define	CAN_CSR		0x0040	/* CAN Suspend Mode Request		*/
#define	CAN_CCR		0x0080	/* CAN Configuration Mode Request	*/

/* CAN_STATUS Masks	*/
#define	CAN_WT		0x0001	/* TX Warning Flag			*/
#define	CAN_WR		0x0002	/* RX Warning Flag			*/
#define	CAN_EP		0x0004	/* Error Passive Mode			*/
#define	CAN_EBO		0x0008	/* Error Bus Off Mode			*/
#define	CAN_SMA		0x0020	/* Sleep Mode Acknowledge		*/
#define	CAN_CSA		0x0040	/* Suspend Mode Acknowledge		*/
#define	CAN_CCA		0x0080	/* Configuration Mode Acknowledge	*/
#define	CAN_MBPTR	0x1F00	/* Mailbox Pointer			*/
#define	CAN_TRM		0x4000	/* Transmit Mode			*/
#define	CAN_REC		0x8000	/* Receive Mode				*/

/* CAN_TIMING Masks	*/
#define	CAN_TSEG1	0x000F	/* Time Segment 1			*/
#define	CAN_TSEG2	0x0070	/* Time Segment 2			*/
#define	CAN_SAM		0x0080	/* Sampling				*/
#define	CAN_SJW		0x0300	/* Synchronization Jump Width		*/


/* CAN_DEBUG Masks	*/
#define	CAN_DEC		0x0001	/* Disable CAN Error Counters		*/
#define	CAN_DRI		0x0002	/* Disable CAN RX Input			*/
#define	CAN_DTO		0x0004	/* Disable CAN TX Output		*/
#define	CAN_DIL		0x0008	/* Disable CAN Internal Loop		*/
#define	CAN_MAA		0x0010	/* Mode Auto-Acknowledge Enable		*/
#define	CAN_MRB		0x0020	/* Mode Read Back Enable		*/
#define	CAN_CDE		0x8000	/* CAN Debug Enable			*/


/* CAN_CEC Masks	*/
#define	CAN_RXECNT	0x00FF	/* Receive Error Counter		*/
#define	CAN_TXECNT	0xFF00	/* Transmit Error Counter		*/

/* CAN_INTR Masks	*/
#define	CAN_MBRIF	0x0001	/* Mailbox Receive Interrupt		*/
#define	CAN_MBTIF	0x0002	/* Mailbox Transmit Interrupt		*/
#define	CAN_GIRQ	0x0004	/* Global Interrupt			*/
#define	CAN_SMACK	0x0008	/* Sleep Mode Acknowledge		*/
#define	CAN_CANTX	0x0040	/* CAN TX Bus Value			*/
#define	CAN_CANRX	0x0080	/* CAN RX Bus Value			*/

/* CAN_GIM Masks	*/
#define	CAN_EWTIM	0x0001	/* Enable TX Error Count Interrupt	*/
#define	CAN_EWRIM	0x0002	/* Enable RX Error Count Interrupt	*/
#define	CAN_EPIM	0x0004	/* Enable Error-Passive Mode Interrupt	*/
#define	CAN_BOIM	0x0008	/* Enable Bus Off Interrupt		*/
#define	CAN_WUIM	0x0010	/* Enable Wake-Up Interrupt		*/
#define	CAN_UIAIM	0x0020	/* Enable Access To Unimplemented Address Interrupt	*/
#define	CAN_AAIM	0x0040	/* Enable Abort Acknowledge Interrupt	*/
#define	CAN_RMLIM	0x0080	/* Enable RX Message Lost Interrupt	*/
#define	CAN_UCEIM	0x0100	/* Enable Universal Counter Overflow Interrupt*/
#define	CAN_EXTIM	0x0200	/* Enable External Trigger Output Interrupt*/
#define	CAN_ADIM	0x0400	/* Enable Access Denied Interrupt	*/

/* CAN_GIS Masks	*/
#define	CAN_EWTIS	0x0001	/* TX Error Count IRQ Status		*/
#define	CAN_EWRIS	0x0002	/* RX Error Count IRQ Status		*/
#define	CAN_EPIS	0x0004	/* Error-Passive Mode IRQ Status	*/
#define	CAN_BOIS	0x0008	/* Bus Off IRQ Status			*/
#define	CAN_WUIS	0x0010	/* Wake-Up IRQ Status			*/
#define	CAN_UIAIS	0x0020	/* Access To Unimplemented Address IRQ Status*/
#define	CAN_AAIS	0x0040	/* Abort Acknowledge IRQ Status		*/
#define	CAN_RMLIS	0x0080	/* RX Message Lost IRQ Status		*/
#define	CAN_UCEIS	0x0100	/* Universal Counter Overflow IRQ Status*/
#define	CAN_EXTIS	0x0200	/* External Trigger Output IRQ Status	*/
#define	CAN_ADIS	0x0400	/* Access Denied IRQ Status		*/

/* CAN_GIF Masks	*/
#define	CAN_EWTIF	0x0001	/* TX Error Count IRQ Flag		*/
#define	CAN_EWRIF	0x0002	/* RX Error Count IRQ Flag		*/
#define	CAN_EPIF	0x0004	/* Error-Passive Mode IRQ Flag		*/
#define	CAN_BOIF	0x0008	/* Bus Off IRQ Flag			*/
#define	CAN_WUIF	0x0010	/* Wake-Up IRQ Flag			*/
#define	CAN_UIAIF	0x0020	/* Access To Unimplemented Address IRQ Flag*/
#define	CAN_AAIF	0x0040	/* Abort Acknowledge IRQ Flag		*/
#define	CAN_RMLIF	0x0080	/* RX Message Lost IRQ Flag		*/
#define	CAN_UCEIF	0x0100	/* Universal Counter Overflow IRQ Flag	*/
#define	CAN_EXTIF	0x0200	/* External Trigger Output IRQ Flag	*/
#define	CAN_ADIF	0x0400	/* Access Denied IRQ Flag		*/


/* Mailbox acceptance mask registers */
typedef struct {
    u16 aml;		/* mailbox acceptance mask low		*/
    u16 dummy1;
    u16 amh;		/* mailbox acceptance mask high		*/
    u16 dummy2;
} mask_t;

#define CAN_MASK \
   ((mask_t volatile *) ((void *)(can_base[minor] + 0x100)) )


/*
 * Macros to handle BlackFin CAN message objects
 *
 * Structure for a single CAN object
 * A total of 32 such object structures exists (starting at CAN_BASE + 0x200)
 * ( 0xFFC02C00 )
 */

struct can_obj {
    u16 msg[8];     	/* Message Data 0 .. 7   		*/
    u16 dlc;		/* data length code			*/
    u16 dummy1;
    u16 tsv;		/* time stamp value			*/
    u16 dummy2;
    u16 id0;		/* MB ID0 register			*/
    u16 dummy3;
    u16 id1;		/* MB ID1 register			*/
    u16 dummy4;
};


/* CAN_MBxx_ID1 and CAN_MBxx_ID0 Masks */
#define CAN_ID_RTR_BIT	0x4000
#define CAN_ID_EXT_BIT	0x2000
#define	CAN_AME		0x8000	/* Acceptance Mask Enable		*/


/* The firs data byte of a message */
#define MSG0 msg[0]
/* CAN object definition */
#define CAN_OBJ \
   ((struct can_obj volatile *) ((void *)(can_base[minor] + 0x200)) )

/* ---------------------------------------------------------------------------
 * CAN_READ_OID(obj) is a macro to read the CAN-ID of the specified object.
 * It delivers the value as 16 bit from the standard ID registers.
 */
#define CAN_READ_OID(bChannel) ((CAN_OBJ[bChannel].id1 & 0x1ffc) >> 2)

#define CAN_READ_XOID(bChannel) \
	(  ((CAN_OBJ[bChannel].id1 & 0x1fff) << 16) \
	 + ((CAN_OBJ[bChannel].id0 )))


/* ---------------------------------------------------------------------------
 * CAN_WRITE_OID(obj, id) is a macro to write the CAN-ID
 * of the specified object with identifier id.
 * CAN_WRITE_XOID(obj, id) is a macro to write the extended CAN-ID
 */
#define CAN_WRITE_OID(bChannel, Id) \
	    (CAN_OBJ[bChannel].id1 = ((Id) << 2) | CAN_AME)


#define CAN_WRITE_XOID(bChannel, Id)  \
	do { \
	    CAN_OBJ[bChannel].id0 = (Id); \
	    CAN_OBJ[bChannel].id1 = (((Id) & 0x1FFF0000) >> 16) \
			+ CAN_ID_EXT_BIT + CAN_AME; \
	} while(0)

/* ---------------------------------------------------------------------------
 * CAN_WRITE_OID_RTR(obj, id) is a macro to write the CAN-ID
 * of the specified object with identifier id and set the RTR Bit.
 */
#define CAN_WRITE_OID_RTR(bChannel, Id) \
	    (CAN_OBJ[bChannel].id1 = ((Id) << 2) | CAN_ID_RTR_BIT | CAN_AME )

#define CAN_WRITE_XOID_RTR(bChannel, Id)  \
	do { \
	    CAN_OBJ[bChannel].id0 = (Id); \
	    CAN_OBJ[bChannel].id1 = (((Id) & 0x1FFF0000) >> 16) \
	    		+ CAN_ID_EXT_BIT + CAN_ID_RTR_BIT; \
	} while(0)


/* ---------------------------------------------------------------------------
 * CAN_WRITE_CTRL(obj, code, length) is a macro to write to the 
 * specified objects control register
 *
 * Writes 2 byte, TIME STAMP is overwritten with 0.
 */
#define CAN_WRITE_CTRL(bChannel, length) \
	(CAN_OBJ[bChannel].dlc = (length))






/*
 * CAN Bit Timing definitions
 */
typedef struct {
	UNSIGNED16 rate;
	UNSIGNED16 brp;		/* bit rate prescaler CAN_CLOCK register */
	UNSIGNED16 tseg;	/* time segments, CAN_TIMING register */
} BTR_TAB_BFCAN_T;

#ifndef CAN_SYSCLK
#  error Please specify an CAN_SYSCLK value
#endif

#if CAN_SYSCLK == 125
    #define CAN_BRP_100K		49
    #define CAN_TSEG_100K		0x007f
    #define CAN_BRP_125K		49
    #define CAN_TSEG_125K		0x002f
    #define CAN_BRP_250K		24
    #define CAN_TSEG_250K		0x002f
    #define CAN_BRP_500K		24
    #define CAN_TSEG_500K		0x0007
    #define CAN_BRP_1000K		4
    #define CAN_TSEG_1000K		0x007f

    #define CAN_SYSCLK_is_ok		1
#endif

#ifndef CAN_SYSCLK_is_ok
#  error Please specify a valid CAN_SYSCLK value (i.e. 125) or define new parameters
#endif

#endif 		/* __BLACKFIN_CAN_H */
