#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/major.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>


MODULE_AUTHOR("Michele d'Amico <michele.damico@fitre.it>");
MODULE_DESCRIPTION("PFButton input driver");
MODULE_LICENSE("GPL");


/*********************************************************
 * Definizioni di "pflags.h" : non voglio importarlo perche'
 * non mi sembra un driver generico scritto per esse usato
 * da fuori.
 *********************************************************/

#define SET_FIO_DIR                		1  // Peripheral Flag Direction Register
#define SET_FIO_POLAR              		2  // Flag Source Polarity Register
#define SET_FIO_EDGE               		3  // Flag Source Sensitivity Register
#define SET_FIO_BOTH               		4  // Flag Set on BOTH Edges Register
#define SET_FIO_INEN					5  // Flag Input Enable Register 


#define INPUT							0 // SET_FIO_DIR
#define OUTPUT							1

#define ACTIVEHIGH_RISINGEDGE			0 // SET_FIO_POLAR
#define ACTIVELOW_FALLINGEDGE			1

#define LEVEL							0 // SET_FIO_EDGE
#define EDGE							1

#define SINGLEEDGE						0 // SET_FIO_BOTH
#define BOTHEDGES						1

#define INPUT_DISABLE					0 // SET_FIO_INEN
#define INPUT_ENABLE					1

/*********************************************************
 * FINE Definizioni di "pflags.h"
 *********************************************************/


#undef	DEBUG
//#define DEBUG


#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif



#define PF_MASK(_val) (0x1<<_val)

#if defined(CONFIG_BFIN533_TASVOIP)
#define BUTTONS 4
#define PF_BUTTON1 11
#define PF_BUTTON2 12
#define PF_BUTTON3 13
#define PF_BUTTON4 14

#define PF_BUTTONS_MASK (PF_MASK(PF_BUTTON1) | PF_MASK(PF_BUTTON2) | PF_MASK(PF_BUTTON3) | PF_MASK(PF_BUTTON4))

static unsigned short bf53xPFbuttons_btn_pfmask[BUTTONS] = {
	[0] 	= PF_MASK(PF_BUTTON1),
	[1] 	= PF_MASK(PF_BUTTON2),
	[2] 	= PF_MASK(PF_BUTTON3),
	[3] 	= PF_MASK(PF_BUTTON4)
};

static unsigned short bf53xPFbuttons_btncode[BUTTONS] = {
	[0] 	= (unsigned short) BTN_0,
	[1] 	= (unsigned short) BTN_1,
	[2] 	= (unsigned short) BTN_2,
	[3] 	= (unsigned short) BTN_3
};

#define LEDS 1
#define PF_LED1 9

#define PF_LEDS_MASK (PF_MASK(PF_LED1))

static unsigned short bf53xPFbuttons_led_pfmask[LEDS] = {
	[0] 	= PF_MASK(PF_LED1)
};

static unsigned short bf53xPFbuttons_ledcode[LEDS] = {
	[0] 	= (unsigned short) LED_MISC
};

#define BELLS 1
#define PF_BELL1 10

#define PF_BELLS_MASK (PF_MASK(PF_BELL1))

static unsigned short bf53xPFbuttons_snd_pfmask[BELLS] = {
	[0] 	= PF_MASK(PF_BELL1)
};

static unsigned short bf53xPFbuttons_sndcode[BELLS] = {
	[0] 	= (unsigned short) SND_BELL
};


#elif defined(CONFIG_BFIN533_STAMP)
#define BUTTONS 3
#define PF_BUTTON1 5
#define PF_BUTTON2 6
#define PF_BUTTON3 8

#define PF_BUTTONS_MASK (PF_MASK(PF_BUTTON1) | PF_MASK(PF_BUTTON2) | PF_MASK(PF_BUTTON3))

static unsigned short bf53xPFbuttons_btn_pfmask[BUTTONS] = {
	[0] 	= PF_MASK(PF_BUTTON1),
	[1] 	= PF_MASK(PF_BUTTON2),
	[2] 	= PF_MASK(PF_BUTTON3)
};

static unsigned short bf53xPFbuttons_btncode[BUTTONS] = {
	[0] 	= (unsigned short) BTN_0,
	[1] 	= (unsigned short) BTN_1,
	[2] 	= (unsigned short) BTN_2
};

#define LEDS 3
#define PF_LED1 2
#define PF_LED2 3
#define PF_LED3 4

#define PF_LEDS_MASK (PF_MASK(PF_LED1) | PF_MASK(PF_LED2) | PF_MASK(PF_LED3))

static unsigned short bf53xPFbuttons_led_pfmask[LEDS] = {
	[0] 	= PF_MASK(PF_LED1),
	[1] 	= PF_MASK(PF_LED2),
	[2] 	= PF_MASK(PF_LED3)
};

static unsigned short bf53xPFbuttons_ledcode[LEDS] = {
	[0] 	= (unsigned short) LED_MISC,
	[1] 	= (unsigned short) LED_MUTE,
	[2] 	= (unsigned short) LED_SUSPEND
};

#define BELLS 0

#else
#error "ONLY Tasvoip and STAMP are supported"
#endif

struct bf53xPFbuttons {
#if BUTTONS
	unsigned short *btncode;
	unsigned short *btn_pfmask;
#endif
#if LEDS
	unsigned short *ledcode;
	unsigned short *led_pfmask;
#endif
#if BELLS
	unsigned short *sndcode;
	unsigned short *snd_pfmask;
#endif
	struct input_dev dev;
	char name[64];
	char phys[32];
	short laststate;
	short statechanged;
	unsigned long irq_handled;
	unsigned long events_sended;
	unsigned long events_processed;
};

static irqreturn_t bf53xPFbuttons_irq_handler ( int irq, void *dev_id, struct pt_regs *regs );
static int bf53xPFbuttons_proc_output (struct bf53xPFbuttons *bf53xPFbuttons,char *buf);
static int bf53xPFbuttons_read_proc (char *page, char **start, off_t off, int count,
			     int *eof, void *data);

static short read_state (struct bf53xPFbuttons *bf53xPFbuttons);
static void check_and_notify(struct bf53xPFbuttons *bf53xPFbuttons);


static struct bf53xPFbuttons chip = {
#if BUTTONS
	.btncode = bf53xPFbuttons_btncode,
	.btn_pfmask = bf53xPFbuttons_btn_pfmask,
#endif
#if LEDS
	.ledcode = bf53xPFbuttons_ledcode,
	.led_pfmask = bf53xPFbuttons_led_pfmask,
#endif
#if BELLS
	.sndcode = bf53xPFbuttons_sndcode,
	.snd_pfmask = bf53xPFbuttons_snd_pfmask,
#endif
	.laststate = 0,
	.statechanged = 0,
	.irq_handled = 0,
	.events_sended = 0,
	.events_processed = 0,
};

static short read_state (struct bf53xPFbuttons *bf53xPFbuttons){
	short val;
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	unsigned short portx_fer;
	portx_fer = *pPORT_FER;
	*pPORT_FER = 0;
	__builtin_bfin_ssync();
#endif


	/* TODO:1) disabilitare gli interrupt;2) passare in modalita' normale leggere;3) ritornare in vecchia e riablitare. */
	/* Disabilito l'interrupt del PF: Non funziona con il multiplexed GPIO, la maschera e' la B (mi pare)*/
	*pFIO_MASKA_C = PF_BUTTONS_MASK;
	__builtin_bfin_ssync();
	/* Configurazione di lettura TODO : studiare se e' possibile partire dallo stato iniziale e tolgare tra i due stati*/
	*pFIO_POLAR &= ~PF_BUTTONS_MASK;
	*pFIO_EDGE &= ~PF_BUTTONS_MASK;
	__builtin_bfin_ssync();
	/*lettura*/
	val = (*pFIO_FLAG_D & PF_BUTTONS_MASK);
	/*ripristino*/
	*pFIO_EDGE |= PF_BUTTONS_MASK;
	*pFIO_BOTH |= PF_BUTTONS_MASK;
	*pFIO_MASKA_S = PF_BUTTONS_MASK;
  	__builtin_bfin_ssync();
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_FER = portx_fer;
	__builtin_bfin_ssync();
#endif
	return val;
}


static void check_and_notify(struct bf53xPFbuttons *bf53xPFbuttons){
	int i;
	unsigned short nextstate = read_state(bf53xPFbuttons);
	bf53xPFbuttons->statechanged   = bf53xPFbuttons->laststate ^ nextstate;
	bf53xPFbuttons->laststate      = nextstate;
	if (bf53xPFbuttons->statechanged){
#if BUTTONS
		for(i=0;i<BUTTONS;i++){
			if (bf53xPFbuttons->statechanged & bf53xPFbuttons->btn_pfmask[i]){
				input_report_key(&bf53xPFbuttons->dev, bf53xPFbuttons->btncode[i], (nextstate&bf53xPFbuttons->btn_pfmask[i])?0:1);
				bf53xPFbuttons->events_sended++;
			}
		}
		input_sync(&bf53xPFbuttons->dev);
#endif
	}
	
}



static irqreturn_t bf53xPFbuttons_irq_handler ( int irq, void *dev_id, struct pt_regs *regs ){
	struct bf53xPFbuttons *bf53xPFbuttons = (struct bf53xPFbuttons *) dev_id;
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	unsigned short portx_fer;
	portx_fer = *pPORT_FER;
	*pPORT_FER = 0;
	__builtin_bfin_ssync();
#endif
	/*Dovrebbe pulire l'interrupt, se non basta scommentare la riga succesiva TODO: verificare se toliere o meno il clear*/
	short my_irq = *pFIO_FLAG_D & PF_BUTTONS_MASK;
	//*pFIO_FLAG_C = PF_BUTTONS_MASK;
	if (my_irq){
		check_and_notify(bf53xPFbuttons);
	}
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_FER = portx_fer;
	__builtin_bfin_ssync();
#endif
	bf53xPFbuttons->irq_handled++;
	DPRINTK("bf53xPFbuttons_irq_handler \n");
	return IRQ_HANDLED;
}

/*
 * sunkbd_event() handles events from the input module.
 */

static int bf53xPFbuttons_dev_event(struct input_dev *dev, unsigned int type, unsigned int code, int value)
{
	struct bf53xPFbuttons *bf53xPFbuttons = (struct bf53xPFbuttons *) dev->private;
	int i;
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	unsigned short portx_fer;
	portx_fer = *pPORT_FER;
	*pPORT_FER = 0;
	__builtin_bfin_ssync();
#endif
	
	switch (type) {

		case EV_LED:
#if LEDS
			for (i=0;i<LEDS;++i){
				if (bf53xPFbuttons->ledcode[i]==code){
					if (value){
						*pFIO_FLAG_S	= bf53xPFbuttons->led_pfmask[i];
					}else{
						*pFIO_FLAG_C	= bf53xPFbuttons->led_pfmask[i];
					}
					__builtin_bfin_ssync();
					bf53xPFbuttons->events_processed++;
					return 0;
				}
			}
			break;
#endif
		case EV_SND:
#if BELLS
			for (i=0;i<BELLS;++i){
				if (bf53xPFbuttons->sndcode[i]==code){
					if (value){
						*pFIO_FLAG_S	= bf53xPFbuttons->snd_pfmask[i];
					}else{
						*pFIO_FLAG_C	= bf53xPFbuttons->snd_pfmask[i];
					}
					__builtin_bfin_ssync();
					bf53xPFbuttons->events_processed++;
					return 0;
				}
			} 
#endif
			break;
	}
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_FER = portx_fer;
	__builtin_bfin_ssync();
#endif
	return -1;
}



static int __init bf53xPFbuttons_init (void){
	struct bf53xPFbuttons *bf53xPFbuttons = &chip;
	int i;
	short maska_state = *pFIO_MASKA_D; /*Per l'eventuale rollback */
	
	*pFIO_MASKA_D = 0x00; /*NON VOGLIO NESSUNO SULLA MIA LINEA DI INTERRUPT */
	__builtin_bfin_ssync();
	if( request_irq (IRQ_PROG_INTA, bf53xPFbuttons_irq_handler, SA_INTERRUPT, "bf53xPFbuttons", bf53xPFbuttons) ){
	    /* ROLLBACK */
	    *pFIO_MASKA_D = maska_state;
	    __builtin_bfin_ssync();
	    printk (KERN_WARNING "bf53xPFbuttons: IRQ %d is not free.\n", IRQ_PROG_INTA);
	    return -EIO;
	}
	init_input_dev(&bf53xPFbuttons->dev);
	bf53xPFbuttons->dev.evbit[0] = 0;
#if BUTTONS
	{
		bf53xPFbuttons->dev.evbit[0] |= BIT(EV_KEY);
		bf53xPFbuttons->dev.keycode = bf53xPFbuttons->btncode;
		bf53xPFbuttons->dev.keycodesize = sizeof(bf53xPFbuttons->btncode);
		bf53xPFbuttons->dev.keycodemax = ARRAY_SIZE(bf53xPFbuttons->btncode);
		
		for (i = 0; i < BUTTONS; i++){
			set_bit(bf53xPFbuttons->btncode[i], bf53xPFbuttons->dev.keybit);
		}
	}
#endif
#if LEDS
	{
		bf53xPFbuttons->dev.evbit[0] |= BIT(EV_LED);
		for (i = 0; i < LEDS; i++){
			set_bit(bf53xPFbuttons->ledcode[i], bf53xPFbuttons->dev.ledbit);
		}
	}
#endif
#if BELLS
	{
		bf53xPFbuttons->dev.evbit[0] |= BIT(EV_SND);
		for (i = 0; i < BELLS; i++){
			set_bit(bf53xPFbuttons->sndcode[i], bf53xPFbuttons->dev.sndbit);
		}
	}
#endif
	
	if (LEDS || BELLS){
		bf53xPFbuttons->dev.event = bf53xPFbuttons_dev_event;
		bf53xPFbuttons->dev.private = bf53xPFbuttons;
	}
	
	sprintf(bf53xPFbuttons->name,"BF53X PFButtons");
	sprintf(bf53xPFbuttons->phys,"pfbuttons/input0");
	bf53xPFbuttons->dev.name = bf53xPFbuttons->name;
	bf53xPFbuttons->dev.phys = bf53xPFbuttons->phys;
	bf53xPFbuttons->dev.id.bustype = BUS_HOST;
	bf53xPFbuttons->dev.id.vendor = 0x0001;
	bf53xPFbuttons->dev.id.product = 0x0001;
	bf53xPFbuttons->dev.id.version = 0x0100;
	
	input_register_device (&bf53xPFbuttons->dev);
	
	printk(KERN_INFO "input: %s at %s\n", bf53xPFbuttons->name, bf53xPFbuttons->dev.phys);
	
	create_proc_read_entry ("driver/bf53xPFbuttons", 0, 0, bf53xPFbuttons_read_proc, bf53xPFbuttons);
	bf53xPFbuttons->statechanged = 0x0;
#if BUTTONS
	*pFIO_DIR &= ~PF_BUTTONS_MASK;
	*pFIO_INEN |= PF_BUTTONS_MASK; /*Sono gli unici registri che non vengono configurati in read_state()*/
#endif
#if LEDS
	*pFIO_DIR |= PF_LEDS_MASK;
	*pFIO_INEN &= ~PF_LEDS_MASK;
#endif
#if BELLS
	*pFIO_DIR |= PF_BELLS_MASK;
	*pFIO_INEN &= ~PF_BELLS_MASK;
#endif
	bf53xPFbuttons->laststate = read_state(bf53xPFbuttons); /* Imposta OK anche i registri per l'irq */
	DPRINTK ("pfx: pfbits driver for bf53x IRQ %d\n", IRQ_PROG_INTA);

	return 0;
}

void __exit bf53xPFbuttons_exit (void){
	free_irq(IRQ_PROG_INTA, bf53xPFbuttons_irq_handler);
	remove_proc_entry ("driver/bf53xPFbuttons", NULL);
}

module_init (bf53xPFbuttons_init);
module_exit (bf53xPFbuttons_exit);


/*
 *  Info exported via "/proc/driver/bf53xPFbuttons".
 */

static int bf53xPFbuttons_proc_output (struct bf53xPFbuttons *bf53xPFbuttons,char *buf){
	char *p;
	unsigned short i, data,dir,maska,maskb,polar,edge,inen,both;
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	unsigned short portx_fer;
#endif
  
	p = buf;
  
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	portx_fer = *pPORT_FER;
	*pPORT_FER = 0;
	__builtin_bfin_ssync();
#endif
	data = *pFIO_FLAG_D;
	dir = *pFIO_DIR;     
	maska = *pFIO_MASKA_D;
	maskb = *pFIO_MASKB_D;
	polar = *pFIO_POLAR;  
	both = *pFIO_BOTH;
	edge = *pFIO_EDGE;   
	inen = *pFIO_INEN;   
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_FER = portx_fer;
	__builtin_bfin_ssync();
#endif
  
	p += sprintf (p, "PF Configurations\n");
	p += sprintf (p, "FIO_DIR \t: = 0x%X\n", dir);
	p += sprintf (p, "FIO_MASKA\t: = 0x%X\n", maska);
	p += sprintf (p, "FIO_MASKB\t: = 0x%X\n", maskb);
	p += sprintf (p, "FIO_POLAR\t: = 0x%X\n", polar);
	p += sprintf (p, "FIO_EDGE \t: = 0x%X\n", edge);
	p += sprintf (p, "FIO_INEN \t: = 0x%X\n", inen);
	p += sprintf (p, "FIO_BOTH \t: = 0x%X\n", both);
	p += sprintf (p, "FIO_FLAG_D\t: = 0x%X\n", data);
	p += sprintf (p, "PIN\t:DATA DIR INEN EDGE BOTH POLAR MASKA MASKB\n");
	p += sprintf (p, "   \t:H/L  O/I D/E  E/L  B/S   L/H   S/C   S/C\n");
	for (i = 0; i < 16; i++){
		p += sprintf (p, "PF%d\t: %d....%d....%d....%d....%d....%d.....%d.....%d \n", i, ((data >> i) & 1), ((dir >> i) & 1),((inen >> i) & 1),((edge >> i) & 1),((both >> i) & 1),((polar >> i) & 1),((maska >> i) & 1),((maskb >> i) & 1));
	}
	p += sprintf (p, "Interrupt: %ld\nEvents sended: %ld\nEvents processed: %ld\n",bf53xPFbuttons->irq_handled,bf53xPFbuttons->events_sended,bf53xPFbuttons->events_processed);
	
  return p - buf;
}

static int bf53xPFbuttons_read_proc (char *page, char **start, off_t off,
		  int count, int *eof, void *data){
	struct bf53xPFbuttons *bf53xPFbuttons = (struct bf53xPFbuttons *) data;
	int len = bf53xPFbuttons_proc_output (bf53xPFbuttons,page);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}

