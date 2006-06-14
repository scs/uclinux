#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>

#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(KERN_DEBUG x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif

#define MODULE_NAME "timer_latency proc module"

#define HW_LEN 8

struct timer_latency_data_t {
	char value;
	unsigned long  latency;
};

struct proc_dir_entry *timer_latency_file;
struct timer_latency_data_t timer_latency_data;


static inline u_long get_vco(void)
{
	u_long msel;
	u_long vco;

	msel = (*pPLL_CTL >> 9) & 0x3F;
	if (0 == msel)
		msel = 64;

	vco = CONFIG_CLKIN_HZ;
	vco >>= (1 & *pPLL_CTL);	/* DF bit */
	vco = msel * vco;
	return vco;
}

/*Get the Core clock*/
static u_long get_cclk(void)
{
	u_long csel, ssel;
	if (*pPLL_STAT & 0x1)
		return CONFIG_CLKIN_HZ;

	ssel = *pPLL_DIV;
	csel = ((ssel >> 4) & 0x03);
	ssel &= 0xf;
	if (ssel && ssel < (1 << csel))	/* SCLK > CCLK */
		return get_vco() / ssel;
	return get_vco() >> csel;
}

/* Get the System clock */
static u_long get_sclk(void)
{
	u_long ssel;

	if (*pPLL_STAT & 0x1)
		return CONFIG_CLKIN_HZ;

	ssel = (*pPLL_DIV & 0xf);
	if (0 == ssel) {
		printk(KERN_WARNING "Invalid System Clock\n");
		ssel = 1;
	}

	return get_vco() / ssel;
}

static int read_timer_latency(char *page, char **start,
			      off_t offset, int count, int *eof,
			      void *data)
{
	char *buffer;

	buffer = page;

	sprintf(buffer++, "%ud", timer_latency_data.latency); 

	return 4;
}


static int write_timer_latency(struct file *file, const char *buffer,
			   unsigned long count, void *data)
{
	unsigned long sclk;
	char user_value;

	copy_from_user(&(user_value), buffer, 1);
	
	if ((user_value == '1') && (timer_latency_data.value == 0)) {
		DPRINTK("start timer_latency\n");
		timer_latency_data.value = 1;
		sclk = get_sclk();
		*pWDOG_CNT = 5 * sclk; /* set count time to 5 seconds */		
		/* set CYCLES counter to 0 and start it*/
		__asm__(
		"R2 = 0;\n\t"
                "CYCLES = R2;\n\t"
		"CYCLES2 = R2;\n\t"
		"R2 = SYSCFG;\n\t"
		"BITSET(R2,1);\n\t"

		"P2.H = 0xffc0;\n\t"
		"P2.L = 0x0200;\n\t"
		"R3 = 0x0004;\n\t"
		"W[P2] = R3;\n\t"
		"SYSCFG = R2;\n\t"    /* start cycles counter */
			);

	}
	
	return 1;  /* always write 1 byte*/
}


static irqreturn_t timer_latency_irq(int irq, void *dev_id, struct pt_regs *regs)
{
	struct timer_latency_data_t *data = dev_id;
	
	u_long cycles_past, cclk; 
	u_long latency;
	
	u_long first_latency, second_latency, third_latency;


	/* get current cycle counter */
	/*
	asm("%0 = CYCLES; p2 = 0xFFE07040; %1 = [p2]; p2 = 0xFFE07044; %2 = [p2]; p2 = 0xFFE07048; %3 = [p2];"
	: "=d" (cycles_past), "=d" (first_latency), "=d" (second_latency), "=d" (third_latency):); */
	
	asm("%0 = CYCLES;"
	    : "=d" (cycles_past));

	*pWDOG_CTL = 0x8AD6;  /* close counter */
	*pWDOG_CTL = 0x8AD6;  /* have to write it twice to disable the timer */

	__asm__(                      /* stop CYCLES counter */
		"R2 = SYSCFG;\n\t"
		"BITCLR(R2,1);\n\t"
		"SYSCFG = R2;\n\t"
		);
	       
	cclk = get_cclk();
	
	DPRINTK("first_latency is %ul, second is %ul, third is %ul, latency is %ul\n", first_latency, second_latency, third_latency, cycles_past);

	latency = cycles_past - (cclk * 5);    /* latency in us */
	DPRINTK("latecy is %ud\n",latency);

	if (*pWDOG_STAT != 0) {
		DPRINTK("timer_latency error!\n");
		return IRQ_HANDLED;
	}

	data->latency = latency;
	timer_latency_data.value = 0;
	
	return IRQ_HANDLED;	      
}


static int __init timer_latency_init(void)
{
	
	DPRINTK("timer_latency start!\n");
		
	timer_latency_file = create_proc_entry("timer_latency", 0666, NULL);
	if(timer_latency_file == NULL) {
		return -ENOMEM;
	}

	/* default value is 0 (timer is stopped) */
	timer_latency_data.value = 0; 
	timer_latency_data.latency = 0;

	timer_latency_file->data = &timer_latency_data;
	timer_latency_file->read_proc = &read_timer_latency;
	timer_latency_file->write_proc = &write_timer_latency;
	timer_latency_file->owner = THIS_MODULE;
	
	request_irq(IRQ_WATCH, timer_latency_irq, SA_INTERRUPT, "timer_latency", &timer_latency_data);
	
	printk(KERN_INFO "timer_latency module loaded\n");

	return 0; /* everything's OK */
}


static void __exit timer_latency_exit(void)
{
	remove_proc_entry("timer_latency", NULL);
	free_irq(IRQ_WATCH, NULL);
	printk(KERN_INFO "timer_latency module removed\n");
}

module_init(timer_latency_init);
module_exit(timer_latency_exit);

MODULE_AUTHOR("Luke Yang");
MODULE_LICENSE("GPL");
