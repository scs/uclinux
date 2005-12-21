#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <asm/dpmc.h>
#include <asm/blackfin.h>
#include <asm/bfin_sport.h>

#define SSYNC __builtin_bfin_ssync()

static int bfin_sport_config_rx( struct bfin_sport_register *regs, 
				unsigned int rcr1, unsigned int rcr2, 
				unsigned int clkdiv, unsigned int fsdiv )
{


	regs->rcr1 = rcr1;
	regs->rcr2 = rcr2;
	regs->rclkdiv = clkdiv;
	regs->rfsdiv = fsdiv;

	SSYNC;

	return 0;
}

static int bfin_sport_config_tx( struct bfin_sport_register *regs,
		unsigned int tcr1, unsigned int tcr2,
		unsigned int clkdiv, unsigned int fsdiv)
{

	regs->tcr1 = tcr1;
	regs->tcr2 = tcr2;
	regs->tclkdiv = clkdiv;
	regs->tfsdiv = fsdiv;

	SSYNC;

	return 0;
}

/* note: multichannel is in units of 8 channels, tdm_count is # channels NOT / 8 ! */
static int bfin_sport_set_multichannel( struct bfin_sport_register *regs, 
					int tdm_count, int packed, int frame_delay)
{

	if( tdm_count ){

		int shift = 32 - tdm_count;    
		unsigned int mask = (0xffffffff >> shift);

		regs->mcmc1 = ((tdm_count>>3)-1) << 12;  /* set WSIZE bits */
		regs->mcmc2 = (frame_delay << 12)| MCMEN | \
					( packed ? (MCDTXPE|MCDRXPE) : 0 );

		regs->mtcs0 = mask; 
		regs->mrcs0 = mask; 

	} else {

		regs->mcmc1 = 0;
		regs->mcmc2 = 0;

		regs->mtcs0 = 0; 
		regs->mrcs0 = 0; 
	}

	regs->mtcs1 = 0; regs->mtcs2 = 0; regs->mtcs3 = 0;
	regs->mrcs1 = 0; regs->mrcs2 = 0; regs->mrcs3 = 0;

	SSYNC;

	return 0;
}


static irqreturn_t bfin_sport_handler_err(int irq, void *dev_id, struct pt_regs *regs)
{
	struct bfin_sport *sport=dev_id;
	unsigned int status;

	SSYNC;
	status = sport->regs->stat;
	if( status & (TOVF|TUVF|ROVF|RUVF) ){
		printk( KERN_WARNING  "sport status error:%s%s%s%s\n", 
				status & TOVF ? " TOVF" : "", 
				status & TUVF ? " TUVF" : "", 
				status & ROVF ? " ROVF" : "", 
				status & RUVF ? " RUVF" : "" );
	}

	if(sport->callback)
		sport->callback(sport->priv);
	
	return IRQ_HANDLED;
}

/* Description: This function initialize sport's contorl registers.
 *		Before call it, allocate a memory for structure bfin_sport and
 *		set the necessary fields.
 * sport:	Object of blackfin sport controller.
 */
int bfin_sport_init(struct bfin_sport* sport)
{
	unsigned int tcr1,tcr2,rcr1,rcr2;
	unsigned int clkdiv, fsdiv;

	int err = 0;
	
	tcr1=tcr2=rcr1=rcr2=0;
	clkdiv = fsdiv =0;
	if (sport->sport_num == 0)
		sport->regs = (struct bfin_sport_register*)SPORT0_TCR1;
	else
		sport->regs = (struct bfin_sport_register*)SPORT1_TCR1;

	if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
		return -EBUSY;


	if (sport->mode == TDM_MODE) {
		if(sport->channels & 0x7 || sport->channels>32 )
			return -EINVAL;

		bfin_sport_set_multichannel(sport->regs, sport->channels, 1, sport->frame_delay);
	} else if (sport->mode == I2S_MODE) {
		tcr1 |= (TCKFE | TFSR);
		tcr2 |= TSFSE ;

		rcr1 |= (RCKFE | RFSR);
		rcr2 |= RSFSE;
	} else {
		/* TODO: support normal mode */
	}

	/* Using internal clock*/
	if (sport->int_clk) { 
		u_long sclk=get_sclk();
		
		if ( sport->serial_clk < 0 || sport->serial_clk > sclk/2)
			return -EINVAL;
		clkdiv = sclk/(2*sport->serial_clk) - 1;
		fsdiv = (sport->serial_clk + sport->serial_clk/2) \
					/ sport->fsync_clk - 1;
		
		tcr1 |= (ITCLK | ITFS);
		rcr1 |= (IRCLK | IRFS);
	}
	
	/* Setting data format */
	tcr1 |= (sport->data_format << 2); /* Bit TDTYPE */
	rcr1 |= (sport->data_format << 2); /* Bit TDTYPE */
	if (sport->word_len >= 3 && sport->word_len <= 32) {
		tcr2 |= sport->word_len - 1;
		rcr2 |= sport->word_len - 1;
	} else
		return -EINVAL;
	

	bfin_sport_config_tx(sport->regs, tcr1, tcr2, clkdiv, fsdiv);
	bfin_sport_config_rx(sport->regs, rcr1, rcr2, clkdiv, fsdiv);

	if (sport->err_irq < 0)
		return -EINVAL;
	
	err = request_irq(sport->err_irq, &bfin_sport_handler_err, SA_SHIRQ,
						"Sport Error", sport);
	if (err < 0) {
		printk(KERN_ERR "%s: failed to request irq:%d\n", 
						__FUNCTION__,sport->err_irq);
		return -ENODEV;
	}

	printk(KERN_INFO"tcr1:0x%x, tcr2:0x%x, rcr1:0x%x, rcr2:0x%x\n"
		"mcmc1:0x%x, mcmc2:0x%x\n",
		sport->regs->tcr1, sport->regs->tcr2,
		sport->regs->rcr1, sport->regs->rcr2,
		sport->regs->mcmc1, sport->regs->mcmc2);

	return 0;
}

/* Description: If the predefined mode don't meet your requirement, 
 *		give advanced user an option to set the register directly,
 *		The popular working mode will be add to bfin_sport_init.
 * sport:	Object of blackfin sport controller.
 * reg:		Specific register which will be modified.
 * mask:	Mask for the bits will be modified in the reigster.
 * value:	value will be set for register.
 */
int bfin_sport_set_register(struct bfin_sport* sport, int reg, 
					unsigned mask, unsigned value)
{
	unsigned temp;
	unsigned *regs = (unsigned *)sport->regs;

	if (reg < SPORT_TCR1 || reg > SPORT_MRCS3)
		return -EINVAL;

	temp = *(regs + reg);
	temp = (temp & ~mask) | value;
	*(regs+reg) = temp;

	return 0;
}


int bfin_sport_start(struct bfin_sport *sport)
{
	sport->regs->tcr1 |= TSPEN;
	sport->regs->rcr1 |= RSPEN;

	SSYNC;
	
	return 0;
}

int bfin_sport_stop(struct bfin_sport *sport)
{
	sport->regs->tcr1 |= TSPEN;
	sport->regs->rcr1 |= RSPEN;

	SSYNC;

	return 0;
}

