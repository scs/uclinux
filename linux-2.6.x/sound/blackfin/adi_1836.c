/* The device driver file */
#include "adi_1836.h"
#ifdef LINUX
static irqreturn_t Sport0_RX_ISR(int irq, void *dev_id, struct pt_regs * regs);
#else
EX_INTERRUPT_HANDLER(Sport0_RX_ISR);
#endif
static int add_physical_channel(struct adi_sport_1836_instance *instance);
static void adi_spt_free_dac_pcm_channel(struct adi_sport_1836_card *card, int channel);
static void adi_spt_free_adc_pcm_channel(struct adi_sport_1836_card *card, int channel);

/***** Initialization *****/
#ifndef LINUX
//--------------------------------------------------------------------------//
// Function:	Init_EBIU													//
//																			//
// Description:	This function initializes and enables asynchronous memory 	//
//				banks in External Bus Interface Unit so that Flash A can be //
//				accessed.													//
//--------------------------------------------------------------------------//
void Init_EBIU(void)
{
	*pEBIU_AMBCTL0	= 0x7bb07bb0;
	*pEBIU_AMBCTL1	= 0x7bb07bb0;
	*pEBIU_AMGCTL	= 0x000f;
}

#else
#define ssync() __asm__("ssync;");
#endif

//--------------------------------------------------------------------------//
// Function:	Init_Flash													//
//																			//
// Description:	This function initializes pin direction of Port A in Flash A//
//				to output.  The AD1836_RESET on the ADSP-BF533 EZ-KIT board //
//				is connected to Port A.										//
//--------------------------------------------------------------------------//
void Init_Flash(void)
{
	*pFlashA_PortA_Dir = 0x1; ssync();
}


//--------------------------------------------------------------------------//
// Function:	Init1836()													//
//																			//
// Description:	This function sets up the SPI port to configure the AD1836. //
//				The content of the array sCodec1836TxRegs is sent to the 	//
//				codec.														//
//--------------------------------------------------------------------------//
void Config1836(void)
{
	int j;
	// Enable PF4
	*pSPI_FLG = FLS4;
	// Set baud rate SCK = HCLK/(2*SPIBAUD) SCK = 2MHz	
	*pSPI_BAUD = 16;
	// configure spi port
	// SPI DMA write, 16-bit data, MSB first, SPI Master
	*pSPI_CTL = TIMOD_DMA_TX | SIZE | MSTR;
	
	// Set up DMA5 to transmit
	// Map DMA5 to SPI
	*pDMA5_PERIPHERAL_MAP	= 0x5000;
	
	// Configure DMA5
	// 16-bit transfers
	*pDMA5_CONFIG = WDSIZE_16;
	// Start address of data buffer
	*pDMA5_START_ADDR = sCodec1836TxRegs;
	// DMA inner loop count
	*pDMA5_X_COUNT = CODEC_1836_REGS_LENGTH;
	// Inner loop address increment
	*pDMA5_X_MODIFY = 2;
	
	// enable DMAs
	*pDMA5_CONFIG = (*pDMA5_CONFIG | DMAEN);
	// enable spi
	*pSPI_CTL = (*pSPI_CTL | SPE);
	
	// wait until dma transfers for spi are finished 
	for (j=0; j<0xaff; j++);
	
	// disable spi
	*pSPI_CTL = 0x0000;
}

void Init1836(void)
{
	int i;
	static unsigned char ucActive_LED = 0x01;
	
	// write to Port A to reset AD1836
	*pFlashA_PortA_Data = 0x00;
	
	// write to Port A to enable AD1836
	*pFlashA_PortA_Data = ucActive_LED;
	
	// wait to recover from reset
	for (i=0; i<0xf000; i++);

	Config1836();
}


//--------------------------------------------------------------------------//
// Function:	Init_Sport0													//
//																			//
// Description:	Configure Sport0 for TDM mode, to transmit/receive data 	//
//				to/from the AD1836. Configure Sport for external clocks and //
//				frame syncs.												//
//--------------------------------------------------------------------------//
void Init_Sport0(void)
{
	// Sport0 receive configuration
	// External CLK, External Frame sync, MSB first
	// 32-bit data
	*pSPORT0_RCR1 = RFSR;
	*pSPORT0_RCR2 = SLEN_32;
	
	// Sport0 transmit configuration
	// External CLK, External Frame sync, MSB first
	// 24-bit data
	*pSPORT0_TCR1 = TFSR;
	*pSPORT0_TCR2 = SLEN_32;
	
	// Enable MCM 8 transmit & receive channels
	*pSPORT0_MTCS0 = 0x000000FF;
	*pSPORT0_MRCS0 = 0x000000FF;
	
	// Set MCM configuration register and enable MCM mode
	*pSPORT0_MCMC1 = 0x0000;
	*pSPORT0_MCMC2 = 0x101c;
}


//--------------------------------------------------------------------------//
// Function:	Init_DMA													//
//																			//
// Description:	Initialize DMA1 in autobuffer mode to receive and DMA2 in	//
//				autobuffer mode to transmit									//
//--------------------------------------------------------------------------//
void Init_DMA(void)
{
	// Set up DMA1 to receive
	// Map DMA1 to Sport0 RX
	*pDMA1_PERIPHERAL_MAP = 0x1000;
	
	// Configure DMA1
	// 32-bit transfers, Interrupt on completion, Autobuffer mode
	//*pDMA1_CONFIG = WNR | WDSIZE_32 | DI_EN | FLOW_1;
	*pDMA1_CONFIG = WNR | WDSIZE_32 | DI_EN | FLOW_1 | DI_SEL | DMA2D; // dont enable dma as yet
	// Start address of data buffer
	*pDMA1_START_ADDR = iRxBuffer1;
	// DMA inner loop count
	*pDMA1_X_COUNT = BUF_SIZE*8/2;
	// Inner loop address increment
	*pDMA1_X_MODIFY	= 4;
	*pDMA1_Y_MODIFY = 4;
	*pDMA1_Y_COUNT = 2;
	
	
	// Set up DMA2 to transmit
	// Map DMA2 to Sport0 TX
	*pDMA2_PERIPHERAL_MAP = 0x2000;
	
	// Configure DMA2
	// 32-bit transfers, Autobuffer mode
	//*pDMA2_CONFIG = WDSIZE_32 | FLOW_1;
	*pDMA2_CONFIG = WDSIZE_32 | FLOW_1 | DMA2D;
	// Start address of data buffer
	*pDMA2_START_ADDR = iTxBuffer1;
	// DMA inner loop count
	*pDMA2_X_COUNT = BUF_SIZE*8/2;
	// Inner loop address increment
	*pDMA2_X_MODIFY	= 4;
	*pDMA2_Y_MODIFY = 4;
	*pDMA2_Y_COUNT = 2;
}


//--------------------------------------------------------------------------//
// Function:	Init_Interrupts												//
//																			//
// Description:	Initialize Interrupt for Sport0 RX							//
//--------------------------------------------------------------------------//
int Init_Sport_Interrupts(void)
{
	// Set Sport0 RX (DMA1) interrupt priority to 2 = IVG9 
	//*pSIC_IAR0 = 0xffffffff;
	//*pSIC_IAR1 = 0xffffff2f;
	//*pSIC_IAR2 = 0xffffffff;

	// assign ISRs to interrupt vectors
	// Sport0 RX ISR -> IVG 9
	//register_handler(ik_ivg9, Sport0_RX_ISR);		
  	if(request_irq(IRQ_SPORT0_RX, Sport0_RX_ISR, 
		0, "Sport AD1836", NULL) != 0)
    		return -EBUSY;
  	enable_irq(IRQ_SPORT0_RX);

	// enable Sport0 RX interrupt
	*pSIC_IMASK |= 0x00000200;
	ssync();

	return 0;
}


//--------------------------------------------------------------------------//
// Function:	Enable_DMA_Sport											//
//																			//
// Description:	Enable DMA1, DMA2, Sport0 TX and Sport0 RX					//
//--------------------------------------------------------------------------//
void Enable_DMA_Sport0(void)
{
	// enable DMAs
	*pDMA2_CONFIG	= (*pDMA2_CONFIG | DMAEN);
	*pDMA1_CONFIG	= (*pDMA1_CONFIG | DMAEN);
	
	// enable Sport0 TX and RX
	*pSPORT0_TCR1 	= (*pSPORT0_TCR1 | TSPEN);
	*pSPORT0_RCR1 	= (*pSPORT0_RCR1 | RSPEN);
}

/***** ISR ****/
//--------------------------------------------------------------------------//
// Function:	Sport0_RX_ISR												//
//																			//
// Description: This ISR is executed after a complete frame of input data 	//
//				has been received. The new samples are stored in 			//
//				iChannel0LeftIn, iChannel0RightIn, iChannel1LeftIn and 		//
//				iChannel1RightIn respectively.  Then the function 			//
//				Process_Data() is called in which user code can be executed.//
//				After that the processed values are copied from the 		//
//				variables iChannel0LeftOut, iChannel0RightOut, 				//
//				iChannel1LeftOut and iChannel1RightOut into the dma 		//
//				transmit buffer.											//
//--------------------------------------------------------------------------//
//#define DEBUG_
inline void sport_isr_rx(void)
{
  /* loop through the adc queue and wake them if the
     wakeup count is large enough
  */
	int count;
	extern struct adi_sport_1836_card *devs;
	
	for(count = 0; count < MAX_ADC_CHANNELS; count++){
	  if(devs->adc_channel[count].used){
#ifdef DEBUG_
printk("rx waking up %d : %d\n", devs->adc_channel[count].used, devs->adc_channel[count].wait.lock);
#endif
	    wake_up_interruptible(&devs->adc_channel[count].wait);
	  }
	}

  /* we are using autobuffer mode in 2-d.
     There is no need to reinit the DMA.
  */
}

// void sport_ac97_isr_tx(...);	//update civ, lvi, picb, sr, glob_sta, glob_cnt
// enter here when halfpoint or endpoint of tx buffer of dma is reached, what we need to do
//is:
inline void sport_isr_tx(void)
{
  /* loop through the dac queue and wake them if the
     wakeup count is large enough
  */
    int count;
    extern struct adi_sport_1836_card *devs;
    
    for(count = 0; count < MAX_DAC_CHANNELS; count++){
      if(devs->dac_channel[count].used){
		wake_up_interruptible(&devs->dac_channel[count].wait);
      }
    }
  
  /* we are using autobuffer mode in 2-d.
     There is no need to reinit the DMA.
  */

}

#ifdef LINUX
static irqreturn_t Sport0_RX_ISR(int irq, void *dev_id, struct pt_regs * regs)
#else
EX_INTERRUPT_HANDLER(Sport0_RX_ISR)
#endif

{
	// confirm interrupt handling
	*pDMA1_IRQ_STATUS = 0x0001;
	
	/* call the rx and tx handlers */
	sport_isr_rx();
	sport_isr_tx();
	return IRQ_HANDLED;
}

/*** The main driver ****/


struct adi_sport_1836_card *devs = NULL;

volatile short sCodec1836TxRegs[CODEC_1836_REGS_LENGTH] =
{									
					DAC_CONTROL_1	| 0x000,
					DAC_CONTROL_2	| 0x000,
					DAC_VOLUME_0	| 0x3ff,
					DAC_VOLUME_1	| 0x3ff,
					DAC_VOLUME_2	| 0x3ff,
					DAC_VOLUME_3	| 0x3ff,
					DAC_VOLUME_4	| 0x3ff,
					DAC_VOLUME_5	| 0x3ff,
					ADC_CONTROL_1	| 0x000,
					ADC_CONTROL_2	| 0x180,
					ADC_CONTROL_3	| 0x000
					
};
// SPORT0 DMA transmit buffer
volatile int iTxBuffer1[8*BUF_SIZE];
// SPORT0 DMA receive buffer
volatile int iRxBuffer1[8*BUF_SIZE];


void
pcm_channels_init(struct adi_sport_1836_card *card)
{
  int channel;

  for(channel = 0; channel < MAX_DAC_CHANNELS; channel++){
    card->dac_channel[channel].used = 0;
	card->dac_channel[channel].dma_buffer = iTxBuffer1;
    card->dac_channel[channel].mode = FMODE_WRITE;
    init_waitqueue_head(&card->dac_channel[channel].wait);
  }
  for(channel = 0; channel < MAX_ADC_CHANNELS; channel++){
    card->adc_channel[channel].used = 0;
    card->adc_channel[channel].dma_buffer = iRxBuffer1;
    card->adc_channel[channel].mode = FMODE_READ;
    init_waitqueue_head(&card->adc_channel[channel].wait);
  }
}

/* Allocate the next available PCM channel.
   If channel number is specified, use that
*/
static struct adi_sport_1836_channel *
adi_spt_alloc_dac_pcm_channel(struct adi_sport_1836_card *card, int channel)
{
  if(channel >= MAX_DAC_CHANNELS){
    /* look for next free channel */
    for(channel = 0; channel < MAX_DAC_CHANNELS; channel++){
      if(card->dac_channel[channel].used == 0)
        break;
    }
  }
  else if(channel < 0){
  	/* look for corresponding matching stereo channel */
  	channel = -channel;
  	if(channel < MAX_DAC_CHANNELS / 2) channel += MAX_DAC_CHANNELS / 2;
  	else channel -= MAX_DAC_CHANNELS / 2;
  	channel--; // convert to index
  }

  if(channel > MAX_DAC_CHANNELS || channel < 0)
    return NULL;

  if(card->dac_channel[channel].used == 1)
    return NULL;

  card->dac_channel[channel].used = 1;
  card->dac_channel[channel].current_buffer_position = 0;
  card->dac_channel[channel].virt = channel;
  if(channel >= MAX_DAC_CHANNELS / 2)
  	card->dac_channel[channel].slot = channel + 1;
  else
  	card->dac_channel[channel].slot = channel; // TODO : left / right check
#ifndef LINUX
  card->dac_channel[channel].wait = 1;
#endif
  return &card->dac_channel[channel];
}

static struct adi_sport_1836_channel *
adi_spt_alloc_adc_pcm_channel(struct adi_sport_1836_card *card, int channel)
{
  if(channel >= MAX_ADC_CHANNELS){
    /* look for next free channel */
    for(channel = 0; channel < MAX_ADC_CHANNELS; channel++){
      if(card->adc_channel[channel].used == 0)
        break;
    }
  }
  else if(channel < 0){
  	/* look for corresponding matching stereo channel */
  	channel = -channel;
  	if(channel < MAX_ADC_CHANNELS / 2) channel += MAX_ADC_CHANNELS / 2;
  	else channel -= MAX_ADC_CHANNELS / 2;
  	channel--; // convert to index
  }

  if(channel > MAX_ADC_CHANNELS || channel < 0)
    return NULL;

  if(card->adc_channel[channel].used == 1)
    return NULL;

  card->adc_channel[channel].used = 1;

  card->adc_channel[channel].current_buffer_position = 0;
  card->adc_channel[channel].virt = channel;
  if(channel >= MAX_ADC_CHANNELS / 2)
  	card->adc_channel[channel].slot = channel + 2;
  else
    card->adc_channel[channel].slot = channel;
#ifndef LINUX
  card->adc_channel[channel].wait = 0; // initiallly wait for the first buffer to be written to
#endif
  return &card->adc_channel[channel];
}

/* write operation ... DAC is being written to
   Copy the contents of buffer to the corresponding channels'
   slots in the dma buffer.

   If not enough space, wait
 */

#ifdef LINUX   
static 
#endif
ssize_t 
adi_sport_1836_write(struct file *file, 
					 const char *buffer,size_t count,
					 loff_t *ppos)
{
  struct adi_sport_1836_instance *instance = 
     (struct adi_sport_1836_instance *)file->private_data;
  struct adi_sport_1836_channel *channel;
  size_t ret;
  int mod;
  int index;
  // if count is not modulo the size of outgoing data,
  // only write upto alignment
  // TODO : currently we are assuming size of 32
  if((count % (sizeof(unsigned int) * instance->channels_used)) != 0)
    count = count - (count % (sizeof(unsigned int) * instance->channels_used));
  if(count <= 0)
    return 0;

  // TODO : we need to support multiple channel read
  
  channel = instance->physical_channels[instance->channels_used - 1];
  ret = 0;
  //mod = SPORT_DMA_BUFFER_SIZE*FRAMES_PER_BUFFER*SPORT_FRAME_SIZE/CIRC_BUF_COUNT;
  mod = BUF_SIZE * 8 / 2;
  while(count > 0){
    if((channel->current_buffer_position == 0) ||
       (channel->current_buffer_position % mod) == 0){
      /* we are at the threshold of the next buffer */
      /* TODO : Check if the next buffer is currently being read */
      /*        This is to make sure we are not in an overrun situation */
      if(! 0 /* TODO: overrun check */){
        /* wait for the buffer to be free */
        interruptible_sleep_on(&channel->wait);
      }
#ifndef LINUX
      if(!check_semaphore(&channel->wait)){
        return ret; // waiting ...
      }
#ifdef DEBUG2
      else{
      	printf("sem %d\n", channel->wait);
      }
#endif
#endif
    }
    /* ok, write to the current_buffer_position */
    for(index = 0; index < instance->channels_used; index++){
	    // TODO : copy into the dma_buffer after adjusting for incoming size
      copy_from_user(&channel->dma_buffer[channel->current_buffer_position + 
      			instance->physical_channels[index]->slot], 
      			buffer + ret,
      			sizeof(unsigned int));
	    
      // bump up ret and bump down count adjusting for size of dat
      ret += sizeof(unsigned int);
      count -= sizeof(unsigned int); // indexing const char *
    }
    /* increment current_buffer_position and count */
    channel->current_buffer_position += SPORT_FRAME_SIZE; // indexing unsigned int *
    // this is a circular buffer, so mod with size
	//    channel->current_buffer_position %= SPORT_DMA_BUFFER_SIZE*FRAMES_PER_BUFFER*SPORT_FRAME_SIZE;
	channel->current_buffer_position %= BUF_SIZE * 8;
  }

  return ret;
}

#ifdef LINUX
static 
#endif
ssize_t 
adi_sport_1836_read(struct file *file, 
                     const char *buffer, 
                     size_t count, 
                     loff_t *ppos)
{
  struct adi_sport_1836_instance *instance = 
     (struct adi_sport_1836_instance *)file->private_data;
  struct adi_sport_1836_channel *channel;
  size_t ret;
  int mod;
  int index;

  // if count is not modulo the size of incoming data,
  // only read upto alignment
  // TODO : currently we are assuming size of 32
  if((count % (sizeof(unsigned int) * instance->channels_used)) != 0)
    count = count - (count % (sizeof(unsigned int) * instance->channels_used));
  if(count <= 0)
    return 0;
    
  // TODO : we need to support multiple channel read
  
  // used the channel of physical channel 0 for storing the buffer position
  channel = instance->physical_channels[0];
#ifdef DEBUG4  
printf("--%d--reading %x\n", channel->current_buffer_position, 
	&channel->dma_buffer[channel->current_buffer_position + channel->slot]);
printf("rx Addr = %x XCount = %d YCount = %d\n", *pDMA1_CURR_ADDR ,
				*pDMA1_CURR_X_COUNT, *pDMA1_CURR_Y_COUNT );  
#endif
  ret = 0;
  //mod = SPORT_DMA_BUFFER_SIZE*FRAMES_PER_BUFFER*SPORT_FRAME_SIZE/CIRC_BUF_COUNT;
  mod = BUF_SIZE * 8 / 2;
  while(count > 0){
    if((channel->current_buffer_position == 0) ||
       (channel->current_buffer_position % mod) == 0){
      /* we are at the threshold of the next buffer */
      /* TODO : Check if the next buffer is currently being read */
      /*        This is to make sure we are not in an overrun situation */
      if(! 0 /* TODO: overrun check */){
        /* wait for the buffer to be free */
#ifdef DEBUG_
printk("sleeping on %d %d\n", count, channel->wait);
#endif
        interruptible_sleep_on(&channel->wait);
      }
#ifndef LINUX
      if(!check_semaphore(&channel->wait)){
        return ret; // waiting ...
      }
#ifdef DEBUG2
      else{
      	printf("sem %d\n", channel->wait);
      }
#endif
#endif
    }
    /* if this has multiple physical channels, copy will alternate in the buffer
       for a storeo data will be l.r.l.r.
     */
    /* ok, write to the current_buffer_position */
    for(index = 0; index < instance->channels_used; index++){
	    // TODO : copy position of dma_buffer to be adjusted for
	    //        size of data expected
	    copy_to_user(buffer + ret,
	                 &channel->dma_buffer[channel->current_buffer_position + 
	                 instance->physical_channels[index]->slot], 
	                 sizeof(unsigned int));
	    // TODO : Bump up ret and bump down count depending on
	    //        size of data
	    ret += sizeof(unsigned int);
	    count -= sizeof(unsigned int); // indexing const char *
    }
    /* increment current_buffer_position and count */
    channel->current_buffer_position += SPORT_FRAME_SIZE; // indexing unsigned int *
    // this is a circular buffer, so mod with size
    //channel->current_buffer_position %= SPORT_DMA_BUFFER_SIZE*FRAMES_PER_BUFFER*SPORT_FRAME_SIZE;
    channel->current_buffer_position %= BUF_SIZE * 8;
  }

  return ret;
}

/////////////////////////////////////////////////////////////
#ifdef LINUX
static 
#endif
int
adi_sport_1836_open(struct inode *inode, struct file *file)
{											  
  struct adi_sport_1836_card *card = devs;
  

  struct adi_sport_1836_instance *instance = card->alloc_instance(card, file->f_mode);
  if(instance == NULL){
  	return -EBUSY;
  }
  file->private_data = instance;
  return 0;
}

static struct adi_sport_1836_instance *
adi_sport_1836_instance_alloc(struct adi_sport_1836_card *card, int mode)
{
  // allocate for the instance structure
  struct adi_sport_1836_instance *instance = kmalloc(sizeof(struct adi_sport_1836_instance), GFP_KERNEL);
  if(instance == NULL)
    return NULL;
  
  // allocate for max channels needed. These are only pointers
  instance->physical_channels = (struct adi_sport_1836_channel **)
  				kmalloc(sizeof(struct adi_sport_1836_channel *) * MAX_DAC_CHANNELS, GFP_KERNEL);
  instance->mode = mode;
  
  /* allocate hardware channels */
  if(mode & FMODE_READ) {
     /* Get an ADC channel */
     if((instance->physical_channels[0] = card->alloc_adc_pcm_channel(card, MAX_ADC_CHANNELS)) == NULL) {
        return NULL;
     }
//     adi_spt_set_adc_rate(instance->physical_channels[0], MAX_ADC_RATE);
  }
  if(mode & FMODE_WRITE) {
    /* Get a DAC channel */
    if((instance->physical_channels[0] = card->alloc_dac_pcm_channel(card, MAX_DAC_CHANNELS)) == NULL) {
      return NULL;
    }
//    adi_spt_set_dac_rate(instance->physical_channels[0], MAX_DAC_RATE);
  }
  // assign physical channel to the structure, default mono
  instance->channels_used = 1; // mono
  return instance;
}

static loff_t 
adi_sport_1836_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}
static void
stop_adc(struct adi_sport_1836_channel *channel)
{
  // TODO : If the channel is in ADC read, make it exit
}

static void 
start_adc(struct adi_sport_1836_channel *channel)
{
}

static void 
stop_dac(struct adi_sport_1836_channel *channel)
{
  // TODO : If the channel is in DAC write, make it exit
}	

static void 
start_dac(struct adi_sport_1836_channel *channel)
{
}


/* Since we have only one dma engine, we dont stop the dma engine
*/
static int
adi_sport_1836_release(struct inode *inode, struct file *file)
{
  struct adi_sport_1836_instance *instance = 
     (struct adi_sport_1836_instance *)file->private_data;
  struct adi_sport_1836_card *card = devs;
  int index;

  // TODO : Re-entrancy requirement ... make sure that the read/write
  //        is not waiting. If so, release them and make them exit
  //        This is best done by adding a flag to the channel which
  //        read / write will check in addition to count
  //        Some kind of stop_adc / stop_dac routines

  /* free hardware channels */
  for(index = 0; index < instance->channels_used; index++){
	  if(instance->mode & FMODE_READ) {
	     /* an ADC channel */
	     stop_adc(instance->physical_channels[index]);
	     card->free_adc_pcm_channel(devs, instance->physical_channels[index]->virt);
	  }
	  else if(instance->mode & FMODE_WRITE) {
	    /* a DAC channel */
	    stop_dac(instance->physical_channels[index]);
	    card->free_dac_pcm_channel(devs, instance->physical_channels[index]->virt);
	  }
  }
  kfree(instance->physical_channels);
  kfree(instance);

  return 0;
}

/////////////////////////////////////////////////////////////
#ifdef LINUX
static 
#endif
int 
adi_sport_1836_ioctl(struct inode *inode, 
                     struct file *file, 
                     unsigned int cmd, 
                     unsigned long arg)
{
	struct adi_sport_1836_instance *instance = 
              (struct adi_sport_1836_instance *)file->private_data;
        int ret;
        int val;
#ifdef DEBUG
	printk("adi_spt_audio: adi_spt_ioctl, arg=0x%x, cmd=", arg ? *(int *)arg : 0);
#endif

	switch (cmd) 
	{
	case OSS_GETVERSION:
#ifdef DEBUG
		printk("OSS_GETVERSION\n");
#endif
		return put_user(SOUND_VERSION, (int *)arg);

	case SNDCTL_DSP_RESET:
#ifdef DEBUG
		printk("SNDCTL_DSP_RESET\n");
#endif
		/* FIXME: spin_lock ? */
        //stop_dac(channel); // TODO : maybe check mode before call
		//stop_adc(channel);
// TODO : First time enable the dma
printk("Initializing Sport Interrupts\n");
Init_Sport_Interrupts();
Enable_DMA_Sport0();
		synchronize_irq();

                // TODO : do other initialization for this channel
                // it is not chip reset for us
	
		return 0;

	case SNDCTL_DSP_SYNC:
#ifdef DEBUG
		printk("SNDCTL_DSP_SYNC\n");
#endif
	    //stop_dac(channel); // TODO : maybe check mode before call
		//stop_adc(channel);
		synchronize_irq();
		return 0;

	case SNDCTL_DSP_SPEED: /* set smaple rate */
#ifdef DEBUG
		printk("SNDCTL_DSP_SPEED\n");
#endif
		if (get_user(val, (int *)arg))
			return -EFAULT;
		if (val >= 0) {
                  // TODO : How to interpret ... all channels sample rate is common
		}
		return put_user(val, (int *)arg);

	case SNDCTL_DSP_STEREO: /* set stereo or mono channel */
#ifdef DEBUG
		printk("SNDCTL_DSP_STEREO\n");
#endif
		if (get_user(val, (int *)arg))
			return -EFAULT;
		if(val==0) {
			ret = -EINVAL;
		} else {
			ret = 1;
		}
		// if corresponding physical channel is not used, allocate
		// data from this point on will be stereo data
		if(add_physical_channel((struct adi_sport_1836_instance *)(file->private_data)) != 0){
			*((int *)arg) = 1;
		}
		return put_user(ret, (int *)arg);

	case SNDCTL_DSP_GETBLKSIZE:
		 ret = -EINVAL;
                 return ret;

	case SNDCTL_DSP_GETFMTS: /* Returns a mask of supported sample format*/
#ifdef DEBUG
		printk("SNDCTL_DSP_GETFMTS\n");
#endif
		return put_user(AFMT_S16_LE, (int *)arg);

	case SNDCTL_DSP_SETFMT: /* Select sample format */
#ifdef DEBUG
		printk("SNDCTL_DSP_SETFMT\n");
#endif
		return put_user(AFMT_S16_LE, (int *)arg);

	case SNDCTL_DSP_CHANNELS:
#ifdef DEBUG
		printk("SNDCTL_DSP_CHANNELS\n");
#endif
		return put_user(6, (int *)arg);

	case SNDCTL_DSP_POST: /* the user has sent all data and is notifying us */
		/* we update the swptr to the end of the last sg segment then return */
                 ret = -EINVAL;
                 return ret;

	case SNDCTL_DSP_SUBDIVIDE:
                 ret = -EINVAL;
                 return ret;

	case SNDCTL_DSP_SETFRAGMENT:
                 ret = -EINVAL;
                 return ret;

	case SNDCTL_DSP_GETOSPACE:

	case SNDCTL_DSP_GETOPTR:

	case SNDCTL_DSP_GETISPACE:

	case SNDCTL_DSP_GETIPTR:
                 ret = -EINVAL;
                 return ret;

	case SNDCTL_DSP_NONBLOCK:
#ifdef DEBUG
		printk("SNDCTL_DSP_NONBLOCK\n");
#endif
		file->f_flags |= O_NONBLOCK;
		return 0;

	case SNDCTL_DSP_GETCAPS:
#ifdef DEBUG
		printk("SNDCTL_DSP_GETCAPS\n");
#endif
	    return put_user(DSP_CAP_REALTIME|DSP_CAP_BIND,
			    (int *)arg);

	case SNDCTL_DSP_GETTRIGGER:

	case SNDCTL_DSP_SETTRIGGER:

	case SNDCTL_DSP_SETDUPLEX:
#ifdef DEBUG
		printk("SNDCTL_DSP_SETDUPLEX\n");
#endif
		return -EINVAL;

	case SNDCTL_DSP_GETODELAY:

	case SOUND_PCM_READ_RATE:

	case SOUND_PCM_READ_CHANNELS:
#ifdef DEBUG
		printk("SOUND_PCM_READ_CHANNELS\n");
#endif
		return put_user(3, (int *)arg);

	case SOUND_PCM_READ_BITS:
#ifdef DEBUG
		printk("SOUND_PCM_READ_BITS\n");
#endif
		return put_user(AFMT_S16_LE, (int *)arg);

	case SNDCTL_DSP_MAPINBUF:
	case SNDCTL_DSP_MAPOUTBUF:
	case SNDCTL_DSP_SETSYNCRO:
	case SOUND_PCM_WRITE_FILTER:
	case SOUND_PCM_READ_FILTER:
#ifdef DEBUG
		printk("SNDCTL_* -EINVAL\n");
#endif
		return -EINVAL;
	}
	return -EINVAL;
}

#ifdef LINUX
static void 
sport_1836_init(void )
{
printk("Init_Flash();\n");
	Init_Flash();
#ifndef LINUX
sport_audio_1836_init();	
#endif
printk("Init1836();\n");
	Init1836();
printk("init_Sport0\n");
	Init_Sport0();
printk("Init_DMA();\n");
	Init_DMA();
#if 0
printk("Init_Sport_Interrupts();\n");
	Init_Sport_Interrupts();
printk("Enable_DMA_Sport0();\n");
	Enable_DMA_Sport0();
#endif
	return;
}
#endif


#ifdef LINUX
static /*const*/ struct file_operations adi_spt_audio_fops = {
	owner:		THIS_MODULE,
	llseek:		adi_sport_1836_llseek,
	read:		adi_sport_1836_read,
	write:		adi_sport_1836_write,
	//poll:		adi_sport_1836_poll,
	ioctl:		adi_sport_1836_ioctl,
	open:		adi_sport_1836_open,
	release:	adi_sport_1836_release,
};

#endif
#ifdef LINUX 
static 
#endif
int __init sport_audio_1836_init(void)
{

#ifdef LINUX
  if ((devs = kmalloc(sizeof(struct adi_sport_1836_card), GFP_KERNEL)) == NULL) {
    printk(KERN_ERR "sport_audio_1836_init: out of memory\n");
    return -ENOMEM;
  }
#else
/* TESTSET requires the bit to be in SRAM not in onchip RAM.
   This SRAM is not being used in our test example
*/
devs = 0x4000;
#endif
  memset(devs, 0, sizeof(devs));
#if 0 // TODO : fix this initialization
  devs->iobase = (unsigned long)&sport_ac97_map;
  devs->ac97base = 0;
  devs->magic = ADI_SPT_devs_MAGIC;
#endif
  devs->irq = IRQ_SPORT0;
//  devs->next = devs;
  spin_lock_init(devs->lock);

  pcm_channels_init(devs);
  devs->alloc_dac_pcm_channel = adi_spt_alloc_dac_pcm_channel;
  devs->alloc_adc_pcm_channel = adi_spt_alloc_adc_pcm_channel;
  devs->free_dac_pcm_channel = adi_spt_free_dac_pcm_channel;
  devs->free_adc_pcm_channel = adi_spt_free_adc_pcm_channel;
  devs->alloc_instance       = adi_sport_1836_instance_alloc;

#ifdef LINUX
  /* register /dev/dsp */
  if ((devs->dev_audio = register_sound_dsp(&adi_spt_audio_fops, -1)) < 0) {
    printk(KERN_ERR "adi_spt_audio: couldn't register DSP device!\n");
    free_irq(devs->irq, devs);
    kfree(devs);
    return -ENODEV;
  }

  /* Now, enable the 1836 ... this includes SPI, 1836, SPORT and DMA.
     isr should be setup and we should be receiving interrupts
  */
  sport_1836_init();

  // TODO : Should register_sound_dsp be called after sport_1836_init?
#endif


  return 0;
}

static void 
adi_spt_free_dac_pcm_channel(struct adi_sport_1836_card *card, int channel)
{
  card->dac_channel[channel].used=0;
}

static void 
adi_spt_free_adc_pcm_channel(struct adi_sport_1836_card *card, int channel)
{
  devs->adc_channel[channel].used=0;
}

/* set playback sample rate */
static unsigned int 
adi_spt_set_dac_rate(struct adi_sport_1836_channel *channel, unsigned int rate)
{	
  // TODO : Set the rate and return read value
  return rate; 
}

/* set recording sample rate */
static unsigned int 
adi_spt_set_adc_rate(struct adi_sport_1836_channel *channel, unsigned int rate)
{
  // TODO : Set the rate and return read value
  return rate; 
}

static int
add_physical_channel(struct adi_sport_1836_instance *instance)
{
	// if a free slot is available add it.
	// if odd number, add the corresponding stereo
	// if even number, add next odd available
	struct adi_sport_1836_channel *(*alloc_pcm_channel)(struct adi_sport_1836_card *, int channel);	
	int channel_no;
  struct adi_sport_1836_card *card = devs;
	
	if(instance->mode & FMODE_READ)
	 alloc_pcm_channel = card->alloc_adc_pcm_channel;
	else
	  alloc_pcm_channel = card->alloc_dac_pcm_channel;
	  
	if(instance->channels_used % 2){
	  // odd channels, look for the corresponding stereo
	  channel_no = -(instance->physical_channels[instance->channels_used - 1]->virt + 1);
	}
	else{
		channel_no = MAX_DAC_CHANNELS+10;
	}
	
    if((instance->physical_channels[instance->channels_used] = 
    		alloc_pcm_channel(card, channel_no)) == NULL) {
        return -EBUSY;
    }
    instance->channels_used++;
    return 0;
}

////////////////////////////////////////////////////////////////

/* set the specific channel's volume */
int
adi_sport_set_volume(int channel, int volume)
{
	if(volume < 0 || volume > 0x3ff)
	  return -1;
	switch(channel){
		case 0 :
			 sCodec1836TxRegs[DAC_VOLUME_0_INDEX] = DAC_VOLUME_0 | volume;
			 break;
		case 1 :
			 sCodec1836TxRegs[DAC_VOLUME_1_INDEX] = DAC_VOLUME_1 | volume;
			 break;
		case 2 :
			 sCodec1836TxRegs[DAC_VOLUME_2_INDEX] = DAC_VOLUME_2 | volume;
			 break;
		case 3 :
			 sCodec1836TxRegs[DAC_VOLUME_3_INDEX] = DAC_VOLUME_3 | volume;
			 break;
		case 4 :
			 sCodec1836TxRegs[DAC_VOLUME_4_INDEX] = DAC_VOLUME_4 | volume;
			 break;
		case 5 :
			 sCodec1836TxRegs[DAC_VOLUME_5_INDEX] = DAC_VOLUME_5 | volume;
			 break;
	}
	Config1836();
	return volume;
}

/*

DAC Control Register 2
Bit   15:12     11      10    9:6   5      4      3      2      1      0
Info  Addr      R/W     Rsvd  Rsvd  DAC3R  DAC3L  DAC2R  DAC2L  DAC1R  DAC1L
Value 0001      0       0     0     0=on   0=on   0=on   0=on   0=on   0=on   
                                    1=mute 1=mute 1=mute 1=mute 1=mute 1=mute 
*/

#define DAC_C2_MUTE_1L	0x0001
#define DAC_C2_MUTE_1R	0x0002
#define DAC_C2_MUTE_2L	0x0004
#define DAC_C2_MUTE_2R	0x0008
#define DAC_C2_MUTE_3L	0x0010
#define DAC_C2_MUTE_3R	0x0020

int
adi_sport_mute(int channel, int what)
{
	unsigned short old_mute = sCodec1836TxRegs[DAC_CONTROL_2_INDEX];
	unsigned short new_mute;
	int channel_shift;
	if(what != 0 || what != 1)
	 return -1;
	
	switch(channel){
		case 0 :
			 channel_shift = 0;
			 break;
		case 1 :
			 channel_shift = 2;
			 break;
		case 2 :
			 channel_shift = 4;
			 break;
		case 3 :
			 channel_shift = 1;
			 break;
		case 4 :
			 channel_shift = 3;
			 break;
		case 5 :
			 channel_shift = 5;
			 break;
	}
	new_mute = what << channel_shift;
	old_mute |= new_mute;
	sCodec1836TxRegs[DAC_CONTROL_2_INDEX] = DAC_CONTROL_2 | old_mute;
	Config1836();
	
	return what;
}

int
adi_sport_muteall(int what)
{
	int index;
	unsigned short old_mute = sCodec1836TxRegs[DAC_CONTROL_2_INDEX];
	unsigned short new_mute;
	int channel_shift;
	if(what != 0 || what != 1)
	 return -1;
	for(index = 0; index < 6; index++){
		old_mute = sCodec1836TxRegs[DAC_CONTROL_2_INDEX];
		switch(index){
			case 0 :
				 channel_shift = 0;
				 break;
			case 1 :
				 channel_shift = 2;
				 break;
			case 2 :
				 channel_shift = 4;
				 break;
			case 3 :
				 channel_shift = 1;
				 break;
			case 4 :
				 channel_shift = 3;
				 break;
			case 5 :
				 channel_shift = 5;
				 break;
		}
		new_mute = what << channel_shift;
		old_mute |= new_mute;
		sCodec1836TxRegs[DAC_CONTROL_2_INDEX] = DAC_CONTROL_2 | old_mute;
	}
	Config1836();
	
	return what;
}

#ifdef LINUX
MODULE_AUTHOR("Analog Devices");
MODULE_DESCRIPTION("Blackfin SPORT 1836 audio support");
#define BLACKFIN_SPORT_MODULE_NAME "blackfin_sport_audio"
#endif

static void __init adi_spt_configure_clocking (void)
{
}
static unsigned int clocking;
#ifdef LINUX
static
#endif
int __init adi_sport_1836_init_module (void)
{
printk("Starting %s\n", BLACKFIN_SPORT_MODULE_NAME);
        sport_audio_1836_init();

        // TODO : do we need this for 1836?
        if(clocking == 48000) {
                adi_spt_configure_clocking();
        }
        return 0;
}

static void __exit adi_sport_1836_remove(void )
{
	struct adi_sport_1836_card *card = devs;
	/* free hardware resources */
	free_irq(card->irq, devs);

	unregister_sound_dsp(card->dev_audio);
	kfree(card);
        devs = NULL;
}



#ifdef LINUX
module_init(adi_sport_1836_init_module);
module_exit(adi_sport_1836_remove);
#endif

