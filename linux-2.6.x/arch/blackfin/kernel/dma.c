/*
 * ########################################################################
 *
 *  This program is free software; you can distribute it and/or modify it
 *  under the terms of the GNU General Public License (Version 2) as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * ########################################################################
*/

#include <asm/dma.h>

/**************************************************************************
 * Global Variables 
***************************************************************************/

DMA_channel 	dma_ch[MAX_BLACKFIN_DMA_CHANNEL];

DMA_register* 	base_addr[MAX_BLACKFIN_DMA_CHANNEL] =
{
	(DMA_register *) 0xffc00c00,		
	(DMA_register *) 0xffc00c40,	
	(DMA_register *) 0xffc00c80,
	(DMA_register *) 0xffc00cc0,
	(DMA_register *) 0xffc00d00,
	(DMA_register *) 0xffc00d40,
	(DMA_register *) 0xffc00d80,
	(DMA_register *) 0xffc00dc0,
	(DMA_register *) 0xffc00e00,
	(DMA_register *) 0xffc00e40,
	(DMA_register *) 0xffc00e80,
	(DMA_register *) 0xffc00ec0,
};

DMA_MAPPING Mapping[] = {
	{ DMA_DEVICE_PPI,	0,	0,	PMAP_PPI	},
	{ DMA_DEVICE_SPORT_RX,	0,	0,	PMAP_SPORT0_RX	},
	{ DMA_DEVICE_SPORT_TX,	0,	0,	PMAP_SPORT0_TX	},
	{ DMA_DEVICE_SPORT_RX,	1,	0,	PMAP_SPORT1_RX	},
	{ DMA_DEVICE_SPORT_TX,	1,	0,	PMAP_SPORT1_TX	},
	{ DMA_DEVICE_SPI,	0,	0,	PMAP_SPI	},
	{ DMA_DEVICE_UART_RX,	0,	0,	PMAP_UART_RX	},
	{ DMA_DEVICE_UART_TX,	0,	0,	PMAP_UART_TX	},
};

struct semaphore dmalock;

void 		testcallback (DMA_EVENT, void *);

/****************************************************************************
*
*  			 INITIALIZATION FUNCTIONS 
*
*****************************************************************************/

/*------------------------------------------------------------------------------
* Name:
*		blackfin_dma_init()
* Description:
*		This is the initialization routine for Blackfin DMA driver.
* Parameters:
*		None
* Return:
*		None
*-------------------------------------------------------------------------------*/

int __init blackfin_dma_init(void)
{
	int 	i;
	
	printk("Blackfin DMA Controller for BF533\n");	
	
	init_MUTEX(&dmalock);

	for (i = 0; i < MAX_BLACKFIN_DMA_CHANNEL; i++)
	{
		dma_ch[i].dma_channel_status = DMA_CHANNEL_AVAILABLE;
		dma_ch[i].regs = base_addr[i];	
	}
	
	return 0;

}
module_init(blackfin_dma_init);

/*------------------------------------------------------------------------------
* Name:
*		InitializeChannel()
* Description:
*		This function is used to Initialize the channel with the given values 			
* Parameters:
*		channel_number:	Channel Number of the Channel to be initialized		
*		cfg:		Configuaration value to be set		
*		start_addr:	start address of the DMA Transfer, to be set		
*		x_count:	x_count value to be set for the DMA transfer		
*		x_modify:	x_modify value to be set for the DMA transfer		
*		y_count:	y_count value to be set for the DMA transfer		
*		y_modify:	y_modify value to be set for the DMA transfer		
* Return: 
*		None
*-------------------------------------------------------------------------------*/

int InitializeChannel (unsigned int channel_number, unsigned short cfg, unsigned short start_addr, 
			unsigned short x_count, unsigned short x_modify, 
			unsigned short y_count, unsigned short y_modify)
{
	if (channel_number >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel_number].regs->cfg = cfg; 
	SSYNC();
	dma_ch[channel_number].regs->start_addr = start_addr;
	SSYNC();
	dma_ch[channel_number].regs->x_count = x_count;
	SSYNC();
	dma_ch[channel_number].regs->x_modify = x_modify;
	SSYNC();
	dma_ch[channel_number].regs->y_count = y_count;
	SSYNC();
	dma_ch[channel_number].regs->y_modify = y_modify;
	SSYNC();

	return DMA_SUCCESS;
}


/***************************************************************************
*
*			Generic DMA API's 
*
*****************************************************************************/

/*------------------------------------------------------------------------------
* Name:
*		request_dma()
* Description:
*		Request the specific DMA channel from the system. 
*
* Parameters:
*		channel:	DMA channel number (See header file for more information).
*		device_id:	pointer to the device ID for the DMA channel. 
*		dma_interrupt:	Interrupt service routine. 
*		callback:	Callback function that can be called from ISR. 
* Return:
*		The channel number will be returned on success.
*		DMA_NO_SUCH_CHANNEL will be returned for invalid channel number 
*		DMA_CHANNEL_IN_USE will be returned, if the channel is already in use. 
*-------------------------------------------------------------------------------*/
int request_dma(unsigned int channel, const char* device_id, dma_interrupt_t dma_interrupt, dma_callback_t callback)
{

	DMA_DBG("request_dma() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	down(&dmalock);

	if (dma_ch[channel].dma_channel_status == DMA_CHANNEL_ALLOCATED ) {
		up(&dmalock);
		DMA_DBG("DMA CHANNEL IN USE  \n");
		return DMA_CHANNEL_IN_USE; 
	}
	else{
	
		dma_ch[channel].dma_channel_status = DMA_CHANNEL_ALLOCATED ;		
		DMA_DBG("DMA CHANNEL IN USE  \n");
	}
	up(&dmalock);

	dma_ch[channel].device_id = device_id;
 	dma_ch[channel].callback = callback;
 	dma_ch[channel].descr_base = BASE_VALUE;
	dma_ch[channel].LoopbackFlag = 0;

	/* This is to be enabled by putting a restriction - you have to request DMA , 
	   before doing any operations on descriptor/channel */

	InitializeChannel(channel, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02);
	DMA_DBG("InitializeChannel : Done  \n");

	switch (channel){
		case CH_PPI: 
			request_irq(IRQ_PPI, (void *)dma_interrupt, SA_INTERRUPT, "ppi-dma", NULL);
			enable_irq (IRQ_PPI);
			break;
		case CH_SPORT0_RX: 
		case CH_SPORT0_TX: 
			request_irq(IRQ_SPORT0, (void *)dma_interrupt, SA_INTERRUPT, "sport0-dma", NULL);
			enable_irq (IRQ_SPORT0);
			break;
		case CH_SPORT1_RX: 
		case CH_SPORT1_TX: 
			request_irq(IRQ_SPORT1, (void *)dma_interrupt, SA_INTERRUPT, "sport1-dma", NULL);
			enable_irq (IRQ_SPORT1);
			break;
		case CH_SPI: 
			request_irq(IRQ_SPI, (void *)dma_interrupt, SA_INTERRUPT, "spi-dma", NULL);
			enable_irq (IRQ_SPI);
			break;
		case CH_UART_RX: 
		case CH_UART_TX: 
			request_irq(IRQ_UART, (void *)dma_interrupt, SA_INTERRUPT, "uart-dma", NULL);
			enable_irq (IRQ_UART);
			break;
		case CH_MEM_STREAM0_SRC: 
		case CH_MEM_STREAM0_DEST: 
			request_irq(IRQ_MEM_DMA0, (void *)dma_interrupt, SA_INTERRUPT, "MemoryStream0-dma", NULL);
			enable_irq (IRQ_MEM_DMA0);
			break;
		case CH_MEM_STREAM1_SRC: 
		case CH_MEM_STREAM1_DEST: 
			request_irq(IRQ_MEM_DMA1, (void *)dma_interrupt, SA_INTERRUPT, "MemoryStream1-dma", NULL);
			enable_irq (IRQ_MEM_DMA1);
			break;
		default:
			break;
	}
	DMA_DBG("IRQ related : Done  \n");

/* If the user calls the request_dma() , at the end of descriptor setup
   then this will cause problem  
   To avoid this problem , we can have restriction, to call the request_dma()
   before using the any other DMA API's, that uses/modifies the channel info. 	
   - To Be Discussed and Finalized 
*/
#if 0
	dma_ch[channel].L_last_descriptor = BASE_VALUE;
	dma_ch[channel].L_first_descriptor = BASE_VALUE;
	dma_ch[channel].L_wait_last_descriptor = BASE_VALUE;
	dma_ch[channel].L_wait_first_descriptor = BASE_VALUE;
	dma_ch[channel].L_next_descriptor = BASE_VALUE;

	dma_ch[channel].S_last_descriptor = BASE_VALUE;
	dma_ch[channel].S_first_descriptor = BASE_VALUE;
	dma_ch[channel].S_wait_last_descriptor = BASE_VALUE;
	dma_ch[channel].S_wait_first_descriptor = BASE_VALUE;
	dma_ch[channel].S_next_descriptor = BASE_VALUE;
#endif

	/* DMA_ERR Interrupt Handler request process has to be done - TODO */

	DMA_DBG("request_dma() : END  \n");

	return channel;
}


/*------------------------------------------------------------------------------
* Name:
*		free_dma()
* Description:
*		Free the specific DMA channel 
* Parameters:
*		channel:	DMA channel number.
* Return:
*		None		
*-------------------------------------------------------------------------------*/
int freedma(unsigned int channel)
{
	DMA_DBG("freedma() : BEGIN \n");
		
	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

		
	/* Check for the DMA Error - TODO  */

	/* Halt the DMA */
	disable_dma(channel);
	clear_dma_buffer(channel);	
	disable_dma_buffer_clear(channel);

	/* DMA Error Handler processing - TODO  */

	/* Make sure the DMA channel will be stopped before free it */
	switch (channel){
		case CH_PPI: 
			disable_irq (IRQ_PPI);
			break;
		case CH_SPORT0_RX: 
		case CH_SPORT0_TX: 
			disable_irq (IRQ_SPORT0);
			break;
		case CH_SPORT1_RX: 
		case CH_SPORT1_TX: 
			disable_irq (IRQ_SPORT1);
			break;
		case CH_SPI: 
			disable_irq (IRQ_SPI);
			break;
		case CH_UART_RX: 
		case CH_UART_TX: 
			disable_irq (IRQ_UART);
			break;
		case CH_MEM_STREAM0_SRC: 
		case CH_MEM_STREAM0_DEST: 
			disable_irq (IRQ_MEM_DMA0);
			break;
		case CH_MEM_STREAM1_SRC: 
		case CH_MEM_STREAM1_DEST: 
			disable_irq (IRQ_MEM_DMA1);
			break;
		default:
			break;
	}
	
	/* Clear the DMA Variable in the Channel*/
	dma_ch[channel].L_last_descriptor = BASE_VALUE;
	dma_ch[channel].L_first_descriptor = BASE_VALUE;
	dma_ch[channel].L_wait_last_descriptor = BASE_VALUE;
	dma_ch[channel].L_wait_first_descriptor = BASE_VALUE;
	dma_ch[channel].L_next_descriptor = BASE_VALUE;

	dma_ch[channel].S_last_descriptor = BASE_VALUE;
	dma_ch[channel].S_first_descriptor = BASE_VALUE;
	dma_ch[channel].S_wait_last_descriptor = BASE_VALUE;
	dma_ch[channel].S_wait_first_descriptor = BASE_VALUE;
	dma_ch[channel].S_next_descriptor = BASE_VALUE;

	down(&dmalock);
	dma_ch[channel].dma_channel_status = DMA_CHANNEL_AVAILABLE;
	up(&dmalock);

	DMA_DBG("freedma() : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		disable_dma()
* Description:
*		Disable the specific DMA channel.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid cahnnel number 
*		DMA_SUCCESS after successfully disabling the DMA for the specified channel 
*-------------------------------------------------------------------------------*/
int disable_dma(unsigned int channel)
{
	DMA_DBG("disable_dma() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].regs->cfg &= ~DMAEN;	/* Clean the enable bit */
	SSYNC();

	/* Needs to be enabled Later */

	DMA_DBG("disable_dma() : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma()
* Description:
*		Enable the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_SUCCESS will be return for Success
*		DMA_NO_SUCH_CHANNEL will be return for invalid channel number
*-------------------------------------------------------------------------------*/
int enable_dma(unsigned int channel)
{
	DMA_DBG("enable_dma() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].flowmode = ((dma_ch[channel].regs->cfg ) & (0xf000)) >> 12 ;
	SSYNC();
	dma_ch[channel].regs->cfg |= DMAEN;	/* Set the enable bit */
	SSYNC();

	DMA_DBG("enable_dma() : BEGIN \n");

	return DMA_SUCCESS;

}



/*------------------------------------------------------------------------------
* Name:
*		dmaGetMapping()
* Description:
*		Get the pheripharal Mapping of the given channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_SUCCESS will be return for Success
*		DMA_BAD_DEVICE will be return for invalid Device 
*-------------------------------------------------------------------------------*/

/* This function is not tested */ 
DMA_RESULT	dmaGetMapping(
		DMA_DEVICE_TYPE	DeviceType,
		unsigned int	DeviceNumber,
		unsigned int	*ControllerNumber,
		unsigned int	*ChannelNumber)
{
	int 		i;
	DMA_MAPPING	*pMapping;
	DMA_channel	*pChannel;

	for (pMapping = Mapping, i = 0 ; i < (sizeof (Mapping)/sizeof(DMA_MAPPING)); i++, pMapping++)
	{
		if ((pMapping->DeviceType == DeviceType) && 
			(pMapping->DeviceNumber == DeviceNumber)) {
			for (i=0; i < MAX_BLACKFIN_DMA_CHANNEL; i++)
			{
				pChannel = &dma_ch[i];		
				if( (pChannel->ControllerNumber == pMapping->ControllerNumber) && (pChannel->PeripheralMap->b_PMAP == pMapping->PeripheralMap)) {
				
					*ControllerNumber = pChannel->ControllerNumber;
					*ChannelNumber = i;
					return DMA_SUCCESS;
				} /* End of if*/
			} /* End of For */
		} /* End of If */
		
	} /* End of for loop */
	
	return (DMA_BAD_DEVICE);

}

/* This function is not tested */ 
DMA_RESULT	dmaSetMapping(
		DMA_DEVICE_TYPE		DeviceType,
		unsigned int		DeviceNumber,
		unsigned int		ControllerNumber,
		unsigned int		ChannelNumber)
{
	int 		i;		/* Generic Counter */
	DMA_MAPPING	*pMapping;	/* Pointer to the Mapping structure */
	DMA_channel	*pChannel;	/* pointer to the channel */

	for (pMapping = Mapping, i = 0; i < (sizeof (Mapping) / (sizeof (DMA_MAPPING))); i++, pMapping++ ){
		if ((pMapping->DeviceType == DeviceType) && (pMapping->DeviceNumber == DeviceNumber)) {
			for (i=0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {
				pChannel = &dma_ch[i];		
				if( (pChannel->ControllerNumber == ControllerNumber) && ( i  == ChannelNumber)) {
				
					/* Set the mapping to the device the client wants */
					pChannel->PeripheralMap->b_PMAP = pMapping->PeripheralMap;
					return DMA_SUCCESS;

				} /* End of if-loop*/
			
			} /* End of for-loop */
		} /* End of if-loop*/
	
	} /* End of for-loop */
	return (DMA_BAD_DEVICE);
}
	

/**********************************************************************
*
*      SET/GET Functions
*
**********************************************************************/

/* The following function is not used now. 
*  But this can be used for Small descriptor Modes
*  to setup the base - Currently the Base of the starting descriptor
*  is taken as the Base for entire list. 
*/

/*------------------------------------------------------------------------------
* Name:
*		set_dma_descriptor_base()
* Description:
*		Set the base address of the DMA descriptor block 
*
* Parameters:
*		channel:		DMA channel number.
*		base:			The address of the DMA descriptors
* Return:
*		DMA_SUCCESS will be returned on success, 
*		DMA_NO_SUCH_CHANNEL will be returned for invalid channel number, 
*-------------------------------------------------------------------------------*/
int set_dma_descriptor_base(unsigned int channel, unsigned int base)
{
	DMA_DBG("set_dma_descriptor_base() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	
 	dma_ch[channel].descr_base = base;

	DMA_DBG("set_dma_descriptor_base() : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_addr()
* Description:
*		Set the Start Address register for the specific DMA channel 
* 		This function can be used for register based DMA , to setup the start address
* Parameters:
*		channel:		DMA channel number.
*		addr:			Starting address of the DMA Data to be transferred.
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the starting address for DMA  
*-------------------------------------------------------------------------------*/
DMA_RESULT set_dma_addr(unsigned int channel, unsigned long addr)
{
	DMA_DBG("set_dma_addr() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->start_addr = addr;
	SSYNC();

	DMA_DBG("set_dma_addr() : END\n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		set_dma_dir()
* Description:
*		Set the transfer direction for the specific DMA channel 
* 		This function can be used in the Register based DMA.
* Parameters:
*		channel:		DMA channel number.
*		dir:			Transfer direction
*						1: Read from memory, 
*						2: Write to memory
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the direction for DMA  
*-------------------------------------------------------------------------------*/

DMA_RESULT set_dma_dir(unsigned int channel,  char dir)
{
	DMA_DBG("set_dma_dir() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].regs->cfg |= DMAWNR;	/* Write to memory */
	SSYNC();

	DMA_DBG("set_dma_dir() : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		set_dma_type()
* Description:
*		Specify the transfer mode for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
*		type:			Transfer mode
*						0: Stop Mode
*						1: Autobuffer based DMA
*						4: Descriptor Array based DMA
*						6: Descriptor list (small Model)
*						7: Descriptor list (large Model)
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the DMA type.  
*-------------------------------------------------------------------------------*/
DMA_RESULT set_dma_type(unsigned int channel, char type)
{
	DMA_DBG("set_dma_type() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	

	dma_ch[channel].regs->cfg &= 0x0FFF;	
	switch(type)	
	{
		case FLOW_STOP:		/* STOP mode */
			break;
		case FLOW_AUTO:	/* Autobuffer based DMA */
			dma_ch[channel].regs->cfg |= (FLOW_AUTO << 12 );	
			SSYNC();
			break;
		case FLOW_ARRAY:	/* Decriptor Array based DMA mode */
			dma_ch[channel].regs->cfg |= (FLOW_ARRAY << 12);	
			SSYNC();
			break;
		case FLOW_SMALL:	/* Decriptor list (small) */
			dma_ch[channel].regs->cfg |= (FLOW_SMALL << 12);	
			SSYNC();
			break;
		case FLOW_LARGE:	/* Decripotr list (large)*/
			dma_ch[channel].regs->cfg |= (FLOW_LARGE << 12);	
			SSYNC();
			break;
		default: 	/* Invalid TYPE */
			DMA_DBG ("Invalid TYPE \n");
			break;
	}

	DMA_DBG("set_dma_type() : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		set_dma_x_count()
* Description:
*		Set the Inner Loop Count register for the specific DMA channel 
* 		This function can be used to setup the x_count for the channel
* 		mainly during the register based DMA 
* Parameters:
*		channel:		DMA channel number.
*		x_count:		The 16-bit transfer count.
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the x-count value for the DMA.  
*-------------------------------------------------------------------------------*/
DMA_RESULT set_dma_x_count(unsigned int channel, unsigned short x_count)
{
	DMA_DBG("set_dma_x_count() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].regs->x_count = x_count;
	SSYNC();	

	DMA_DBG("set_dma_x_count() : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		set_dma_y_count()
* Description:
*		Set the Outer Loop Count register for the specific DMA channel 
*		( This will be used during the 2D DMA method )
* 		This function can be used to setup the y_count for the channel
* 		mainly during the register based DMA
* Parameters:
*		channel:		DMA channel number.
*		y_count:		The 16-bit transfer count.
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the y-count value for the DMA.  
*-------------------------------------------------------------------------------*/
DMA_RESULT set_dma_y_count(unsigned int channel, unsigned short y_count)
{
	DMA_DBG("set_dma_y_count() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].regs->y_count = y_count;
	SSYNC();	

	DMA_DBG("set_dma_y_count() : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		set_dma_x_modify()
* Description:
*		Set the Inner Loop Address Increment register for the specific DMA channel 
* 		This function can be used to setup the x_modify for the channel
* 		mainly during the register based DMA 
* Parameters:
*		channel:		DMA channel number.
*		x_modify:		The 16-bit modification/increment value .
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the x-modify value for the DMA.  
*-------------------------------------------------------------------------------*/
DMA_RESULT set_dma_x_modify(unsigned int channel, unsigned short x_modify)
{
	DMA_DBG("set_dma_x_modify() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].regs->x_modify = x_modify;
	SSYNC();	

	DMA_DBG("set_dma_x_modify() : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_y_modify()
* Description:
*		Set the Inner Loop Address Increment register for the specific DMA channel 
*		(This register is used during 2D DMA transfer method only)	
* 		This function can be used to setup the y_modify for the channel
* 		mainly during the register based DMA 
* Parameters:
*		channel:		DMA channel number.
*		y_modify:		The 16-bit modification/increment value .
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the y-modify value for the DMA.  
*-------------------------------------------------------------------------------*/

DMA_RESULT set_dma_y_modify(unsigned int channel, unsigned short y_modify)
{
	DMA_DBG("set_dma_y_modify() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].regs->y_modify = y_modify;
	SSYNC();	

	DMA_DBG("set_dma_y_modify() : END \n");
	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		set_dma_transfer_size()
* Description:
*		Set the data size of transfer for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
*		size:			Data size. 
*						DATA_SIZE_8:	8-bit width
*						DATA_SIZE_16:	16-bit width
*						DATA_SIZE_32:	32-bit width
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number 
*		DMA_SUCCESS after successfully set the y-modify value for the DMA.  
*-------------------------------------------------------------------------------*/
DMA_RESULT set_dma_transfer_size(unsigned int channel, char size)
{
	unsigned short size_word;

	DMA_DBG("set_dma_tranfer() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;
	

	size_word = 0;

	dma_ch[channel].regs->cfg &= 0xFFF3; /* Set the 2 & 3 bits as 0 for Initialization */
	
	switch (size)
	{

		case DATA_SIZE_8:
			break;
		case DATA_SIZE_16:
			dma_ch[channel].regs->cfg |= DMAWDSIZE16;
			break;
		case DATA_SIZE_32:
			dma_ch[channel].regs->cfg |= DMAWDSIZE32;
			break;
		default:
			DMA_DBG ("Invalid tranfer_size \n");
			break;
			 
	}
	SSYNC();

	DMA_DBG("set_dma_tranfer() : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		get_dma_transfer_size()
* Description:
*		Get the current data size of the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number	
*		For Success : The data_size of the DMA transfer , set for the specified channel 	
*-------------------------------------------------------------------------------*/
int get_dma_transfer_size(unsigned int channel)
{
	unsigned short  size_word;

	DMA_DBG("get_dma_tranfer_size() : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	size_word = dma_ch[channel].regs->cfg;
	size_word &= 0x000C; 	/* Bits 2 & 3 represents the WDSIZE  */ 
	size_word >>=2;	   

	DMA_DBG("get_dma_tranfer_size() : END \n");

	return size_word;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_stopmode()
* Description:
*		Enable stop mode for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_RESULT 
*-------------------------------------------------------------------------------*/
DMA_RESULT enable_dma_stopmode(unsigned int channel)
{
	return set_dma_type(channel, DMA_STOP);
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_autobuffer()
* Description:
*		Enable Autobuffer mode for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_RESULT 
*-------------------------------------------------------------------------------*/
DMA_RESULT enable_dma_autobuffer(unsigned int channel)
{
	return 	set_dma_type(channel, DMA_AUTO);
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_descr_array()
* Description:
*		Enable descriptor array mode for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_RESULT 
*-------------------------------------------------------------------------------*/
DMA_RESULT enable_dma_descr_array(unsigned int channel)
{
	return 	set_dma_type(channel, DMA_ARRAY);
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_descr_small()
* Description:
*		Enable descriptor list (small) mode for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_RESULT
*-------------------------------------------------------------------------------*/
DMA_RESULT enable_dma_descr_small(unsigned int channel)
{
	return	set_dma_type(channel, DMA_SMALL);
}



/*------------------------------------------------------------------------------
* Name:
*		enable_dma_descr_large()
* Description:
*		Enable descriptor list (large) mode for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_RESULT
*-------------------------------------------------------------------------------*/
DMA_RESULT enable_dma_descr_large(unsigned int channel)
{
	return set_dma_type(channel, DMA_LARGE);
}


/*------------------------------------------------------------------------------
* Name:
*		get_dma_curr_x_count()
* Description:
*		Get the content of curr_x_count register for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel number
*		The current value of curr_x_count register
*-------------------------------------------------------------------------------*/
int get_dma_curr_x_count(unsigned int channel)
{

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	return dma_ch[channel].regs->curr_x_count;
}

/*------------------------------------------------------------------------------
* Name:
*		get_dma_curr_y_count()
* Description:
*		Get the content of curr_y_count register for the specific DMA channel 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		The current value of curr_y_count register
*-------------------------------------------------------------------------------*/
int get_dma_curr_y_count(unsigned int channel)
{
	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	return dma_ch[channel].regs->curr_y_count;
}


/*------------------------------------------------------------------------------
* Name:
*		clear_dma_buffer()
* Description:
*		Set the Buffer Clear bit in the Configuration register of specific 
*		DMA channel. This will stop the descriptor based DMA operation.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/
DMA_RESULT clear_dma_buffer(unsigned int channel)
{

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->cfg |= DMARESTART;
	SSYNC();

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		disable_dma_buffer_clear()
* Description:
*		Clear the Buffer Clear bit in the Configuration register of specific 
*		DMA channel. 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/
DMA_RESULT  disable_dma_buffer_clear(unsigned int channel)
{

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->cfg &= ~DMARESTART;
	SSYNC();

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_data_row_intr()
* Description:
*		Enable Data Interrupt Timing Select ( used in 2D DMA )  
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/

DMA_RESULT enable_dma_data_row_intr(unsigned int channel)
{

	/* Check whether this function is called from 2D-DMA only */
	DMA_DBG("enable_dma_data_row_intr () : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->cfg |= DMASEL; /* Interrupt After completing each row */

	SSYNC();	

	DMA_DBG("enable_dma_data_row_intr () : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_data_intr()
* Description:
*		Enable Interrupt On Completion (IOC) 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/

DMA_RESULT enable_dma_data_intr(unsigned int channel)
{
	DMA_DBG("enable_dma_data_intr () : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	/* enable Data Interrupt  */
	dma_ch[channel].regs->cfg |= DMADI; 
	SSYNC();	

	DMA_DBG("enable_dma_data_intr () : BEGIN \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_err_intr()
* Description:
*		Enable Interrupt On Error(IOE) for the specific DMA channel.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/

DMA_RESULT enable_dma_err_intr(unsigned int channel)
{
	DMA_DBG("enable_dma_err_intr () : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	/* enable Error Interrupt  */
	dma_ch[channel].regs->irq_status |= DMAERR;
	SSYNC();	

	DMA_DBG("enable_dma_err_intr () : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_intr()
* Description:
*		This function enables all interrupts ( error, DI_EN and DMASEL ) 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_SUCCESS for successfully enabling the interrupts	
*-------------------------------------------------------------------------------*/
DMA_RESULT enable_dma_intr(unsigned int channel)
{
	DMA_DBG("enable_dma_intr () : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	/* enable Data Interrupt */
	enable_dma_data_intr(channel);

	/* enable Data Interrupt */
	enable_dma_data_row_intr(channel);

	/* enable Error Interrupt */
	enable_dma_err_intr(channel);
		
	SSYNC();	

	DMA_DBG("enable_dma_intr () : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		disable_dma_data_row_intr()
* Description:
*		Disable Data Interrupt Timing Select (used in 2D DMA ) 
* Parameters:
*		channel:		DMA channel number.
*	
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/

DMA_RESULT disable_dma_data_row_intr(unsigned int channel)
{
	DMA_DBG("disable_dma_data_row_intr () : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->cfg &= ~DMASEL;
	SSYNC();

	DMA_DBG("disable_dma_data_row_intr () : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		disable_dma_data_intr()
* Description:
*		Disable Data Data Interrupt 
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/
DMA_RESULT  disable_dma_data_intr(unsigned int channel)
{
	unsigned short intr_word;

	DMA_DBG("disable_dma_data_intr () : BEGIN \n");

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	intr_word = 0;

	dma_ch[channel].regs->cfg &= ~DMADI;		

	SSYNC();

	DMA_DBG("disable_dma_data_intr () : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		disable_dma_err_intr()
* Description:
*		Disable Interrupt On Error(IOE) for the specific DMA channel.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/

DMA_RESULT disable_dma_err_intr(unsigned int channel)
{
	DMA_DBG("disable_dma_err_intr () : BEGIN \n");
	DMA_DBG("channel Number %d \n", channel);


	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->irq_status &= ~DMAERR;
	SSYNC();

	DMA_DBG("disable_dma_err_intr () : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		disable_dma_intr()
* Description:
*		Disable Data Interrupt and 
*		Disable Data Interrupt Timing Select (used in 2D DMA ) and
*		Interrupt On Error(IOE) for the specific DMA channel.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_SUCCESS : for successful completion 
*-------------------------------------------------------------------------------*/
DMA_RESULT disable_dma_intr(unsigned int channel, unsigned char intr)
{
	
	DMA_DBG("disable_dma_intr () : BEGIN \n");

	disable_dma_data_row_intr(channel);
	disable_dma_data_intr(channel);
	disable_dma_err_intr(channel);

	DMA_DBG("disable_dma_intr () : END \n");

	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		get_dma_irq_stat()
* Description:
*		Get the content of IRQ Status register of specific DMA channel
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		The content of IRQ Status register for successful execution. 
*-------------------------------------------------------------------------------*/
unsigned short get_dma_irq_stat(unsigned int channel)
{

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	return dma_ch[channel].regs->irq_status;
}

/*------------------------------------------------------------------------------
* Name:
*		clr_dma_irq_stat()
* Description:
*		Clear the content of IRQ Status register of specific DMA channel
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		The content of IRQ Status register for successful execution. 
*-------------------------------------------------------------------------------*/
int clr_dma_irq_stat(unsigned int channel)
{

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->irq_status = BASE_VALUE;
	SSYNC();
	return DMA_SUCCESS;
}


/*******************************************************
*
*    DESCRIPTOR RELATED FUNCTIONS
*
*******************************************************/


/* NOTE: The descriptor must be aligned to 16-bit boundary */
#if 0
static dmasg_t DescSrc __attribute__ ((aligned (2)));
static dmasg_t DescDest __attribute__ ((aligned (2)));
static dmasg_t DescDummy __attribute__ ((aligned (2)));
#endif


#ifdef CONFIG_BLKFIN_DCACHE
#define SPECIAL_DESC
#endif

#ifdef SPECIAL_DESC
/* Is this required ???? BFin */
extern unsigned long l1sram_alloc(unsigned long size);
extern void bf53x_cache_init(void);

#if 0
static dmasg_t * pDescSrc = NULL;
static dmasg_t * pDescDest = NULL;
static dmasg_t * pDescDummy = NULL;
#endif
#endif /* SPECIAL_DESC */


/*------------------------------------------------------------------------------
* Name:
*		create_descriptor()
* Description:
*		Creates a new descriptor with the given type (Array,small,large)
*
* Parameters:
*		flowtype:	The type of the DMA Descriptor to be created
* Return:
*		returns the descriptor for success.
*		returns NULL for failure.
*-------------------------------------------------------------------------------*/

void* create_descriptor(int flowtype)
{
	void 		*pDescriptor;

	DMA_DBG("create_desriptor() : BEGIN \n");

	switch (flowtype){
		/* For Array Type DMA, the dynamic allocation is not required.
		   So the respective code is commented */
		/*
		case FLOW_ARRAY:
			descriptor = (dmasgarray_t *)kmalloc(sizeof(dmasgarray_t), GFP_KERNEL);
			break;
		*/
		case FLOW_SMALL:
			pDescriptor = (dmasgsmall_t *)kmalloc(sizeof(dmasgsmall_t), GFP_KERNEL);	
			break;
		case FLOW_LARGE:
			pDescriptor = (dmasglarge_t *)kmalloc(sizeof(dmasglarge_t), GFP_KERNEL);	
			break;
		default:
			return NULL;
	}

	DMA_DBG("create_desriptor() : END \n");

	return pDescriptor;
	
}


/* This function is not used currently */

/*------------------------------------------------------------------------------
* Name:
*		dma_setup_desc()
* Description:
*		Set the values in the specified descriptor
* Parameters:
*		desc:		Descriptor to be set .
*		next:		Next Descriptor address to be set in the descriptor.
*		start_addr:	starting address of the DMA to be set in the descriptor.
*		cfg:		configuaration register value to be set in the descriptor.
*		x_count:	x_count value to be set in the descriptor  .
*		x_modify:	x_modify value to be set int the descriptor.
*		y_count:	y_count value to be set in the descriptor to be set .
*		y_modify:	y_modify value to be set in the descriptor to be set .
* Return:
*		none
*-------------------------------------------------------------------------------*/

void dma_setup_desc(unsigned long desc, 
	            unsigned long next, 
		    unsigned long start_addr, 
		    unsigned short cfg, 
		    /* DMA_CONFIG_REG cfg, */
		    unsigned short x_count,
		    unsigned short x_modify,
	            unsigned short y_count,
	            unsigned short y_modify)
{
	DMA_DBG("dma_setup_desc () : BEGIN \n");

	/* Set the next addr  */
	/*
	((dmasg_t *) desc)->next_desc_ptr_lsb = (unsigned short) ((next) & LOW_WORD);
	((dmasg_t *) desc)->next_desc_ptr_msb = (unsigned short) (((next) >> 16) & LOW_WORD);
	*/

	/* Set the start  addr  */
	((dmasg_t *) desc)->start_addr = start_addr;

	/* Set the Configuaration Register */
	((dmasg_t *) desc)->cfg = cfg;

	/* Set the x-count */
	((dmasg_t *) desc)->x_count = x_count;

	/* Set the x-modify */
	((dmasg_t *) desc)->x_modify = x_modify;

	/* Set the y-count */
	((dmasg_t *) desc)->y_count = y_count;
	
	/* Set the y-modify */
	((dmasg_t *) desc)->y_modify = y_modify;

	DMA_DBG("dma_setup_desc () : END \n");
}

/*------------------------------------------------------------------------------
* Name:
*		check_desc_size()
* Description:
*		Checks the size of the descriptor set in the config register 
*		based on the flow type
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel number . 
*		DMA_BAD_DESCRIPTOR : for Bad descriptor Size Value	
*		DMA_SUCCESS : for Valid descriptor Size	
*-------------------------------------------------------------------------------*/
/* This function is not used currently */
DMA_RESULT check_desc_size(unsigned int channel)
{
	unsigned short desc_size,flow_type = 0x0000;
	unsigned short cfg_word; 

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;


	cfg_word = dma_ch[channel].regs->cfg;
	flow_type = cfg_word & 0xF000;
	flow_type >>= 12;

	desc_size = cfg_word & 0x0F00;
	desc_size >>= 8;

	switch (flow_type)
	{
		case DMA_STOP:
		case DMA_AUTO:
			if (desc_size)
				return DMA_BAD_DESCRIPTOR;	
			break;
		case DMA_ARRAY:
			if (desc_size > NDSIZE_ARRAY )
				return DMA_BAD_DESCRIPTOR;	
			break;
		case DMA_SMALL:
			if (desc_size > NDSIZE_SMALL )
				return DMA_BAD_DESCRIPTOR;	
			break;
		case DMA_LARGE:
			if (desc_size > NDSIZE_LARGE )
				return DMA_BAD_DESCRIPTOR;	
			break;
	} 
	return DMA_SUCCESS;

}


/*------------------------------------------------------------------------------
* Name:
*		set_desc_start_addr()
* Description:
*		Set the starting address of  the DMA Transfer in the given descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		startaddr:	starting address of the DMA,  to be set .
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : for successfully setting the DMA Start address
*-------------------------------------------------------------------------------*/

DMA_RESULT set_desc_startaddr(void *pDescriptor, unsigned long startaddr, int flowtype)
{
	if (pDescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;	

	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->start_addr = startaddr;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->start_addr_lo = startaddr & LOW_WORD;
			((dmasgsmall_t *)pDescriptor)->start_addr_hi = (startaddr & HIGH_WORD ) >> 16 ;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->start_addr = startaddr;
			break;
		default:
			break;
	}
	
	return DMA_SUCCESS;
	
}

/*------------------------------------------------------------------------------
* Name:
*		set_desc_x_count()
* Description:
*		Set the x_count value for the DMA Transfer in the given descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		x_count:	x_count value to be set.
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : for successfully setting the x_count
*-------------------------------------------------------------------------------*/

DMA_RESULT set_desc_xcount(void *pDescriptor, unsigned short x_count, int flowtype)
{

	if (pDescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;	

	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->x_count = x_count;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->x_count = x_count;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->x_count = x_count;
			break;
		default:
			break;
	}
	
	return DMA_SUCCESS;
	
}

/*------------------------------------------------------------------------------
* Name:
*		set_desc_x_modify()
* Description:
*		Set the x_modify value for the DMA Transfer in the given descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		x_modify:	x_modify value to be set.
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : for successfully setting the x_count
*------------------------------------------------------------------------------*/

DMA_RESULT set_desc_xmodify(void *pDescriptor, unsigned short x_modify, int flowtype)
{
	if (pDescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;	

	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->x_modify = x_modify;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->x_modify = x_modify;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->x_modify = x_modify;
			break;
		default:
			break;
	}
	
	return DMA_SUCCESS;
	
}
/*------------------------------------------------------------------------------
* Name:
*		set_desc_y_count()
* Description:
*		Set the y_count value for the DMA Transfer in the given descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		y_count:	y_count value to be set.
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : for successfully setting the y_count
*-------------------------------------------------------------------------------*/

DMA_RESULT set_desc_ycount(void *pDescriptor, unsigned short y_count, int flowtype)
{
	if (pDescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;	

	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->y_count = y_count;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->y_count = y_count;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->y_count = y_count;
			break;
		default:
			break;
	}
	
	return DMA_SUCCESS;
	
}

/*------------------------------------------------------------------------------
* Name:
*		set_desc_y_modify()
* Description:
*		Set the y_modify value for the DMA Transfer in the given descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		y_modify:	y_modify value to be set.
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : for successfully setting the y_modify
*-------------------------------------------------------------------------------*/
DMA_RESULT set_desc_ymodify(void *pDescriptor, unsigned short y_modify, int flowtype)
{
	if (pDescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;	

	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->y_modify = y_modify;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->y_modify = y_modify;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->y_modify = y_modify;
			break;
		default:
			break;
	}
	
	return DMA_SUCCESS;
	
}

/*------------------------------------------------------------------------------
* Name:
*		add_descriptor()
* Description:
*		Adds a new descriptor at the end of the existing descriptor list
*		of the given channel.
*		The last descriptor in the list will be in the stop mode
* Parameters:
*		pNewDescriptor:	Pointer to the new descriptor to be addded.
*		channel_number:	Channel number.
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return: 
*		DMA_NO_SUCH_CHANNEL: If the  channel number is invalid
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : For successful execution
*-------------------------------------------------------------------------------*/

DMA_RESULT add_descriptor(void *pNewdescriptor, int  channel_number, int flowtype)
{
	DMA_channel *channel = &dma_ch[channel_number];		
	void *last_descriptor = channel->L_last_descriptor;

	DMA_DBG (" add_descriptor(): BEGIN \n");

	if (channel_number >= MAX_BLACKFIN_DMA_CHANNEL)  
		return DMA_NO_SUCH_CHANNEL;

	if (pNewdescriptor == NULL)  
		return DMA_BAD_DESCRIPTOR;

	if (( dma_ch[channel_number].regs->cfg ) & (DMAEN)) {
		down(&dmalock);
		add_to_wait_descriptor(pNewdescriptor, channel_number, flowtype);	
		up(&dmalock);
	}


	if (flowtype == FLOW_LARGE)
		(dmasglarge_t *)last_descriptor = channel->L_last_descriptor;
	else
		(dmasgsmall_t *)last_descriptor = channel->S_last_descriptor;


	if (last_descriptor){ /* Channel has already a list of descriptors  */ 

		if (flowtype == FLOW_LARGE){

			/* set the next descriptor address of the new descriptor */
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr = 
					((dmasglarge_t *)last_descriptor)->next_desc_addr;

			/* update the  next descriptor address of the last descriptor in the existing list */
			((dmasglarge_t *)last_descriptor)->next_desc_addr = (unsigned long)pNewdescriptor;

			((dmasglarge_t *)last_descriptor)->cfg |= 0x7900  ; 
		}
		else
		{
			/* set the lower 4 bytes of the next descriptor address of the new descriptor */
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo = 
					((dmasgsmall_t *)last_descriptor)->next_desc_addr_lo;

			/* update the lower 4 bytes of the  next descriptor address of the last descriptor 
				in the existing list */
			((dmasgsmall_t *)last_descriptor)->next_desc_addr_lo = 
					(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);

			/* In non-loopback mode, the last descriptor used to have STOP flow mode. 
			   This is to be changed */
			((dmasgsmall_t *)last_descriptor)->cfg |= 0x6800  ; 
		}
		
 	} /* end of if (last_descriptor) */
	else { /* Channel does not have any existing list of descriptors */
		if (flowtype == DMA_LARGE){
			/*  */
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr = (unsigned long)pNewdescriptor;
			channel->L_first_descriptor = (dmasglarge_t *)pNewdescriptor;
		}
		else{
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo = 
					(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
			
			channel->S_first_descriptor = (dmasgsmall_t *)pNewdescriptor; 
		}
	 }

	if (flowtype == DMA_LARGE){
		channel->L_last_descriptor = (dmasglarge_t *)pNewdescriptor;
		((dmasgsmall_t *)pNewdescriptor)->cfg &= 0x0fff; 
	}
	else {
		channel->S_last_descriptor = (dmasgsmall_t *)pNewdescriptor;
		((dmasgsmall_t *)pNewdescriptor)->cfg &= 0x0fff; 
	}

	DMA_DBG (" add_descriptor(): END \n");
	return DMA_SUCCESS;
}


/*------------------------------------------------------------------------------
* Name:
*		add_to_wait_descriptor()
* Description:
*		Adds a new descriptor at the end of the existing Waitingdescriptor list
*		of the given channel.
* Parameters:
*		pNewDescriptor:	Pointer to the new descriptor to be addded.
*		channel_number:	Channel number.
*		flowtype:	The flow type of the descriptor 
*				The flow type can be  Array or Small or Large.
* Return: 
*		DMA_NO_SUCH_CHANNEL: If the  channel number is invalid
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL	
*		DMA_SUCCESS : For successful execution
*-------------------------------------------------------------------------------*/

DMA_RESULT add_to_wait_descriptor(void *pNewdescriptor, int  channel_number, int flowtype)
{
	DMA_channel *channel = &dma_ch[channel_number];		
	void* last_descriptor;
	
	DMA_DBG (" add_to_wait_descriptor : BEGIN \n");

	if (flowtype == FLOW_SMALL){
		last_descriptor = channel->L_wait_last_descriptor;
	}
	else{
		last_descriptor = channel->S_wait_last_descriptor;
	}

	if (flowtype == DMA_SMALL){
		unsigned short base = (unsigned short)(((unsigned long)pNewdescriptor & HIGH_WORD ) >> 16 );

		if ((channel->descr_base) && (base  != channel->descr_base))
		{
			DMA_DBG ("Descriptor Out of Range \n");
			return DMA_BAD_DESCRIPTOR;
		}
	}


	if (last_descriptor){
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr = 
					channel->L_wait_last_descriptor->next_desc_addr;

			((dmasglarge_t *)last_descriptor)->next_desc_addr = (unsigned long)pNewdescriptor;
		}
		else{ /* SMALL Descriptor Case */
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo = 
					channel->S_wait_last_descriptor->next_desc_addr_lo;
			((dmasgsmall_t *)(last_descriptor))->next_desc_addr_lo = 
					(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
		}
 	}
	else {
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr = (unsigned long)pNewdescriptor;
			channel->L_wait_first_descriptor = (dmasglarge_t *)pNewdescriptor;
		}
		else{
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo = 
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);

			channel->S_wait_first_descriptor = (dmasgsmall_t *)pNewdescriptor; 
		}
	}

	if (flowtype == DMA_LARGE)
		channel->L_wait_last_descriptor = (dmasglarge_t *)pNewdescriptor;
	else
		channel->S_wait_last_descriptor = (dmasgsmall_t *)pNewdescriptor;

	DMA_DBG (" add_to_wait_descriptor : END \n");
	return DMA_SUCCESS;
}




/***********************************************************
*
*   INTERRUPT RELATED FUNCTIONS
*
***********************************************************/

/*------------------------------------------------------------------------------
* Name:
*		testcallback()
* Description:
*		Callback function that will be called from ISR
*		This is a sample Test Program , for testing purpose
*		
* Parameters:
*		event:		The DMA_EVENT that caused to generate interrupt.
*		startAddress:	Starting address of the DMA in the descriptor 
* Return: 
*		None
*-------------------------------------------------------------------------------*/

/* Current Implementation of callback function is for testing purpose  */
void testcallback (DMA_EVENT event,  void *startAddress)
{

	DMA_DBG ("Callback Function is called \n");

	switch (event){
		case DMA_ERROR_INTERRUPT:
			DMA_DBG ("DMA Error Interrupt  \n");
			break;
		case DMA_DESCRIPTOR_PROCESSED:
			DMA_DBG ("DMA Descriptor Event  \n");
			break;
		case DMA_INNER_LOOP_PROCESSED:
			DMA_DBG ("DMA Inner Loop processed Event  \n");
			break;
		case DMA_OUTER_LOOP_PROCESSED:
			DMA_DBG ("DMA Outer Loop processed Event  \n");
			break;
		case DMA_UNKNOWN_EVENT:
		default:
			DMA_DBG ("DMA Unknown Event  \n");
			break;
			 

	}
	DMA_DBG ("\n Completed the Callback function processing \n");
	 
}

/*------------------------------------------------------------------------------
* Name:
*		dma_interrupt()
* Description:
*		Interrupt Service  Routine (ISR).
*		This function checks the Interrupt Type and Calls the Callback function
*		After the execution of Callback function, the next descriptor in the
*		descriptor list will be used to start the DMA		
* Parameters:
*		irq:		irq number of the Interrupt
*				(refer bf533_irq.h for the mapping between irq numbers and INTERRUPTS )	
*		dev_id:		Device id of the Device that generated the interrupt 
*		pt_regs:	Device id of the Device that generated the interrupt 
* Return: 
*		None
*-------------------------------------------------------------------------------*/

void dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=0;
	DMA_EVENT	event;
	DMA_channel 	*channel;		
	
	for (i=0; i<MAX_BLACKFIN_DMA_CHANNEL; i++)
	{
		channel = &dma_ch[i];		
		/* check the DMA Channels that caused the interrupt */
		if (dma_ch[i].regs->irq_status & DMA_DONE) /* Check for the IRQ_STATUS is DMA_DONE or not */
		{
			if (dma_ch[i].flowmode == DMA_AUTO)
			{
			/*	disable_dma(i); */ /* This has to be crosschecked once again - TODO*/
				DMA_DBG ("Auto Mode Interrupt is processing \n");

				/* This part of the is as per the reference code from ADI - to be verified Again -TODO */ 
				if (((dma_ch[i].regs->cfg ) & DMASEL) && 
					((dma_ch[i].regs->curr_y_count != 1) ))
				{
					event = DMA_INNER_LOOP_PROCESSED;
				}else {
					event = DMA_OUTER_LOOP_PROCESSED;
				}
				if (dma_ch[i].callback)
					(dma_ch[i].callback)(event, NULL);
		/*		enable_dma(i); */ /* This has to be crosschecked once again - TODO*/
			}
			else {

			/* Proposed Implementation  with DI_EN on any of the descriptor in the list 
			   in addition to the last descriptor in the list. 
				- Send the intimation to the Callback function
				- Get the next descriptor in the list 
				- If the descriptor is the last descriptor in the list, then 
  					- If the Loop back method was set, then start DMA once again. 
						( Using the next_desc_ptr and next descriptor config )
						(Is it not automatic ??? Check once again )
					- If there is a waiting descriptor list 
						start the DMA using the waiting descriptor as active descriptor list.
				- If the descriptor is not last descriptor, then 
						load the values to restart the DMA 
						( Not required always, if the values will be stored automatically)
			*/

			/* 1) 	We are not getting the interrupts at the end of each descriptor (in 1-D DMA ) 
			    	eventhough the DI_EN is set at each descriptor,
			      	- to solve this, we can go for 2D DMA or 
			      	- use the interrupt that was generated - in this case at the end of the descriptor list 

			   2) 	Here we are not taking care of Loopback method , due to a problem while executing the 
			   	Loop back Mode - This has to be taken care or to be informed to ADI 
			*/

			/* 	With current execution of interrupts - i.e interrupts coming at the end of the 	
				descriptor list the following implementation was done. This will be finalized after the 
				review or confirmation from ADI. - TODO
			*/ 	


				DMA_DBG ("Not In the AutoBuffer Mode  \n");
				disable_dma(i);
				
				if (((dma_ch[i].regs->cfg ) & DMASEL) && 
					((dma_ch[i].regs->curr_y_count != 1) ))
				{
					DMA_DBG("Descrptor, Inner Loop Processing \n ");
					event = DMA_INNER_LOOP_PROCESSED;
				}else {
					DMA_DBG("Descrptor, Outer Loop Processing , curr_y_count is %d \n", (dma_ch[i].regs->curr_y_count));
					event = DMA_OUTER_LOOP_PROCESSED;
				}


				if (dma_ch[i].callback)
					(dma_ch[i].callback)(DMA_DESCRIPTOR_PROCESSED, NULL);

				if (dma_ch[i].regs->next_desc_ptr == (unsigned int)(channel->L_first_descriptor)) { /*All the descriptors are processed */

					/* execute the waiting descriptor list */
					if (channel->L_wait_first_descriptor)
					{
						DMA_DBG ("Wait descriptor processing \n ");
						channel->L_first_descriptor = channel->L_wait_first_descriptor;
						channel->L_last_descriptor = channel->L_wait_last_descriptor;
						SSYNC();
						channel->regs->next_desc_ptr = (unsigned long)(channel->L_first_descriptor);
						SSYNC();

						/* If we have a single waiting descriptor then it is like stop mode 
						- Because with Loop back mode we have a problem */
						if (channel->L_last_descriptor == channel->L_wait_first_descriptor)
						{
				
							channel->regs->start_addr = channel->L_first_descriptor->start_addr;
							channel->regs->x_count = channel->L_first_descriptor->x_count;
							channel->regs->x_modify = channel->L_first_descriptor->x_modify;
							channel->regs->y_count = channel->L_first_descriptor->y_modify;
							channel->regs->y_modify = channel->L_first_descriptor->y_modify;
						}
							channel->L_wait_first_descriptor = NULL;
							channel->L_wait_last_descriptor = NULL;
					}
				}
			} /* End of the Else loop - for Not Auto Buffer */
		} /* End of Irq_status register Check */
	} /* End of the For Loop */
}

/*------------------------------------------------------------------------------
* Name:
*		blkfin_inv_cache_all()
* Description:
*		This function will invalidate the Cache 			
* Return: 
*		None
*-------------------------------------------------------------------------------*/

void blkfin_inv_cache_all()
{
#ifdef CONFIG_BLKFIN_CACHE
	/* unsigned long flags; */
	/* save_flags(flags); */

	/* cli(); */
	
	/* spin_lock_irq(&cache_lock); */

	/*bf53x_cache_init();*/

	/* spin_unlock_irq(&cache_lock); */
	/* restore_flags(flags); */
#endif
}

void add_descriptor_descr(void *newdescriptor, void *previousdescriptor, int flowtype)
{
	dmasglarge_t* newdescr = (dmasglarge_t *)newdescriptor;
	dmasglarge_t* prevdescr = (dmasglarge_t *)previousdescriptor;

	DMA_DBG (" add_descriptor_descr \n");
	if (prevdescr) {
		newdescr->next_desc_addr = (unsigned long)prevdescr;
		prevdescr->next_desc_addr =  (unsigned long)newdescr;
	}
	else{
		newdescr->next_desc_addr = (unsigned long)newdescr;
	}
}



