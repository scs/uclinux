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

/*
*  arch/bfinnommu/kernel/dma.c
*  This file contains the DMA Implementation for BF533
*
*  Copyright (C) 2004 LG Soft India
*
*/

#include <asm/dma.h>
int interruptCount;

/**************************************************************************
 * Global Variables 
***************************************************************************/

static DMA_channel 	dma_ch[MAX_BLACKFIN_DMA_CHANNEL];

static DMA_register* 	base_addr[MAX_BLACKFIN_DMA_CHANNEL] =
{
	(DMA_register *) DMA0_NEXT_DESC_PTR,
	(DMA_register *) DMA1_NEXT_DESC_PTR,
	(DMA_register *) DMA2_NEXT_DESC_PTR,
	(DMA_register *) DMA3_NEXT_DESC_PTR,
	(DMA_register *) DMA4_NEXT_DESC_PTR,
	(DMA_register *) DMA5_NEXT_DESC_PTR,
	(DMA_register *) DMA6_NEXT_DESC_PTR,
	(DMA_register *) DMA7_NEXT_DESC_PTR,
	(DMA_register *) MDMA_D0_NEXT_DESC_PTR,
	(DMA_register *) MDMA_S0_NEXT_DESC_PTR,
	(DMA_register *) MDMA_D1_NEXT_DESC_PTR,
	(DMA_register *) MDMA_S1_NEXT_DESC_PTR,
};

static DMA_MAPPING Mapping[] = {
	{ DMA_DEVICE_PPI,	0,	0,	PMAP_PPI	},
	{ DMA_DEVICE_SPORT_RX,	0,	0,	PMAP_SPORT0_RX	},
	{ DMA_DEVICE_SPORT_TX,	0,	0,	PMAP_SPORT0_TX	},
	{ DMA_DEVICE_SPORT_RX,	1,	0,	PMAP_SPORT1_RX	},
	{ DMA_DEVICE_SPORT_TX,	1,	0,	PMAP_SPORT1_TX	},
	{ DMA_DEVICE_SPI,	0,	0,	PMAP_SPI	},
	{ DMA_DEVICE_UART_RX,	0,	0,	PMAP_UART_RX	},
	{ DMA_DEVICE_UART_TX,	0,	0,	PMAP_UART_TX	},
};


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
*-----------------------------------------------------------------------------*/
int __init blackfin_dma_init(void)
{
	int 	i;
	
	printk("Blackfin DMA Controller for BF533\n");

	for (i = 0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {

		dma_ch[i].dma_channel_status = DMA_CHANNEL_FREE;
		dma_ch[i].regs = base_addr[i];
		init_MUTEX(&(dma_ch[i].dmalock));
	}
	interruptCount = 0;
	
	return 0;
}
module_init(blackfin_dma_init);

/*------------------------------------------------------------------------------
* Name:
*		InitializeChannel()
* Description:
*		This function is used to Initialize the channel with the given
*		values
* Parameters:
*		channel_number:	Channel Number of the Channel to be initialized
*		cfg:		Configuaration value to be set
*		start_addr:	start address of the DMA Transfer, to be set
*		x_count:	x_count value to be set for the DMA transfer
*		x_modify:	x_modify value to be set for the DMA transfer
*		y_count:	y_count value to be set for the DMA transfer
*		y_modify:	y_modify value to be set for the DMA transfer
* Return:
*		DMA_NO_SUCH_CHANNEL: If the channel number is > 11
*		DMA_SUCCESS: For successful Initialization
*-----------------------------------------------------------------------------*/
static DMA_RESULT InitializeChannel (unsigned int channel_number,
			unsigned short cfg, unsigned short start_addr,
			unsigned short x_count, unsigned short x_modify,
			unsigned short y_count, unsigned short y_modify)
{

	assert (channel_number < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel_number >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel_number].regs->cfg = cfg;
	dma_ch[channel_number].regs->start_addr = start_addr;
	dma_ch[channel_number].regs->x_count = x_count;
	dma_ch[channel_number].regs->x_modify = x_modify;
	dma_ch[channel_number].regs->y_count = y_count;
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
*		channel:	DMA channel number
*		device_id:	pointer to the device ID for the DMA channel.
*		dma_interrupt:	Interrupt service routine.
*		callback:	Callback function that can be called from ISR.
* Return:
*		DMA_NO_SUCH_CHANNEL will be returned for invalid channel number
*		DMA_CHANNEL_IN_USE will be returned, if the channel is already
*		in use.
*		DMA_FAIL will be returned if the device_id is null.
*		The return value of the request_irq() for the failure of the
*		request_irq()
*		DMA_SUCCESS will be returned for success ?
*-----------------------------------------------------------------------------*/
DMA_RESULT request_dma(unsigned int channel,const char* device_id,
		      dma_callback_t callback)
{
	return new_request_dma(channel, device_id, callback, DMA_INTERRUPT_TYPE);
}
DMA_RESULT new_request_dma(unsigned int channel,const char* device_id,
		      dma_callback_t callback, DMA_TYPE dma_type)
{

	int		ret_irq = 0;
	DMA_RESULT	retValue;
 
	DMA_DBG("request_dma() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(device_id !=  NULL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (device_id == NULL)
		return DMA_FAIL;

	down(&(dma_ch[channel].dmalock));

	if ((dma_ch[channel].dma_channel_status == DMA_CHANNEL_REQUESTED )
		||(dma_ch[channel].dma_channel_status == DMA_CHANNEL_ENABLED)){

		up(&(dma_ch[channel].dmalock));
		DMA_DBG("DMA CHANNEL IN USE  \n");
		return DMA_CHANNEL_IN_USE;
	}
	else{
	
		dma_ch[channel].dma_channel_status = DMA_CHANNEL_REQUESTED ;
		DMA_DBG("DMA CHANNEL IS ALLOCATED  \n");
	}
	up(&(dma_ch[channel].dmalock));

	dma_ch[channel].device_id = device_id;
 	dma_ch[channel].descr_base = BASE_VALUE;
	dma_ch[channel].LoopbackFlag = 0;

	/* This is to be enabled by putting a restriction -
	   you have to request DMA , before doing any operations on
	   descriptor/channel
	*/

	retValue = InitializeChannel(channel, 0x00, 0x00, 0x00, 0x02, 
					0x01, 0x02);
	if (retValue != DMA_SUCCESS)
		return retValue;

	DMA_DBG("InitializeChannel : Done  \n");

	if (dma_type == DMA_INTERRUPT_TYPE)
	{
		dma_ch[channel].dma_type = DMA_INTERRUPT_TYPE;
 		dma_ch[channel].callback = callback;
		switch (channel){
		case CH_PPI:
			ret_irq = request_irq(IRQ_PPI, (void *)ppi_dma_interrupt,
					SA_INTERRUPT, "ppi-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_SPORT0_RX:
			ret_irq = request_irq(IRQ_SPORT0_RX, (void *)sport0_rx_dma_interrupt,
					SA_INTERRUPT, "sport0_rx-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_SPORT0_TX:
			ret_irq = request_irq(IRQ_SPORT0_TX, (void *)sport0_tx_dma_interrupt,
					SA_INTERRUPT, "sport0_tx-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;

		case CH_SPORT1_RX:
			ret_irq = request_irq(IRQ_SPORT1_RX, (void *)sport1_rx_dma_interrupt,
					SA_INTERRUPT, "sport1_rx-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_SPORT1_TX:
			ret_irq = request_irq(IRQ_SPORT1_TX, (void *)sport1_tx_dma_interrupt,
					SA_INTERRUPT, "sport1_tx-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_SPI:
			ret_irq = request_irq(IRQ_SPI, (void *)spi_dma_interrupt,
					      SA_INTERRUPT, "spi-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_UART_RX:
			ret_irq	= request_irq(IRQ_UART_RX, (void *)uart_rx_dma_interrupt,
					      SA_INTERRUPT|SA_SHIRQ, "uart_rx-dma", (void *)device_id);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_UART_TX:
			ret_irq	= request_irq(IRQ_UART_TX, (void *)uart_tx_dma_interrupt,
					      SA_INTERRUPT|SA_SHIRQ, "uart_tx-dma", (void *)device_id);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_MEM_STREAM0_SRC:
		case CH_MEM_STREAM0_DEST:
			ret_irq = request_irq(IRQ_MEM_DMA0,(void *)mem_stream0_dma_interrupt,
					SA_INTERRUPT, "MemStream0-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		case CH_MEM_STREAM1_SRC:
		case CH_MEM_STREAM1_DEST:
			ret_irq = request_irq(IRQ_MEM_DMA1,(void *)mem_stream1_dma_interrupt,
					SA_INTERRUPT, "MemStream1-dma", NULL);
			if (ret_irq)
				return ret_irq;
			break;
		default:
			break;
		}
	}
	else
		dma_ch[channel].dma_type = DMA_POLLING_TYPE;
		
	DMA_DBG("IRQ related : Done  \n");
	DMA_DBG("request_dma() : END  \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		free_dma()
* Description:
*		Free the specific DMA channel
* Parameters:
*		channel:	DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL: If the Invalid Channel Number is given.
*		DMA_FAIL:  If the Channel is already freed
*		DMA_SUCCESS : for successful execution
*-----------------------------------------------------------------------------*/
DMA_RESULT freedma(unsigned int channel)
{
	DMA_DBG("freedma() : BEGIN \n");
		
	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status == DMA_CHANNEL_FREE)
		return DMA_FAIL;
		
	/* Halt the DMA */
	disable_dma(channel);
	clear_dma_buffer(channel);
	disable_dma_buffer_clear(channel);


	/* Make sure the DMA channel will be stopped before free it */
	if (dma_ch[channel].dma_type == DMA_INTERRUPT_TYPE){
	switch (channel){
		case CH_PPI:
			disable_irq (IRQ_PPI);
			break;
		case CH_SPORT0_RX:
			disable_irq (IRQ_SPORT0_RX);
			break;
		case CH_SPORT0_TX:
			disable_irq (IRQ_SPORT0_TX);
			break;
		case CH_SPORT1_RX:
			disable_irq (IRQ_SPORT1_RX);
			break;
		case CH_SPORT1_TX:
			disable_irq (IRQ_SPORT1_TX);
			break;
		case CH_SPI:
			disable_irq (IRQ_SPI);
			break;
		case CH_UART_RX:
			disable_irq (IRQ_UART_RX);
			break;
		case CH_UART_TX:
			disable_irq (IRQ_UART_TX);
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
}
	
	/* Clear the DMA Variable in the Channel*/
	dma_ch[channel].last_descriptor = BASE_VALUE;
	dma_ch[channel].first_descriptor = BASE_VALUE;
	dma_ch[channel].wait_last_descriptor = BASE_VALUE;
	dma_ch[channel].wait_first_descriptor = BASE_VALUE;
	dma_ch[channel].next_descriptor = BASE_VALUE;

	down(&(dma_ch[channel].dmalock));
	dma_ch[channel].dma_channel_status = DMA_CHANNEL_FREE;
	up(&(dma_ch[channel].dmalock));

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
*		DMA_SUCCESS after successfully disabling the DMA for the
*		specified channel
*-----------------------------------------------------------------------------*/
DMA_RESULT disable_dma(unsigned int channel)
{
	DMA_DBG("disable_dma() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	/* Here we are not checking for enable_dma() - is it required ?*/

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	dma_ch[channel].regs->cfg &= ~DMAEN;	/* Clean the enable bit */
	SSYNC();

	dma_ch[channel].dma_channel_status  = DMA_CHANNEL_REQUESTED;

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
*-----------------------------------------------------------------------------*/
DMA_RESULT enable_dma(unsigned int channel)
{
	DMA_DBG("enable_dma() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	/* here we are not returning if the channel is not requested. 
	   We have to do this - But need to be discussed */
	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;


	dma_ch[channel].flowmode = (((dma_ch[channel].regs->cfg ) &
							(0xf000)) >> 12);
	dma_ch[channel].regs->cfg |= DMAEN;	/* Set the enable bit */
	SSYNC();

	dma_ch[channel].dma_channel_status = DMA_CHANNEL_ENABLED;

	DMA_DBG("enable_dma() : END \n");

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
*-----------------------------------------------------------------------------*/
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

	assert(*ChannelNumber < MAX_BLACKFIN_DMA_CHANNEL);
	if (*ChannelNumber >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	for (pMapping = Mapping, i = 0 ;
		i < (sizeof (Mapping)/sizeof(DMA_MAPPING)); i++, pMapping++) {

		if ((pMapping->DeviceType == DeviceType) &&
			(pMapping->DeviceNumber == DeviceNumber)) {

			for (i=0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {

				pChannel = &dma_ch[i];
				if((pChannel->ControllerNumber == pMapping->ControllerNumber)
					&& (pChannel->PeripheralMap->b_PMAP == pMapping->PeripheralMap)) {

					*ControllerNumber = pChannel->ControllerNumber;
					*ChannelNumber = i;
					return DMA_SUCCESS;
				} /* End of if*/
			} /* End of For */
		} /* End of If */
	} /* End of for loop */
	return (DMA_BAD_DEVICE);
}

/*------------------------------------------------------------------------------
* Name:
*		dmaSetMapping()
* Description:
*		Get the pheripharal Mapping of the given channel
* Parameters:
*		DeviceType:		DMA Device Type.
*		DeviceNumber:		DMA Device Number.
*		ControllerNumber:	DMA Controller Number.
*		ChannelNumber:		DMA Channel Number.
* Return:
*		DMA_SUCCESS will be return for Success
*		DMA_BAD_DEVICE will be return for invalid Device 
*-----------------------------------------------------------------------------*/
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

	assert(ChannelNumber < MAX_BLACKFIN_DMA_CHANNEL);
	if (ChannelNumber >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	for (pMapping = Mapping, i = 0;
		i < (sizeof (Mapping) / (sizeof (DMA_MAPPING)));
		i++, pMapping++ ){

		if ((pMapping->DeviceType == DeviceType) &&
			(pMapping->DeviceNumber == DeviceNumber)) {

			for (i=0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {
				pChannel = &dma_ch[i];
				if( (pChannel->ControllerNumber == ControllerNumber) &&
					( i  == ChannelNumber)) {
				
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
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_descriptor_base(unsigned int channel, unsigned int base)
{
	DMA_DBG("set_dma_descriptor_base() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_ENABLED);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  == DMA_CHANNEL_ENABLED)
		return DMA_ALREADY_RUNNING ;

 	dma_ch[channel].descr_base = base;

	DMA_DBG("set_dma_descriptor_base() : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_addr()
* Description:
*		Set the Start Address register for the specific DMA channel
* 		This function can be used for register based DMA ,
*		to setup the start address
* Parameters:
*		channel:	DMA channel number.
*		addr:		Starting address of the DMA Data to be
*				transferred.
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the starting address for DMA
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_addr(unsigned int channel, unsigned long addr)
{
	DMA_DBG("set_dma_addr() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL ;

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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the direction for DMA
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_dir(unsigned int channel,  char dir)
{
	DMA_DBG("set_dma_dir() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->cfg |= WNR;	/* Write to memory */
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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the DMA type.
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_type(unsigned int channel, char type)
{
	DMA_DBG("set_dma_type() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->cfg &= 0x0FFF;
	switch(type){
		case FLOW_STOP:		/* STOP mode */
			break;
		case FLOW_AUTO:	/* Autobuffer based DMA */
			dma_ch[channel].regs->cfg |= (FLOW_AUTO << 12 );
			break;
		case FLOW_ARRAY:	/* Decriptor Array based DMA mode */
			dma_ch[channel].regs->cfg |= (FLOW_ARRAY << 12);
			break;
		case FLOW_SMALL:	/* Decriptor list (small) */
			dma_ch[channel].regs->cfg |= (FLOW_SMALL << 12);
			break;
		case FLOW_LARGE:	/* Decripotr list (large)*/
			dma_ch[channel].regs->cfg |= (FLOW_LARGE << 12);
			break;
		default: 	/* Invalid TYPE */
			DMA_DBG ("Invalid TYPE \n");
			break;
	}
	SSYNC();

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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the x-count value.
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_x_count(unsigned int channel, unsigned short x_count)
{
	DMA_DBG("set_dma_x_count() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the y-count value.
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_y_count(unsigned int channel, unsigned short y_count)
{
	DMA_DBG("set_dma_y_count() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL ;

	dma_ch[channel].regs->y_count = y_count;
	SSYNC();

	DMA_DBG("set_dma_y_count() : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_x_modify()
* Description:
*		Set the Inner Loop Address Increment register for the specific
*		DMA channel. This function can be used to setup the x_modify for
*		the channe, mainly during the register based DMA
* Parameters:
*		channel:		DMA channel number.
*		x_modify:		The 16-bit modification/increment value.
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the x-modify value.
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_x_modify(unsigned int channel, unsigned short x_modify)
{
	DMA_DBG("set_dma_x_modify() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->x_modify = x_modify;
	SSYNC();

	DMA_DBG("set_dma_x_modify() : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_y_modify()
* Description:
*		Set the Inner Loop Address Increment register for the specific
*		DMA channel.
* 		This function can be used to setup the y_modify for the channel
* 		mainly during the register based DMA
* Parameters:
*		channel:		DMA channel number.
*		y_modify:		The 16-bit modification/increment value.
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the y-modify value
*-----------------------------------------------------------------------------*/

DMA_RESULT set_dma_y_modify(unsigned int channel, unsigned short y_modify)
{
	DMA_DBG("set_dma_y_modify() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->y_modify = y_modify;
	SSYNC();

	DMA_DBG("set_dma_y_modify() : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_config()
* Description:
* 		This function can be used to setup the configuaration for the
*		channel.This function is used Mainly during the register based
*		DMA.
* Parameters:
*		channel:		DMA channel number.
*		config:			configuaration value to be set.
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the y-modify value
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_config(unsigned int channel, unsigned short config)
{
	DMA_DBG("set_dma_config() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->cfg = config;
	SSYNC();

	DMA_DBG("set_dma_config() : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_currdesc_addr()
* Description:
* 		This function can be used to setup the Current Descriptor Address 
*		for the channel.This function is used Mainly during the register 
*		based DMA.
* Parameters:
*		channel:		DMA channel number.
*		desc_addr:		Current Descriptor Address .
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_BAD_DESCRIPTOR if the Invalid Descriptor address is given
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the y-modify value
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_currdesc_addr(unsigned int channel, unsigned long desc_addr)
{
	DMA_DBG("set_dma_current_descriptor() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(desc_addr != 0);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if ( desc_addr == 0)
		return DMA_BAD_DESCRIPTOR;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->curr_desc_ptr = desc_addr;
	SSYNC();

	DMA_DBG("set_dma_current_descriptor() : END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		set_dma_nextdesc_addr()
* Description:
* 		This function can be used to setup the Next Descriptor Address 
*		for the channel.This function is used Mainly during the register 
*		based DMA.
* Parameters:
*		channel:		DMA channel number.
*		next_desc_addr:		Next Descriptor Address .
*
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_BAD_DESCRIPTOR if the Invalid Descriptor address is given
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the y-modify value
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_nextdesc_addr(unsigned int channel, unsigned long next_desc_addr)
{
	DMA_DBG("set_dma_next_descriptor() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(next_desc_addr != 0);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if ( next_desc_addr == 0)
		return DMA_BAD_DESCRIPTOR;

	if (dma_ch[channel].dma_channel_status  != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->next_desc_ptr = next_desc_addr;
	SSYNC();

	DMA_DBG("set_dma_next_descriptor() : END \n");
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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS after successfully set the y-modify value
*-----------------------------------------------------------------------------*/
DMA_RESULT set_dma_transfer_size(unsigned int channel, char size)
{
	unsigned short size_word;

	DMA_DBG("set_dma_tranfer() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	size_word = 0;

	/* Set the 2 & 3 bits as 0 for Initialization */
	dma_ch[channel].regs->cfg &= 0xFFF3;
	
	switch (size) {

		case DATA_SIZE_8:
			break;
		case DATA_SIZE_16:
			dma_ch[channel].regs->cfg |= WDSIZE_16;
			break;
		case DATA_SIZE_32:
			dma_ch[channel].regs->cfg |= WDSIZE_32;
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
*		IN :  channel:		DMA channel number.
*		OUT:  size:		transfer size of the DMA channel
* Return:
*		DMA_NO_SUCH_CHANNEL for invalid channel number
*		DMA_FAIL for NULL value for the size
*		DMA_SUCCESS for successful execution
*-----------------------------------------------------------------------------*/
DMA_RESULT get_dma_transfer_size(unsigned int channel, unsigned short* size)
{

	DMA_DBG("get_dma_tranfer_size() : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(size != 0);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (size == NULL)
		return DMA_FAIL;

	*size = dma_ch[channel].regs->cfg;
	*size &= 0x000C; 	/* Bits 2 & 3 represents the WDSIZE  */
	*size >>=2;

	DMA_DBG("get_dma_tranfer_size() : END \n");

	return DMA_SUCCESS;
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
*-----------------------------------------------------------------------------*/
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
*-----------------------------------------------------------------------------*/
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
*-----------------------------------------------------------------------------*/
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
*-----------------------------------------------------------------------------*/
DMA_RESULT enable_dma_descr_large(unsigned int channel)
{
	return set_dma_type(channel, DMA_LARGE);
}

/*------------------------------------------------------------------------------
* Name:
*		get_dma_curr_x_count()
* Description:
*		Get the content of curr_x_count register for the specific DMA
*		channel
* Parameters:
*		IN : channel:		DMA channel number.
*		OUT: x_count:		The x_count value will be retreived
*					and returned using this variable
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel number
*		DMA_FAIL : for NULL value given for x_count
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT get_dma_curr_x_count(unsigned int channel, unsigned short *x_count)
{

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(x_count != NULL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;
	if (x_count == NULL)
		return DMA_FAIL;

	*x_count = dma_ch[channel].regs->curr_x_count;
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		get_dma_curr_y_count()
* Description:
*		Get the content of curr_y_count register for the specific DMA
*		channel
* Parameters:
*		IN : channel:		DMA channel number.
*		OUT: y_count:		The y_count value will be retreived
*					and returned using this variable
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel number
*		DMA_FAIL : for NULL value given for y_count
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT get_dma_curr_y_count(unsigned int channel, unsigned short *y_count)
{
	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(y_count != NULL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;
	if (y_count == NULL)
		return DMA_FAIL;

	*y_count = dma_ch[channel].regs->curr_y_count;
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		clear_dma_buffer()
* Description:
*		Set the Buffer Clear bit in the Configuration register of
*		specific DMA channel. This will stop the descriptor based DMA
*		operation.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT clear_dma_buffer(unsigned int channel)
{

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->cfg |= RESTART;
	SSYNC();

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		disable_dma_buffer_clear()
* Description:
*		Clear the Buffer Clear bit in the Configuration register of
*		specific DMA channel.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT  disable_dma_buffer_clear(unsigned int channel)
{

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->cfg &= ~RESTART;
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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/

DMA_RESULT enable_dma_data_row_intr(unsigned int channel)
{

	/* Check whether this function is called from 2D-DMA only */
	DMA_DBG("enable_dma_data_row_intr () : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

 	/* Interrupt After completing each row */
	dma_ch[channel].regs->cfg |= DI_SEL;

	SSYNC();

	DMA_DBG("enable_dma_data_row_intr () : END \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_data_intr()
* Description:
*		Enable Data Interrupt
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT enable_dma_data_intr(unsigned int channel)
{
	DMA_DBG("enable_dma_data_intr () : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	/* enable Data Interrupt  */
	dma_ch[channel].regs->cfg |= DI_EN;
	SSYNC();

	DMA_DBG("enable_dma_data_intr () : BEGIN \n");

	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		enable_dma_err_intr()
* Description:
*		Enable DMA Error for the specific DMA channel.
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT enable_dma_err_intr(unsigned int channel)
{
	DMA_DBG("enable_dma_err_intr () : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS for successfully enabling the interrupts
*-----------------------------------------------------------------------------*/
DMA_RESULT enable_dma_intr(unsigned int channel)
{
	DMA_DBG("enable_dma_intr () : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/

DMA_RESULT disable_dma_data_row_intr(unsigned int channel)
{
	DMA_DBG("disable_dma_data_row_intr () : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	dma_ch[channel].regs->cfg &= ~DI_SEL;
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
*		DMA_FAIL if the channel is not requested or already enabled
*		DMA_SUCCESS : for successful completion
*-----------------------------------------------------------------------------*/
DMA_RESULT  disable_dma_data_intr(unsigned int channel)
{
	unsigned short intr_word;

	DMA_DBG("disable_dma_data_intr () : BEGIN \n");

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	intr_word = 0;

	dma_ch[channel].regs->cfg &= ~DI_EN;

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
*-----------------------------------------------------------------------------*/
DMA_RESULT disable_dma_err_intr(unsigned int channel)
{
	DMA_DBG("disable_dma_err_intr () : BEGIN \n");
	DMA_DBG("channel Number %d \n", channel);

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

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
*-----------------------------------------------------------------------------*/
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
*		IN  : channel:		DMA channel number.
*		OUT : irq_stat:		IRQ status of the DMA Channel.
* Return:
*		DMA_NO_SUCH_CHANNEL : for invalid channel Number
*		DMA_FAIL for invalid address for irq_stat
*		DMA_SUCCESS : for successful execution
*-----------------------------------------------------------------------------*/
DMA_RESULT get_dma_irq_stat(unsigned int channel, unsigned short *irq_stat)
{
	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);
	assert(irq_stat != NULL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (irq_stat == NULL)
		return DMA_FAIL;

	*irq_stat = dma_ch[channel].regs->irq_status;
	return DMA_SUCCESS;
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
*-----------------------------------------------------------------------------*/
int clr_dma_irq_stat(unsigned int channel)
{

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

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

#ifdef CONFIG_BLKFIN_DCACHE
#define SPECIAL_DESC
#endif

#ifdef SPECIAL_DESC
/* Is this required ???? BFin */
extern unsigned long l1sram_alloc(unsigned long size);
extern void bf53x_cache_init(void);

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
*-----------------------------------------------------------------------------*/
void* create_descriptor(int flowtype)
{
	void 		*pDescriptor;

	DMA_DBG("create_desriptor() : BEGIN \n");

	switch (flowtype){
		/* For Array Type DMA, the dynamic allocation is not required.
		   So the respective code is commented */
		/*
		case FLOW_ARRAY:
			descriptor =
			(dmasgarray_t *)kmalloc(sizeof(dmasgarray_t),GFP_KERNEL);
			break;
		*/
		case FLOW_SMALL:
			pDescriptor = 
			(dmasgsmall_t *)kmalloc(sizeof(dmasgsmall_t),GFP_KERNEL);
			break;
		case FLOW_LARGE:
			pDescriptor = 
			(dmasglarge_t *)kmalloc(sizeof(dmasglarge_t),GFP_KERNEL);
			break;
		default:
			return NULL;
	}

	DMA_DBG("create_desriptor() : END \n");

	return pDescriptor;
}

/*------------------------------------------------------------------------------
* Name:
*		dma_setup_desc()
* Description:
*		Set the values in the specified descriptor
* Parameters:
*		desc:		Descriptor to be set .
*		next:		Next Descriptor address to be set.
*		start_addr:	starting address of the DMA to be set.
*		cfg:		configuaration register value to be set.
*		x_count:	x_count value to be set in the descriptor.
*		x_modify:	x_modify value to be set in the descriptor.
*		y_count:	y_count value to be set in the descriptor.
*		y_modify:	y_modify value to be set in the descriptor.
* Return:
*		none
*-----------------------------------------------------------------------------*/
/* This function is not used currently */
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

	/* Set the start  addr  */
	((dmasglarge_t *) desc)->start_addr = start_addr;

	/* Set the Configuaration Register */
	((dmasglarge_t *) desc)->cfg = cfg;

	/* Set the x-count */
	((dmasglarge_t *) desc)->x_count = x_count;

	/* Set the x-modify */
	((dmasglarge_t *) desc)->x_modify = x_modify;

	/* Set the y-count */
	((dmasglarge_t *) desc)->y_count = y_count;
	
	/* Set the y-modify */
	((dmasglarge_t *) desc)->y_modify = y_modify;

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
*		DMA_NO_SUCH_CHANNEL : for invalid channel number.
*		DMA_BAD_DESCRIPTOR : for Bad descriptor Size Value
*		DMA_SUCCESS : for Valid descriptor Size
*-----------------------------------------------------------------------------*/
/* This function is not used currently */
DMA_RESULT check_desc_size(unsigned int channel)
{
	unsigned short desc_size,flow_type = 0x0000;
	unsigned short cfg_word;

	assert(channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (channel >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	cfg_word = dma_ch[channel].regs->cfg;
	flow_type = cfg_word & 0xF000;
	flow_type >>= 12;

	desc_size = cfg_word & 0x0F00;
	desc_size >>= 8;

	switch (flow_type){

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
*		Set the starting address of  the DMA Transfer in the given
*		descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		startaddr:	starting address of the DMA,  to be set .
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : for successfully setting the DMA Start address
*-----------------------------------------------------------------------------*/
DMA_RESULT set_desc_startaddr(void *pDescriptor, unsigned long startaddr,
				 int flowtype)
{
	assert(pDescriptor != NULL);

	if (pDescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;

	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->start_addr = startaddr;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->start_addr_lo =
						startaddr & LOW_WORD;
			((dmasgsmall_t *)pDescriptor)->start_addr_hi =
						(startaddr & HIGH_WORD ) >> 16 ;
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
*		Set the x_count value for the DMA Transfer in the given
*		descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		x_count:	x_count value to be set.
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : for successfully setting the x_count
*-----------------------------------------------------------------------------*/
DMA_RESULT set_desc_xcount(void *pDescriptor, unsigned short x_count,
				 int flowtype)
{

	assert(pDescriptor != NULL);

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
*		Set the x_modify value for the DMA Transfer in the given
*		descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		x_modify:	x_modify value to be set.
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : for successfully setting the x_count
*----------------------------------------------------------------------------*/
DMA_RESULT set_desc_xmodify(void *pDescriptor, unsigned short x_modify,
				int flowtype)
{
	assert(pDescriptor != NULL);

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
*		Set the y_count value for the DMA Transfer in the given
*		descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		y_count:	y_count value to be set.
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : for successfully setting the y_count
*-----------------------------------------------------------------------------*/
DMA_RESULT set_desc_ycount(void *pDescriptor, unsigned short y_count,
				 int flowtype)
{
	assert(pDescriptor != NULL);

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
*		Set the y_modify value for the DMA Transfer in the given
*		descriptor
* Parameters:
*		pDescriptor:	Pointer to the descriptor.
*		y_modify:	y_modify value to be set.
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : for successfully setting the y_modify
*-----------------------------------------------------------------------------*/
DMA_RESULT set_desc_ymodify(void *pDescriptor, unsigned short y_modify,
				 int flowtype)
{
	assert(pDescriptor != NULL);

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
*-----------------------------------------------------------------------------*/
DMA_RESULT add_descriptor(	void *pNewdescriptor,
				int  channel_number,
				int flowtype)
{
	DMA_channel *channel = &dma_ch[channel_number];
	DMA_RESULT 	retValue;
	void *last_descriptor = channel->last_descriptor;

	assert(pNewdescriptor != NULL);
	assert(channel_number < MAX_BLACKFIN_DMA_CHANNEL);

	DMA_DBG (" add_descriptor(): BEGIN \n");

	if (channel_number >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	if (pNewdescriptor == NULL)
		return DMA_BAD_DESCRIPTOR;

	if (( dma_ch[channel_number].regs->cfg ) & (DMAEN)) {
		down(&(dma_ch[channel_number].dmalock));
		retValue = 
			add_to_wait_descriptor(pNewdescriptor, 
						channel_number,flowtype);
		up(&(dma_ch[channel_number].dmalock));
		return retValue;
	}

	if (last_descriptor){ /* Channel has already a list of descriptors  */

		if (flowtype == FLOW_LARGE){

			/*set the next descriptor address of the newdescriptor*/
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
				((dmasglarge_t *)last_descriptor)->next_desc_addr;

			/* update the  next descriptor address of the last
			descriptor in the existing list */
			((dmasglarge_t *)last_descriptor)->next_desc_addr =
				(unsigned long)pNewdescriptor;

			((dmasglarge_t *)last_descriptor)->cfg |= 0x7900;
		} else {

			/* If the new descriptor is 64K out of range of
			   previous descriptor then return error */
			int descr_base =
			(unsigned short)((unsigned long)pNewdescriptor & HIGH_WORD);
			if (channel->descr_base != descr_base){
				return DMA_BAD_DESCRIPTOR;
			}

			/* set the lower 4 bytes of the next descriptor address
			 of the new descriptor */
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
				((dmasgsmall_t *)last_descriptor)->next_desc_addr_lo;

			/* update the lower 4 bytes of the  next descriptor
			address of the last descriptor in the existing
			list */
			((dmasgsmall_t *)last_descriptor)->next_desc_addr_lo =
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);

			/* In non-loopback mode, the last descriptor used to
			have STOP flow mode.  This is to be changed */
			((dmasgsmall_t *)last_descriptor)->cfg |= 0x6800;
		}
		
 	} else { /* Channel does not have any existing list of descriptors */
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
				(unsigned long)pNewdescriptor;
		} else{
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
			channel->descr_base =
				(unsigned short)((unsigned long)pNewdescriptor & HIGH_WORD);
		}
		channel->first_descriptor = pNewdescriptor;
	 }

	if (flowtype == DMA_LARGE){
		((dmasglarge_t *)pNewdescriptor)->cfg &= 0x0fff;
	} else {
		((dmasgsmall_t *)pNewdescriptor)->cfg &= 0x0fff;
	}
	channel->last_descriptor = pNewdescriptor;

	DMA_DBG (" add_descriptor(): END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		add_to_wait_descriptor()
* Description:
*		Adds a new descriptor at the end of the existing Waiting
*		descriptor list	of the given channel.
* Parameters:
*		pNewDescriptor:	Pointer to the new descriptor to be addded.
*		channel_number:	Channel number.
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_NO_SUCH_CHANNEL: If the  channel number is invalid
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : For successful execution
*-----------------------------------------------------------------------------*/
DMA_RESULT add_to_wait_descriptor(	void *pNewdescriptor,
					int  channel_number,
			 		int flowtype)
{
	DMA_channel *channel = &dma_ch[channel_number];
	void* last_descriptor;
	
	assert(pNewdescriptor != NULL);
	assert(channel_number < MAX_BLACKFIN_DMA_CHANNEL);

	DMA_DBG (" add_to_wait_descriptor : BEGIN \n");

	last_descriptor = channel->wait_last_descriptor;

	if (flowtype == DMA_SMALL){
		unsigned short base =
			(unsigned short)(((unsigned long)pNewdescriptor & HIGH_WORD)>>16);

		if ((channel->descr_base) && (base  != channel->descr_base)) {
			DMA_DBG ("Descriptor Out of Range \n");
			return DMA_BAD_DESCRIPTOR;
		}
	}

	if (last_descriptor){
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
			((dmasglarge_t *)(channel->wait_last_descriptor))->next_desc_addr;

			((dmasglarge_t *)last_descriptor)->next_desc_addr =
						(unsigned long)pNewdescriptor;
		} else{ /* SMALL Descriptor Case */
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
			((dmasgsmall_t *)(channel->wait_last_descriptor))->next_desc_addr_lo;

			((dmasgsmall_t *)(last_descriptor))->next_desc_addr_lo =
			(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
		}
 	} else {
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
				(unsigned long)pNewdescriptor;
		} else{
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
		}
		channel->wait_first_descriptor = pNewdescriptor;
	}

	channel->wait_last_descriptor = pNewdescriptor;

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
*-----------------------------------------------------------------------------*/

/* Current Implementation of callback function is for testing purpose  */
void testcallback (DMA_EVENT event,  void *startAddress)
{

	DMA_DBG ("Callback Function is called \n");

	if (startAddress == NULL)
		return;

	switch (event){
		case DMA_ERROR_INTERRUPT:
			DMA_DBG ("DMA Error Interrupt  \n");
			break;
		case DMA_DONE_INTERRUPT:
			DMA_DBG ("DMA Done Event  \n");
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
*		This function checks the Interrupt Type and Calls the
*		Callback function. After the execution of Callback function, the
*		next descriptor in the descriptor list will be used to start the
*		DMA.
* Parameters:
*		irq:		irq number of the Interrupt
*				(refer bf533_irq.h for the mapping between
*				irq numbers and INTERRUPTS )
*		dev_id:		Device id
*		pt_regs:	pt_regs
* Return: 
*		None
*-------------------------------------------------------------------------------*/
irqreturn_t mem_stream0_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_MEM_STREAM0_DEST;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

		/* Proposed Implementation  with DI_EN on any of the
		   descriptor in the list in addition to the last
		   descriptor in the list.
			- Send the intimation to the Callback function
			- Get the next descriptor in the list
			- If the descriptor is the last descriptor in
			  the list, then
  				- If the Loop back method was set, then
				   start DMA once again.
					( Using the next_desc_ptr and
					  next descriptor config.This 
					  is to be automatic )
				- If there is a waiting descriptor list
					start the DMA using the waiting
					descriptor as active descriptor
					list.
			- If the descriptor is not last descriptor, then
				load the values to restart the DMA
				( Not required always, if the values will
				  be stored automatically)
		*/

		/* 	With current execution of interrupts -
			i.e interrupts coming at the end of the
			descriptor list the following implementation
			was done. 
		*/

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* If we have a single waiting
				   descriptor then it is like stop mode
				   - Because with Loop back mode we have
				     a problem
				   - Once the loopback problem is
                                            solved this code can be removed*/
				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[CH_MEM_STREAM0_DEST].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
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

/*------------------------------------------------------------------------------
* Name:
*		add_descriptor_descr()
* Description:
*		This function will add a new descriptor to another descriptor
*		Currently this function is not used. In future we can enhance
*		this function to add a descriptor to the list of descriptors. 			
* Return:
*		None
*-----------------------------------------------------------------------------*/
/* This function is not used */
DMA_RESULT add_descriptor_descr(void *newdescriptor,
			void *previousdescriptor,
			int flowtype)
{
	dmasglarge_t* newdescr = (dmasglarge_t *)newdescriptor;
	dmasglarge_t* prevdescr = (dmasglarge_t *)previousdescriptor;
	DMA_DBG (" add_descriptor_descr \n");

	assert(newdescriptor != NULL);
	assert(previousdescriptor != NULL);
	if(newdescriptor == NULL);
		return DMA_BAD_DESCRIPTOR;
	if(previousdescriptor == NULL);
		return DMA_BAD_DESCRIPTOR;


	if (prevdescr) {
		newdescr->next_desc_addr = (unsigned long)prevdescr;
		prevdescr->next_desc_addr =  (unsigned long)newdescr;
	} else{
		newdescr->next_desc_addr = (unsigned long)newdescr;
	}
}
irqreturn_t mem_stream1_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_MEM_STREAM1_DEST;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t ppi_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_PPI;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t sport0_tx_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_SPORT0_TX;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t sport0_rx_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_SPORT0_RX;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t sport1_tx_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_SPORT1_TX;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t sport1_rx_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_SPORT1_RX;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {
			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t spi_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_SPI;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t uart_rx_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_UART_RX;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {

			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

irqreturn_t uart_tx_dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs)
{
	int 		i=CH_UART_TX;
	DMA_channel 	*channel;
	
	assert(pt_regs != NULL);
	channel = &dma_ch[i];
	/* Check for the IRQ_STATUS is DMA_DONE or not */
	if (dma_ch[i].regs->irq_status & DMA_DONE) {
		if (dma_ch[i].callback)
			(dma_ch[i].callback)(DMA_DONE_INTERRUPT, NULL);

		if (dma_ch[i].flowmode == DMA_AUTO) {
			DMA_DBG ("Auto Mode Interrupt is processing \n");
		} else {
			DMA_DBG ("Not In the AutoBuffer Mode  \n");

			if (dma_ch[i].regs->next_desc_ptr ==
			    	(unsigned long)(channel->first_descriptor)){
				/*All the descriptors are processed */

				/* execute the waiting descriptor list */
			    	if ((unsigned long)channel->wait_first_descriptor) {
					disable_dma(i);
					DMA_DBG ("Wait descriptor \n ");
					channel->first_descriptor =
						channel->wait_first_descriptor;
					channel->last_descriptor =
				    		channel->wait_last_descriptor;
					channel->regs->next_desc_ptr =
				    		(unsigned long)(channel->first_descriptor);

				/* ************************************/
					if (channel->last_descriptor ==
				    		channel->wait_first_descriptor){

						if (dma_ch[i].flowmode == DMA_SMALL) {
				    			channel->regs->start_addr =
								((((dmasgsmall_t *)(channel->first_descriptor))->start_addr_lo) &
					    			(channel->descr_base << 16)) ;

							channel->regs->x_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasgsmall_t *)(channel->first_descriptor))->y_modify;
				     		} else if (dma_ch[i].flowmode == DMA_LARGE) {

				     			channel->regs->start_addr =
					    			((dmasglarge_t *)(channel->first_descriptor))->start_addr;

							channel->regs->x_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_count;

							channel->regs->x_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->x_modify;

							channel->regs->y_count =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_count;

							channel->regs->y_modify =
					    			((dmasglarge_t *)(channel->first_descriptor))->y_modify;
						}
					}
					/************************************/

		   	 		if (dma_ch[i].flowmode == DMA_LARGE)
			    			channel->regs->cfg =
				    			((dmasglarge_t *)(channel->first_descriptor))->cfg;
				    		else if (dma_ch[i].flowmode == DMA_SMALL)
							channel->regs->cfg =
					    			((dmasgsmall_t *)(channel->first_descriptor))->cfg;

			     			SSYNC();
					
					channel->wait_first_descriptor = NULL;
					channel->wait_last_descriptor = NULL;
				}
			}
		} /* End of the Else loop - for Not Auto Buffer */
	/* We have to Clear the Interrupt Here */
	 dma_ch[i].regs->irq_status |= DMA_DONE; 
	 return IRQ_HANDLED;
	} /* End of Irq_status register Check */
	else if (dma_ch[i].regs->irq_status & DMA_ERR) {
		(dma_ch[i].callback)(DMA_ERROR_INTERRUPT, NULL);
	 	dma_ch[i].regs->irq_status |= DMA_ERR; 
	 return IRQ_HANDLED;
	}
	return IRQ_NONE;
}
