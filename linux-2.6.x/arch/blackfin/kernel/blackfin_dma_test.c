
/*********************************************************** 
*
*   THIS FILE  CONTAINS THE TEST PROGRAMS 
*   THIS FILE MAY NOT BE INCLUDED IN THE FINAL RELEASE 
*   THIS IS FOR INTERNAL TESTING ONLY 
*
*
************************************************************/



#include <linux/kernel.h>
#include <linux/string.h>

#include <asm/dma.h>
extern DMA_channel 	dma_ch[MAX_BLACKFIN_DMA_CHANNEL];
extern void 		testcallback (DMA_EVENT, void *);

#define TEST_TIMES 1
#define BUF_SIZE 100
// #define PROG_MSG
static char src[BUF_SIZE] = "Blackfin DMA testing";
static char dest[BUF_SIZE];
static char src2[BUF_SIZE] = "Second Descriptor content";
static char dest2[BUF_SIZE];
static char src3[BUF_SIZE] = "Jai Jawan, Jai Kisan";
static char dest3[BUF_SIZE];



/* This function is used to test the STOP Mode */

int dma_m2m_test_stop(unsigned long src_addr, unsigned long dest_addr, unsigned char data_size, unsigned short x_count, unsigned short type)
{

	unsigned long ch_src, ch_dest;

	DMA_DBG("dma_m2m_test () : BEGIN \n");
	printk("STOP Mode Test \n");
	ch_src = ch_dest = 0;

	ch_src = request_dma(CH_MEM_STREAM0_SRC, "memdma0_src", testcallback); 
	if (ch_src < 0)
		return ch_src;
	ch_dest = request_dma(CH_MEM_STREAM0_DEST, "memdma0_dest", testcallback); 
	if (ch_dest < 0)
		return ch_dest;


	set_dma_addr(CH_MEM_STREAM0_SRC, src_addr);


	set_dma_addr(CH_MEM_STREAM0_DEST, dest_addr);

	set_dma_x_count(CH_MEM_STREAM0_SRC,x_count);
	set_dma_x_modify(CH_MEM_STREAM0_SRC,2);
	set_dma_config(CH_MEM_STREAM0_SRC,0x0084);
	set_dma_x_count(CH_MEM_STREAM0_DEST,x_count);

	set_dma_x_modify(CH_MEM_STREAM0_DEST,2);
	set_dma_config(CH_MEM_STREAM0_DEST,0x0086);

	enable_dma(CH_MEM_STREAM0_SRC);
	enable_dma(CH_MEM_STREAM0_DEST);
	
	printk("End of Enabling the DMA   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("dma_m2m_test () : END \n");

	return DMA_SUCCESS;
	
}

/* This function is used to test the AUTO BUFFER Mode */

int dma_m2m_test_auto(unsigned long src_addr, unsigned long dest_addr, unsigned char data_size, unsigned short x_count, unsigned short type)
{

	unsigned long ch_src, ch_dest;
	int i;

	DMA_DBG("dma_m2m_test_auto () : BEGIN \n");


	ch_src = request_dma(CH_MEM_STREAM0_SRC,  "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST, "memdma0_dest", testcallback); 

	DMA_DBG("End of request DMA  \n");


	set_dma_addr(CH_MEM_STREAM0_SRC, src_addr);
	set_dma_addr(CH_MEM_STREAM0_DEST, dest_addr);
	set_dma_x_count(CH_MEM_STREAM0_SRC,x_count);
	set_dma_x_modify(CH_MEM_STREAM0_SRC,2);
	set_dma_config(CH_MEM_STREAM0_SRC,0x1004);

	set_dma_x_count(CH_MEM_STREAM0_DEST,x_count);
	set_dma_x_modify(CH_MEM_STREAM0_DEST,2);
	set_dma_config(CH_MEM_STREAM0_DEST,0x1086);

	enable_dma(CH_MEM_STREAM0_SRC);
	enable_dma(CH_MEM_STREAM0_DEST);
	
	printk("End of Enabling the DMA   \n");

	for (i=0; i<20000; i++);

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("dma_m2m_test () : END \n");

	return ESUCCESS;
	
}

int dma_m2m_test_auto1D_2D(unsigned long src_addr, unsigned long dest_addr, unsigned char data_size, unsigned short x_count, unsigned short type)
{

	unsigned long ch_src, ch_dest;
	int i;

	DMA_DBG("dma_m2m_test_auto1D_2D () : BEGIN \n");


	ch_src = request_dma(CH_MEM_STREAM0_SRC, "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST,  "memdma0_dest", testcallback); 

	DMA_DBG("End of request DMA  \n");

	set_dma_addr(CH_MEM_STREAM0_SRC, src_addr);
	set_dma_addr(CH_MEM_STREAM0_DEST, dest_addr);
	set_dma_x_count(CH_MEM_STREAM0_SRC,x_count);
	set_dma_x_modify(CH_MEM_STREAM0_SRC,2);
	set_dma_config(CH_MEM_STREAM0_SRC,0x1004);

	set_dma_x_count(CH_MEM_STREAM0_DEST,x_count/2);
	set_dma_x_modify(CH_MEM_STREAM0_DEST,2);
	set_dma_y_count(CH_MEM_STREAM0_DEST,2);
	set_dma_y_modify(CH_MEM_STREAM0_DEST,2);
	set_dma_config(CH_MEM_STREAM0_DEST,0x10D6);

	enable_dma(CH_MEM_STREAM0_SRC);
	enable_dma(CH_MEM_STREAM0_DEST);
	
	printk("End of Enabling the DMA   \n");

	for (i=0; i<20000; i++);

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("dma_m2m_test () : END \n");

	return ESUCCESS;
	
}

/* This function is used to test the ARRAY Mode DMA Transfer */

dmasgarray_t      SrcDescArray[4];
dmasgarray_t      DestDescArray[4];

int dma_m2m_testArray(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2)
{
	/* unsigned short irq_stat_src, irq_stat_dest; */
	unsigned long ch_src, ch_dest, src_array_addr, dest_array_addr;
	unsigned long i;
	printk (" \n Array Mode Testing  ");

	// Create the Array of descriptors
#if DEBUG
	for (i=0;i<=3;i++)
		DMA_DBG (" %d -  src_Addr is %x dest_addr is %x \n ", i,&(SrcDescArray[i]),&( DestDescArray[i]));
#endif

	SrcDescArray[0].start_addr = src_addr ;
	SrcDescArray[0].cfg = 0x4705;
	SrcDescArray[0].x_count = count;
	SrcDescArray[0].x_modify = 2;
	SrcDescArray[0].y_count = 0;
	SrcDescArray[0].y_modify = 0;


	SrcDescArray[1].start_addr = src_addr2;
	SrcDescArray[1].cfg = 0x4705;
	SrcDescArray[1].x_count = count2;
	SrcDescArray[1].x_modify = 2;
	SrcDescArray[1].y_count = 0;
	SrcDescArray[1].y_modify = 0;


	SrcDescArray[2].start_addr = src_addr;
	SrcDescArray[2].cfg = 0x4705;
	SrcDescArray[2].x_count = count;
	SrcDescArray[2].x_modify = 2;
	SrcDescArray[2].y_count = 0;
	SrcDescArray[2].y_modify = 0;


	SrcDescArray[3].start_addr = src_addr2;
	SrcDescArray[3].cfg = 0x0785;
	SrcDescArray[3].x_count = count2;
	SrcDescArray[3].x_modify = 2;
	SrcDescArray[3].y_count = 0;
	SrcDescArray[3].y_modify = 0;


	DestDescArray[0].start_addr = dest_addr ;
	DestDescArray[0].cfg = 0x47D7;
	DestDescArray[0].x_count = count/2;
	DestDescArray[0].x_modify = 2;
	DestDescArray[0].y_count = 2;
	DestDescArray[0].y_modify = 2;


	DestDescArray[1].start_addr = dest_addr2 ;
	DestDescArray[1].cfg = 0x47D7;
	DestDescArray[1].x_count = count2/2;
	DestDescArray[1].x_modify = 2;
	DestDescArray[1].y_count = 2;
	DestDescArray[1].y_modify = 2;


	DestDescArray[2].start_addr = dest_addr ;
	DestDescArray[2].cfg = 0x47D7;
	DestDescArray[2].x_count = count/2;
	DestDescArray[2].x_modify = 2;
	DestDescArray[2].y_count = 2;
	DestDescArray[2].y_modify = 2;

	DestDescArray[3].start_addr = dest_addr2 ;
	DestDescArray[3].cfg = 0x07D7;
	DestDescArray[3].x_count = count2/2;
	DestDescArray[3].x_modify = 2;
	DestDescArray[3].y_count = 2;
	DestDescArray[3].y_modify = 2;

	ch_src = request_dma(CH_MEM_STREAM0_SRC,  "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST,  "memdma0_dest",testcallback); 

	DMA_DBG(" End of request DMA \n");

	src_array_addr = (unsigned long) (&(SrcDescArray[0]));


	set_dma_currdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);

	set_dma_nextdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);


	dest_array_addr = (unsigned long) &(DestDescArray[0]);


	set_dma_currdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

	set_dma_nextdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

	DMA_DBG("End of Setting the Descriptor Pointers    \n");

	SSYNC();
	
	set_dma_config(CH_MEM_STREAM0_SRC, SrcDescArray[0].cfg);
	set_dma_config(CH_MEM_STREAM0_DEST, DestDescArray[0].cfg);

	printk(" DMA Config for Dest is   \n");
	for (i=0; i <= 20000000; i++);

	DMA_DBG("End of Tranfer   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("End of Function   \n");

	return DMA_SUCCESS;

}

dmasgsmall_t      SmallSrcDesc[2];
dmasgsmall_t      SmallDestDesc[2];

/* Test program , to test the small descriptor list */

int dma_m2m_testSmall(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2)
{
	/* unsigned short irq_stat_src, irq_stat_dest; */
	unsigned long ch_src, ch_dest, src_array_addr, dest_array_addr;
	dmasgsmall_t *SmallSrcDesc1, *SmallSrcDesc2;
	dmasgsmall_t *SmallDestDesc1, *SmallDestDesc2;

	printk ("Test Small \n ");

	SmallSrcDesc1 = (dmasgsmall_t *) kmalloc(sizeof (dmasgsmall_t), GFP_KERNEL);
	SmallDestDesc1 = (dmasgsmall_t *) kmalloc(sizeof (dmasgsmall_t), GFP_KERNEL);
	SmallSrcDesc2 = (dmasgsmall_t *) kmalloc(sizeof (dmasgsmall_t), GFP_KERNEL);
	SmallDestDesc2 = (dmasgsmall_t *) kmalloc(sizeof (dmasgsmall_t), GFP_KERNEL);

	// Check for Higher 2 Bytes
#if 0
	if (((unsigned long)SmallSrcDesc1 & HIGH_WORD ) != ((unsigned long)SmallSrcDesc2 & HIGH_WORD)) 
	{
		DMA_DBG ("The Src Descriptors are out of range for this model \n");
		return -1;
	}
	if(((unsigned long)SmallDestDesc1 & HIGH_WORD) != ((unsigned long)SmallDestDesc2 & HIGH_WORD))
	{
		DMA_DBG ("The Dest Descriptors are out of range for this model \n");
		return -1;
	}
#endif

	SmallSrcDesc1->next_desc_addr_lo = (unsigned long)(SmallSrcDesc2) & LOW_WORD;
	SmallSrcDesc1->start_addr_lo = src_addr & LOW_WORD;
	SmallSrcDesc1->start_addr_hi = (src_addr & HIGH_WORD ) >> 16 ;
	SmallSrcDesc1->cfg = 0x6885;
	SmallSrcDesc1->x_count = count;
	SmallSrcDesc1->x_modify = 2;
	SmallSrcDesc1->y_count = 0;
	SmallSrcDesc1->y_modify = 0;

	DMA_DBG ("End of srcDesc1 Setting \n");
	
	SmallSrcDesc2->next_desc_addr_lo = (unsigned long)SmallSrcDesc1 & LOW_WORD;
	SmallSrcDesc2->start_addr_lo = src_addr2 & LOW_WORD;
	SmallSrcDesc2->start_addr_hi = (src_addr2 & HIGH_WORD ) >> 16 ;
	SmallSrcDesc2->cfg = 0x6885;
	SmallSrcDesc2->x_count = count2;
	SmallSrcDesc2->x_modify = 2;
	SmallSrcDesc2->y_count = 0;
	SmallSrcDesc2->y_modify = 0;

	DMA_DBG ("End of srcDesc1 Setting \n");


	SmallDestDesc1->next_desc_addr_lo = (unsigned long)SmallDestDesc2 & LOW_WORD;
	SmallDestDesc1->start_addr_lo = dest_addr & LOW_WORD;
	SmallDestDesc1->start_addr_hi = (dest_addr & HIGH_WORD ) >> 16 ;
	SmallDestDesc1->cfg = 0x6887;
	SmallDestDesc1->x_count = count;
	SmallDestDesc1->x_modify = 2;
	SmallDestDesc1->y_count = 0;
	SmallDestDesc1->y_modify = 0;


	SmallDestDesc2->next_desc_addr_lo = (unsigned long)SmallDestDesc1 & LOW_WORD;
	SmallDestDesc2->start_addr_lo = dest_addr2 & LOW_WORD;
	SmallDestDesc2->start_addr_hi = (dest_addr2 & HIGH_WORD ) >> 16 ;
	SmallDestDesc2->cfg = 0x6887;
	SmallDestDesc2->x_count = count2;
	SmallDestDesc2->x_modify = 2;
	SmallDestDesc2->y_count = 0;
	SmallDestDesc2->y_modify = 0;

	ch_src = request_dma(CH_MEM_STREAM0_SRC,  "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST, "memdma0_dest", testcallback); 

	DMA_DBG(" End of request DMA  - Small \n");

	src_array_addr = (unsigned long) SmallSrcDesc1;

	set_dma_nextdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);

	DMA_DBG(" Small : After Setting the next descriptor pointer for source \n");

	dest_array_addr = (unsigned long) SmallDestDesc1;


	set_dma_nextdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

	DMA_DBG(" Small : After Setting the next descriptor pointer for dest \n");

	set_dma_config(CH_MEM_STREAM0_SRC, SmallSrcDesc1->cfg);

	// DMA_DBG(" DMA Config for src1 is   %x\n", dma_ch[ch_src].regs->cfg);


	set_dma_config(CH_MEM_STREAM0_DEST, SmallDestDesc1->cfg);

	// printk(" DMA Config for dest1 is   %x\n", dma_ch[ch_dest].regs->cfg);
	printk(" DMA Config for dest1 is  SET \n");

	DMA_DBG("End of Tranfer   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("End of Function   \n");
	return ESUCCESS;

}

/* Test Program to test the Small Descriptor Mode with dynamic allocation and add descriptor*/ 

int dma_m2m_testSmall_dynamic(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2)
{
	/* unsigned short irq_stat_src, irq_stat_dest; */

	unsigned long ch_src, ch_dest, src_array_addr, dest_array_addr;
	dmasgsmall_t      *SmallSrcDesc1, *SmallSrcDesc2;
	dmasgsmall_t      *SmallDestDesc1, *SmallDestDesc2;
	dmasgsmall_t      *SmallSrcDesc3, *SmallDestDesc3;


	printk(" In the Small - Dynamic Model  \n");
	SmallSrcDesc1 = create_descriptor(FLOW_SMALL);
	SmallSrcDesc2 = create_descriptor(FLOW_SMALL);
	SmallDestDesc1 = create_descriptor(FLOW_SMALL);
	SmallDestDesc2 = create_descriptor(FLOW_SMALL);
	SmallSrcDesc3 = create_descriptor(FLOW_SMALL);
	SmallDestDesc3 = create_descriptor(FLOW_SMALL);

	add_descriptor(SmallSrcDesc1, CH_MEM_STREAM0_SRC, FLOW_SMALL);
	SmallSrcDesc1->start_addr_lo = src_addr & LOW_WORD;
	SmallSrcDesc1->start_addr_hi = (src_addr & HIGH_WORD ) >> 16 ;
	SmallSrcDesc1->cfg = 0x6885;
	SmallSrcDesc1->x_count = count;
	SmallSrcDesc1->x_modify = 2;
	SmallSrcDesc1->y_count = 0;
	SmallSrcDesc1->y_modify = 0;

	DMA_DBG ("End of srcDesc1 Setting \n");
	
	add_descriptor(SmallSrcDesc2, CH_MEM_STREAM0_SRC, FLOW_SMALL);
	SmallSrcDesc2->start_addr_lo = src_addr2 & LOW_WORD;
	SmallSrcDesc2->start_addr_hi = (src_addr2 & HIGH_WORD ) >> 16 ;
	SmallSrcDesc2->cfg = 0x0885;
	SmallSrcDesc2->x_count = count2;
	SmallSrcDesc2->x_modify = 2;
	SmallSrcDesc2->y_count = 0;
	SmallSrcDesc2->y_modify = 0;

	add_to_wait_descriptor(SmallSrcDesc3, CH_MEM_STREAM0_SRC, FLOW_SMALL);
	SmallSrcDesc3->start_addr_lo = src_addr & LOW_WORD;
	SmallSrcDesc3->start_addr_hi = (src_addr & HIGH_WORD ) >> 16 ;
	SmallSrcDesc3->cfg = 0x0885;
	SmallSrcDesc3->x_count = count2;
	SmallSrcDesc3->x_modify = 2;
	SmallSrcDesc3->y_count = 0;
	SmallSrcDesc3->y_modify = 0;
	DMA_DBG ("End of srcDesc1 Setting \n");


	/* dest_array_addr = SmallDestDesc2; */

	//SmallDestDesc1->next_desc_addr_lo = (unsigned long)SmallDestDesc2 & LOW_WORD;
	add_descriptor(SmallDestDesc1, CH_MEM_STREAM0_DEST, FLOW_SMALL);
	SmallDestDesc1->start_addr_lo = dest_addr & LOW_WORD;
	SmallDestDesc1->start_addr_hi = (dest_addr & HIGH_WORD ) >> 16 ;
	SmallDestDesc1->cfg = 0x6887;
	SmallDestDesc1->x_count = count;
	SmallDestDesc1->x_modify = 2;
	SmallDestDesc1->y_count = 0;
	SmallDestDesc1->y_modify = 0;

	DMA_DBG ("End of srcDesc1 Setting \n");

	/* dest_array_addr = SmallDestDesc1; */

	add_descriptor(SmallDestDesc2, CH_MEM_STREAM0_DEST, FLOW_SMALL);
	SmallDestDesc2->start_addr_lo = dest_addr2 & LOW_WORD;
	SmallDestDesc2->start_addr_hi = (dest_addr2 & HIGH_WORD ) >> 16 ;
	SmallDestDesc2->cfg = 0x0887;
	SmallDestDesc2->x_count = count2;
	SmallDestDesc2->x_modify = 2;
	SmallDestDesc2->y_count = 0;
	SmallDestDesc2->y_modify = 0;

	add_to_wait_descriptor(SmallDestDesc3, CH_MEM_STREAM0_DEST, FLOW_SMALL);
	SmallDestDesc3->start_addr_lo = dest_addr & LOW_WORD;
	SmallDestDesc3->start_addr_hi = (dest_addr & HIGH_WORD ) >> 16 ;
	SmallDestDesc3->cfg = 0x0887;
	SmallDestDesc3->x_count = count;
	SmallDestDesc3->x_modify = 2;
	SmallDestDesc3->y_count = 0;
	SmallDestDesc3->y_modify = 0;
	DMA_DBG(" End of Descriptor Creation  - Small \n");

	ch_src = request_dma(CH_MEM_STREAM0_SRC,  "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST,  "memdma0_dest", testcallback); 

	DMA_DBG(" End of request DMA  - Small \n");

	src_array_addr = (unsigned long) SmallSrcDesc1;
	set_dma_nextdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);

	DMA_DBG(" Small : After Setting the next descriptor pointer for source \n");

	dest_array_addr = (unsigned long) SmallDestDesc1;

	set_dma_nextdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

	DMA_DBG(" Small : After Setting the next descriptor pointer for dest \n");

	

	set_dma_config(CH_MEM_STREAM0_SRC, SmallSrcDesc1->cfg);


	set_dma_config(CH_MEM_STREAM0_DEST, SmallDestDesc1->cfg);

	// printk(" DMA Config for dest1 is   %x\n", dma_ch[ch_dest].regs->cfg);
	printk(" DMA Config for dest1 is   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("End of Function   \n");
	return ESUCCESS;


}

/* Test program , to test the Large descriptor list */
dmasglarge_t      LargeSrcDesc[2];
dmasglarge_t      LargeDestDesc[2];
int dma_m2m_testLarge(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2)
{
	/* unsigned short irq_stat_src, irq_stat_dest; */
	unsigned long ch_src, ch_dest, src_array_addr, dest_array_addr;
	dmasglarge_t      *LargeSrcDesc1, *LargeSrcDesc2;
	dmasglarge_t      *LargeDestDesc1, *LargeDestDesc2;
	dmasglarge_t      *LargeSrcDesc3, *LargeDestDesc3;
	
	src_array_addr = dest_array_addr = 0x0;

	DMA_DBG(" In the Large Model  \n");

	LargeSrcDesc1 = create_descriptor(FLOW_LARGE);
	LargeSrcDesc2 = create_descriptor(FLOW_LARGE);
	LargeSrcDesc3 = create_descriptor(FLOW_LARGE);
	LargeDestDesc1 = create_descriptor(FLOW_LARGE);
	LargeDestDesc2 = create_descriptor(FLOW_LARGE);
	LargeDestDesc3 = create_descriptor(FLOW_LARGE);

	add_descriptor(LargeSrcDesc1, CH_MEM_STREAM0_SRC, FLOW_LARGE);
	LargeSrcDesc1->next_desc_addr = src_array_addr;
	set_desc_startaddr(LargeSrcDesc1, src_addr, FLOW_LARGE);
	
	LargeSrcDesc1->cfg = 0x7905; 
	set_desc_xcount(LargeSrcDesc1, count, FLOW_LARGE);
	set_desc_xmodify(LargeSrcDesc1, 2 , FLOW_LARGE);
	set_desc_ycount(LargeSrcDesc1, 0, FLOW_LARGE);
	set_desc_ymodify(LargeSrcDesc1, 0, FLOW_LARGE);

	DMA_DBG ("End of setting the first source descriptor \n ");

	 add_descriptor(LargeSrcDesc2, CH_MEM_STREAM0_SRC, FLOW_LARGE);
	LargeSrcDesc2->next_desc_addr = src_array_addr;
	set_desc_startaddr(LargeSrcDesc2, src_addr2, FLOW_LARGE);
	LargeSrcDesc2->cfg = 0x7905; // DI_EN Enabled
	set_desc_xcount(LargeSrcDesc2, count2 , FLOW_LARGE);
	set_desc_xmodify(LargeSrcDesc2, 2 , FLOW_LARGE);
	set_desc_ycount(LargeSrcDesc2, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeSrcDesc2, 0 , FLOW_LARGE);

	DMA_DBG ("End of setting the Second  source descriptor \n ");

	 add_descriptor(LargeSrcDesc3, CH_MEM_STREAM0_SRC, FLOW_LARGE);
	set_desc_startaddr(LargeSrcDesc3, src_addr2, FLOW_LARGE);
	LargeSrcDesc3->cfg = 0x0985; // DI_EN Enabled
	set_desc_xcount(LargeSrcDesc3, count2 , FLOW_LARGE);
	set_desc_xmodify(LargeSrcDesc3, 2 , FLOW_LARGE);
	set_desc_ycount(LargeSrcDesc3, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeSrcDesc3, 0 , FLOW_LARGE);

	DMA_DBG ("End of setting the addtowait  source descriptor \n ");

	add_descriptor(LargeDestDesc1, CH_MEM_STREAM0_DEST, FLOW_LARGE);
	LargeDestDesc1->next_desc_addr = dest_array_addr;
	set_desc_startaddr(LargeDestDesc1, dest_addr, FLOW_LARGE);
	LargeDestDesc1->cfg = 0x79D7; // DI_EN Enabled 
	set_desc_xcount(LargeDestDesc1, count/2 , FLOW_LARGE);
	set_desc_xmodify(LargeDestDesc1, 2 , FLOW_LARGE);
	set_desc_ycount(LargeDestDesc1, 2 , FLOW_LARGE);
	set_desc_ymodify(LargeDestDesc1, 2 , FLOW_LARGE);

	DMA_DBG ("End of setting the Second  source descriptor \n ");
	

	 add_descriptor(LargeDestDesc2, CH_MEM_STREAM0_DEST, FLOW_LARGE);
	LargeDestDesc2->next_desc_addr = dest_array_addr;
	set_desc_startaddr(LargeDestDesc2, dest_addr2, FLOW_LARGE);
	LargeDestDesc2->cfg = 0x79D7; // DI_EN Enabled
	set_desc_xcount(LargeDestDesc2, count2/2 , FLOW_LARGE);
	set_desc_xmodify(LargeDestDesc2, 2 , FLOW_LARGE);
	set_desc_ycount(LargeDestDesc2, 2 , FLOW_LARGE);
	set_desc_ymodify(LargeDestDesc2, 2 , FLOW_LARGE);

	DMA_DBG ("End of setting the addtowait  source descriptor \n ");
	DMA_DBG(" End of Descriptor Creation  - large \n");
	
	 add_descriptor(LargeDestDesc2, CH_MEM_STREAM0_DEST, FLOW_LARGE);
	set_desc_startaddr(LargeDestDesc3, dest_addr2, FLOW_LARGE);
	LargeDestDesc3->cfg = 0x09D7; // DI_EN Enabled
	set_desc_xcount(LargeDestDesc3, count2/2 , FLOW_LARGE);
	set_desc_xmodify(LargeDestDesc3, 2 , FLOW_LARGE);
	set_desc_ycount(LargeDestDesc3, 2 , FLOW_LARGE);
	set_desc_ymodify(LargeDestDesc3, 2 , FLOW_LARGE);

	ch_src = request_dma(CH_MEM_STREAM0_SRC,  "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST, "memdma0_dest", testcallback); 

	DMA_DBG(" End of request DMA  - large\n");

	src_array_addr = (unsigned long) LargeSrcDesc1;


	set_dma_nextdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);

	DMA_DBG(" large : After Setting the next descriptor pointer for source \n");

	dest_array_addr = (unsigned long) LargeDestDesc1;



	set_dma_nextdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

	DMA_DBG(" large : After Setting the next descriptor pointer for dest \n");

	

	set_dma_config(CH_MEM_STREAM0_SRC, LargeSrcDesc1->cfg);

	set_dma_config(CH_MEM_STREAM0_DEST, LargeDestDesc1->cfg);

//	printk(" DMA Config for dest1 is   %x\n", dma_ch[ch_dest].regs->cfg);
	printk(" DMA Config for dest1 is   \n");

	DMA_DBG("End of Enabling the DMA   \n");

	DMA_DBG("End of Tranfer   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("End of Function   \n");
	return ESUCCESS;

}
/* Test program , to test the Large descriptor list With 1D-2D  */
int dma_m2m_testLarge1D2D(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2)
{
	unsigned long ch_src, ch_dest, src_array_addr, dest_array_addr;

	DMA_DBG(" In the Large Model-1D2D  \n");


	// Create the Array of descriptors

	src_array_addr = (unsigned long) (&(LargeSrcDesc[1])); 
	LargeSrcDesc[0].next_desc_addr = src_array_addr;
	LargeSrcDesc[0].start_addr = src_addr;
	LargeSrcDesc[0].cfg = 0x7985;
	LargeSrcDesc[0].x_count = count;
	LargeSrcDesc[0].x_modify = 2;
	LargeSrcDesc[0].y_count = 0;
	LargeSrcDesc[0].y_modify = 0;
	
	src_array_addr = (unsigned long)  (&(LargeSrcDesc[0]));
	LargeSrcDesc[1].next_desc_addr = src_array_addr;
	LargeSrcDesc[1].start_addr = src_addr2;
	LargeSrcDesc[1].cfg = 0x0985;
	LargeSrcDesc[1].x_count = count2;
	LargeSrcDesc[1].x_modify = 2;
	LargeSrcDesc[1].y_count = 0;
	LargeSrcDesc[1].y_modify = 0;

	dest_array_addr = (unsigned long) (&(LargeDestDesc[1]));
	LargeDestDesc[0].next_desc_addr = dest_array_addr;
	LargeDestDesc[0].start_addr = dest_addr ;
	LargeDestDesc[0].cfg = 0x7997;
	LargeDestDesc[0].x_count = count/4;
	LargeDestDesc[0].x_modify = 2;
	LargeDestDesc[0].y_count = 4;
	LargeDestDesc[0].y_modify = 25;
	
	dest_array_addr = (unsigned long)(& (LargeDestDesc[0]));
	LargeDestDesc[1].next_desc_addr = dest_array_addr;
	LargeDestDesc[1].start_addr = dest_addr2 ;
	LargeDestDesc[1].cfg = 0x0997;
	LargeDestDesc[1].x_count = count2/4;
	LargeDestDesc[1].x_modify = 2;
	LargeDestDesc[1].y_count = 4;
	LargeDestDesc[1].y_modify = 25;

	DMA_DBG(" End of Descriptor Creation  - large \n");
	
	ch_src = request_dma(CH_MEM_STREAM0_SRC, "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST, "memdma0_dest", testcallback); 
	
	DMA_DBG(" End of request DMA  - large\n");

	src_array_addr = (unsigned long) (&(LargeSrcDesc[0]));
	set_dma_nextdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);

	DMA_DBG(" large : After Setting the next descriptor pointer for source \n");

	dest_array_addr = (unsigned long) &(LargeDestDesc[0]);

	set_dma_nextdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

	DMA_DBG(" large : After Setting the next descriptor pointer for dest \n");

	

	set_dma_config(CH_MEM_STREAM0_SRC, LargeSrcDesc[0].cfg);


	set_dma_config(CH_MEM_STREAM0_DEST, LargeDestDesc[0].cfg);

	//printk(" DMA Config for dest is   %x\n", dma_ch[ch_dest].regs->cfg);
	printk(" DMA Config for dest is   \n");

	DMA_DBG("End of Tranfer   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

	DMA_DBG("End of Function   \n");
	return ESUCCESS;

}



/* Test function for testing the Large Descriptor list with add_descriptor function used  */

int dma_m2m_testLarge_queue(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2,
		unsigned long src_addr3, unsigned long dest_addr3,
		unsigned char data_size3, unsigned short count3)
{
	/* unsigned short irq_stat_src, irq_stat_dest; */
	unsigned long ch_src, ch_dest, src_array_addr, dest_array_addr;
	dmasglarge_t      *LargeSrcDesc1, *LargeSrcDesc2;
	dmasglarge_t      *LargeDestDesc1, *LargeDestDesc2;
	dmasglarge_t      *LargeSrcDesc3, *LargeDestDesc3;

	printk(" In the Large Model  \n");

	src_array_addr = dest_array_addr = 0x0;

	LargeSrcDesc1 = create_descriptor(FLOW_LARGE);
	LargeSrcDesc2 = create_descriptor(FLOW_LARGE);
	LargeSrcDesc3 = create_descriptor(FLOW_LARGE);

	LargeDestDesc1 = create_descriptor(FLOW_LARGE);
	LargeDestDesc2 = create_descriptor(FLOW_LARGE);
	LargeDestDesc3 = create_descriptor(FLOW_LARGE);
#if DEBUG
	DMA_DBG ("src Data locations are : \n src1 %t %x \n src2 %t %x \n src3 %t %x \n ", src_addr, src_addr2, src_addr3);
	DMA_DBG ("Dest Data locations are : \n dest1 %t %x \n dest2 %t %x \n dest3 %t %x \n ", dest_addr, dest_addr2, dest_addr3);
	DMA_DBG ("src descr locations are : \n src_descr1 %t %x \n src_descr2 %t %x \n src_descr3 %t %x \n ", LargeSrcDesc1, LargeSrcDesc2, LargeSrcDesc3);
	DMA_DBG ("Dest descr locations are : \n dest_descr1 %t %x \n dest_descr2 %t %x \n dest_descr3 %t %x \n ", LargeDestDesc1, LargeDestDesc2, LargeDestDesc3);
#endif

	add_descriptor(LargeSrcDesc1, CH_MEM_STREAM0_SRC, FLOW_LARGE);
	set_desc_startaddr(LargeSrcDesc1, src_addr, FLOW_LARGE);
	LargeSrcDesc1->cfg = 0x7985; // DI_EN Enabled
	set_desc_xcount(LargeSrcDesc1, count, FLOW_LARGE);
	set_desc_xmodify(LargeSrcDesc1, 2 , FLOW_LARGE);
	set_desc_ycount(LargeSrcDesc1, 0, FLOW_LARGE);
	set_desc_ymodify(LargeSrcDesc1, 0, FLOW_LARGE);

//	printk ("End of setting the first source descriptor \n ");

	 add_descriptor(LargeSrcDesc2, CH_MEM_STREAM0_SRC, FLOW_LARGE);
	set_desc_startaddr(LargeSrcDesc2, src_addr2, FLOW_LARGE);
	LargeSrcDesc2->cfg = 0x7985; // DI_EN Enabled
	set_desc_xcount(LargeSrcDesc2, count2 , FLOW_LARGE);
	set_desc_xmodify(LargeSrcDesc2, 2 , FLOW_LARGE);
	set_desc_ycount(LargeSrcDesc2, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeSrcDesc2, 0 , FLOW_LARGE);

//	printk ("End of setting the Second  source descriptor \n ");

	add_to_wait_descriptor(LargeSrcDesc3, CH_MEM_STREAM0_SRC, FLOW_LARGE);
	set_desc_startaddr(LargeSrcDesc3, src_addr3, FLOW_LARGE);
	LargeSrcDesc3->cfg = 0x0985; // DI_EN Enabled
	set_desc_xcount(LargeSrcDesc3, count3 , FLOW_LARGE);
	set_desc_xmodify(LargeSrcDesc3, 2 , FLOW_LARGE);
	set_desc_ycount(LargeSrcDesc3, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeSrcDesc3, 0 , FLOW_LARGE);

//	printk ("End of setting the wait  source descriptor \n ");

	add_descriptor(LargeDestDesc1, CH_MEM_STREAM0_DEST, FLOW_LARGE);
	set_desc_startaddr(LargeDestDesc1, dest_addr, FLOW_LARGE);
	LargeDestDesc1->cfg = 0x7987; // DI_EN Enabled 
	set_desc_xcount(LargeDestDesc1, count , FLOW_LARGE);
	set_desc_xmodify(LargeDestDesc1, 2 , FLOW_LARGE);
	set_desc_ycount(LargeDestDesc1, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeDestDesc1, 0 , FLOW_LARGE);

//	printk ("End of setting the Second  source descriptor \n ");
	
	 add_descriptor(LargeDestDesc2, CH_MEM_STREAM0_DEST, FLOW_LARGE);
	set_desc_startaddr(LargeDestDesc2, dest_addr2, FLOW_LARGE);
	LargeDestDesc2->cfg = 0x7987; // DI_EN Enabled
	set_desc_xcount(LargeDestDesc2, count2 , FLOW_LARGE);
	set_desc_xmodify(LargeDestDesc2, 2 , FLOW_LARGE);
	set_desc_ycount(LargeDestDesc2, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeDestDesc2, 0 , FLOW_LARGE);


//	printk(" End of Second Descriptor creation  - large \n");
	
	add_to_wait_descriptor(LargeDestDesc3, CH_MEM_STREAM0_DEST, FLOW_LARGE);
	set_desc_startaddr(LargeDestDesc3, dest_addr3, FLOW_LARGE);
	LargeDestDesc3->cfg = 0x0987; // DI_EN Enabled
	set_desc_xcount(LargeDestDesc3, count3 , FLOW_LARGE);
	set_desc_xmodify(LargeDestDesc3, 2 , FLOW_LARGE);
	set_desc_ycount(LargeDestDesc3, 0 , FLOW_LARGE);
	set_desc_ymodify(LargeDestDesc3, 0 , FLOW_LARGE);

//	printk(" End of wait  Descriptor creation  - large \n");

	ch_src = request_dma(CH_MEM_STREAM0_SRC, "memdma0_src", testcallback); 
	ch_dest = request_dma(CH_MEM_STREAM0_DEST,  "memdma0_dest", testcallback); 

//	printk(" End of request DMA  - large\n");

	src_array_addr = (unsigned long) LargeSrcDesc1;


	set_dma_nextdesc_addr(CH_MEM_STREAM0_SRC, src_array_addr);

//	printk(" large : After Setting the next descriptor pointer for source \n");

	dest_array_addr = (unsigned long) LargeDestDesc1;


	set_dma_nextdesc_addr(CH_MEM_STREAM0_DEST, dest_array_addr);

//	printk(" large : After Setting the next descriptor pointer for dest \n");

	
	set_dma_config(CH_MEM_STREAM0_SRC, LargeSrcDesc1->cfg);
//	printk(" DMA Config for src1 is   %x\n", dma_ch[ch_src].regs->cfg);


	set_dma_config(CH_MEM_STREAM0_DEST, LargeDestDesc1->cfg);

//	printk(" DMA Config for dest1 is   %x\n", dma_ch[ch_dest].regs->cfg);
	printk(" DMA Config for dest1 is   \n");

//	printk("End of Tranfer   \n");

	freedma(CH_MEM_STREAM0_SRC);
	freedma(CH_MEM_STREAM0_DEST);

//	printk("End of Function   \n");
	return ESUCCESS;

}


/* This Test function is not used 
*/

/* The following function is to be done  */ 

int dma_m2p(unsigned int channel, unsigned long start_addr, char dir, char data_size, unsigned short count)
{
	return DMA_SUCCESS;
}

int dma_m2m(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2,
		unsigned long src_addr3, unsigned long dest_addr3, 
		unsigned char data_size3, unsigned short count3)
{
	int return_value = 0;

	// return_value = dma_m2m_test_stop(src_addr, dest_addr, data_size, count,0);
	// return_value = dma_m2m_test_auto(src_addr, dest_addr, data_size, count,0);
	// return_value = dma_m2m_test_auto1D_2D(src_addr, dest_addr, data_size, count,0);

	/* After the execution of This function kernel is hanging first time, 
	if we restart the VDSP and load the run it again, then we are not i
        getting any problem  - We have to lookinto this - TODO*/
	//return_value = dma_m2m_testSmall(src_addr, dest_addr, data_size, count, src_addr2, dest_addr2, data_size2, count2);

	// return_value = dma_m2m_testSmall_dynamic(src_addr, dest_addr, data_size, count, src_addr2, dest_addr2, data_size2, count2);

	// return_value = dma_m2m_testArray(src_addr, dest_addr, data_size, count, src_addr2, dest_addr2, data_size2, count2);
	return_value = dma_m2m_testLarge(src_addr, dest_addr, data_size, count, src_addr2, dest_addr2, data_size2, count2);
	// return_value = dma_m2m_testLarge_queue(src_addr, dest_addr, data_size, count, src_addr2, dest_addr2, data_size2, count2, src_addr3, dest_addr3, data_size3, count3);

	return return_value;
	//return 0;
}

unsigned char m2m_dma_test(unsigned long src_addr, unsigned long dest_addr, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, unsigned short count2,
		unsigned long src_addr3, unsigned long dest_addr3,unsigned short count3)
{
	// The count should be multiple of 4
	count &= (~0x3);

	memset((void *) dest_addr, 0, count);
	memset((void *) dest_addr2, 0, count);
	memset((void *) dest_addr3, 0, count);

	dma_m2m(src_addr, dest_addr, DATA_SIZE_8, count, src_addr2, dest_addr2, DATA_SIZE_8, count2, src_addr3, dest_addr3, DATA_SIZE_8, count3);

	if (memcmp((void *) src_addr, (void *) dest_addr, count))
		return 0;
	
	printk (" \n first \n ");
	/*
	if (memcmp((void *) src_addr2, (void *) dest_addr2, count2))
		return 0;

	printk (" \n Second \n ");
	if (memcmp((void *) src_addr3, (void *) dest_addr3, count3))
		return 0;
	printk (" \n third \n ");

	memset((void *) dest_addr, 0, count);
	dma_m2m(src_addr, dest_addr, DATA_SIZE_16, count >> 1);
	if (memcmp((void *) src_addr, (void *) dest_addr, count))
		return 0;
		
	memset((void *) dest_addr, 0, count);
	dma_m2m(src_addr, dest_addr, DATA_SIZE_32, count >> 2);
	if (memcmp((void *) src_addr, (void *) dest_addr, count))
		return 0;
		
	*/

	return 1;
}


void dma_test(void)
{
	int i;
	
	printk("MemDMA testing started\n");

	for (i = 0; i < TEST_TIMES; i++)
	{
		if (!m2m_dma_test((unsigned long) src, (unsigned long) dest, 
					BUF_SIZE, (unsigned long)src2, (unsigned long)dest2, BUF_SIZE, (unsigned long)src3, (unsigned long) dest3, BUF_SIZE))
			{	
				printk("MemDMA testing failed!, index=%d\n", i);
				return;
			}
	#ifdef PROG_MSG 
		if (!(i & 0xf))
			printk("MemDMA %d passed\n", i);
	#endif
	}

	printk("MemDMA testing passed\n");
	
}
