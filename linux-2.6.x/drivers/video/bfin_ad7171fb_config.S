/*****************************************************************************
**																			**
**	 Project Name: Frame Buffer Driver For uClinux for BF533	
**																			**
******************************************************************************

(C) Copyright 2005 - Rrap Softwares Pvt. Ltd.

File Name:		bfin_ad7171fb_config.S		

Date Modified:		6th Jan 2005	

Hardware:		ADSP-BF533 EZ-KIT Board

Special Connections:  	None

Purpose:		For video driver this file provide functions for 
			Configuring various devices for video driver purpose. 
			It defines some data buffers also.		
		
				
******************************************************************************/


#include <asm/board/defBF533.h>

#define INTR_PERIOD 400
#define NUM_OF_VOUT_FRAMES 2
#define REAL_DATA 1
#define UPDATE 1

#define LINE_LENGTH_IN_BYTES 1440
#define LINE_LENGTH_IN_PIXELS 360
#define BYTES_PER_PIXEL         4
/***Definitions for AD7171***/
/*************************************************/
/*************************************************/
#define RST_7171 0x2       // encoder reset bit #2 in flashA portA
#define CFG_FLASH 0x1      // configure flash flag
#define en_async_mem 0xf   // field in asynch mem ctrl reg

#define flashA_sram 0x20240000  // base addr
#define flashA_csio 0x20270000  // base addr
#define portA_data_out 0x04     // offset
#define portB_data_out 0x05     // offset
#define portA_data_dir 0x06     // offset
#define portB_data_dir 0x07     // offset


.global _config_dma;
.global dma_set_next_buf;

.type _config_dma, STT_FUNC ;
.global _Flash_Setup_ADV_Reset;
.type _Flash_Setup_ADV_Reset, STT_FUNC ;

.section .data;
_dma_descriptor:
.space 12
._dma_descriptor.end:
.global _dma_descriptor;
.type _dma_descriptor, STT_OBJECT ;

.section .text;
_config_dma:
.align 4
	[--sp] = p0;	
	P0.L = _dma_descriptor;
	P0.H = _dma_descriptor;
	
	r1 = p0;
	
	w[p0] = r1.l; // NDPL - set to self
	p0 += 2;
	w[p0] = R0.l; // SAL
	p0 += 2;
	w[p0] = R0.h; // SAH
	
	P0.L = lo(DMA0_NEXT_DESC_PTR);
	P0.H = hi(DMA0_NEXT_DESC_PTR);
	[P0] = R1; // next desc ptr 
	
	//DMA0_CONFIG
	// auto buffer, DI_SEL, 2d, 8bit, read
	R0.L = 0x6390;		
	
	P0.L = lo(DMA0_CONFIG);
	P0.H = hi(DMA0_CONFIG);	
	W[P0] = R0.L;						
	
	//DMA0_X_COUNT
	R0.L = 0x06B4;		// 1716
	P0.L = lo(DMA0_X_COUNT);
	P0.H = hi(DMA0_X_COUNT);	
	W[P0] = R0.L;						
		
	//DMA0_X_MODIFY
	R0.L = 0x0001;					
	P0.L = lo(DMA0_X_MODIFY);
	P0.H = hi(DMA0_X_MODIFY);	
	W[P0] = R0.L;						

	//DMA0_Y_COUNT
	R0.L = 0x020D;		// 525
	P0.L = lo(DMA0_Y_COUNT);
	P0.H = hi(DMA0_Y_COUNT);	
	W[P0] = R0.L;						
		
	//DMA0_Y_MODIFY
	R0.L = 0x0001;					
	P0.L = lo(DMA0_Y_MODIFY);
	P0.H = hi(DMA0_Y_MODIFY);	
	W[P0] = R0.L;
	
	
	p0 = [sp++];
		
	RTS;
	
config_dma.END:

.type dma_set_next_buf, STT_FUNC ;
dma_set_next_buf :

	[--sp] = p0;	
	P0.L = _dma_descriptor;
	P0.H = _dma_descriptor;
	
	r1 = p0;
	
	p0 += 2;
	w[p0] = R0.l; // SAL
	p0 += 2;
	w[p0] = R0.h; // SAH

	p0 = [sp++];
	RTS;

dma_set_next_buf.END:


/*Routine for Configuring PPI*/

.global _config_ppi;
.type _config_ppi, STT_FUNC ;
_config_ppi:


        /* PPI Control Register:  Output direction, 656 mode.   */

        P0.L = PPI_CONTROL & 0xffff;
        P0.H = PPI_CONTROL >> 16;
        R0.L = PORT_DIR;
        W[P0] = R0.L;

        RTS;

_config_ppi.END:
/**********From here things specific to video starts**************/

         /******Routine for Configuring IC AD7171******/


_Flash_Setup_ADV_Reset:

        //Initialize flash A csio regs (port A and B).

    //Clear data registers.
        P1.L = lo(flashA_csio) + portA_data_out;
        P1.H = hi(flashA_csio);
        R0 = 0x0;
        W[P1] = R0;
        ssync;

    //Direction control registers.
        P1.H = hi(flashA_csio);
        P1.L = lo(flashA_csio) + portA_data_dir;
        R0 = 0xFFFF(Z);
        W[P1] = R0;                      //Set direction to output.
        ssync;



        //De-assert reset from ADP7171 device (flashA portA bit 2)

        P1.H = hi(flashA_csio);
        P1.L = lo(flashA_csio) + portA_data_out;
        R0 = B[P1] (z);
        bitset(R0,RST_7171);     // de-assert reset of the encoder device
        B[P1] = R0;



        RTS;

Flash_Setup_ADV_Reset.END:

/******COLOR PATTERNS AND OTHER DATA BUFFERS*******/
.section .data

.global _rgb_buffer;
.type _rgb_buffer, STT_OBJECT ;
_rgb_buffer:
.byte4 0;
.global _cycrcbbuffer ;
_cycrcbbuffer:
.byte4 0;



// bit mappin.extern _Ntsc;g of line type for PAL, 1 Vblank line 0 active line
// 0,   32,  64,  96
// 128, 160, 192, 224
// 256, 288, 320, 352
// 384, 416, 448, 480
// 512, 544, 576, 608


 PalLineMap:

.byte4 0x007FFFFF;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0xFF800000;
.byte4 0x0000FFFF;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0xFFFF0000;
.global PalLineMap;

// bit mapping of line type for NTSC, 1 Vblank line 0 active line
// 0,   32,  64,  96
// 128, 160, 192, 224
// 256, 288, 320, 352
// 384, 416, 448, 480
// 512
// SAV, EAV for active video   in field 1
// SAV, EAV for vertical blank in field 1
// SAV, EAV for active video   in field 2
// SAV, EAV for vertical blank in field 2


// black
// blue
// red
// magenta
// green
// cyan
// yellow
// white

 ColorBarTableOrig:

.byte4   0x80108010;
.byte4   0xF0296E29;
.byte4   0x5A51F051;
.byte4   0xCA6ADE6A;
.byte4   0x36912291;
.byte4   0xA6AA10AA;
.byte4   0x10D292D2;
.byte4   0x80EB80EB;
.global ColorBarTableOrig;


// Need the line buffers in l1 data
.section .data_l1,"aw",@progbits;
RGBLineCache:
.space 1440 ;


YCrCbLine:
.space 1440;

.global RGBLineCache;
.global YCrCbLine;

.global _SystemCodeMap;
_SystemCodeMap:
.byte4 0xFF000080;
.byte4 0xFF00009D;
.byte4 1;
.byte4 0xFF0000AB;
.byte4 0xFF0000B6;
.byte4 0;
.byte4 0xFF0000C7;
.byte4 0xFF0000DA;
.byte4 1;
.byte4 0xFF0000EC;
.byte4 0xFF0000F1;
.byte4 0;


.global _NtscLineMap ;
 _NtscLineMap:
.byte4 0x0007FFFF;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x03FFFF00;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00000000;
.byte4 0x00010000;

.global  _ColorBarTable;
_ColorBarTable:
/////BBGG00RR
.byte4   0x00000000;    
.byte4   0xff000000;  
.byte4   0x000000ff;  
.byte4   0xff0000ff;
.byte4   0x00ff0000;  
.byte4   0xffff0000;  
.byte4   0x00ff00ff;  
.byte4   0xffff00ff;


.section .text.l1, "ax", @progbits;
.align 4;

// Parameters : R0 : destination buffer - YCrCb data buffer
//              R1 : source buffer      - RGB   data buffer
//              When calling from "C", first parameter is YCrCb buffer pointer
//                                     second parameter is RGB buffer pointer
_NtscVideoOutFrameBuffInit:

        [--sp] = rets;
        [--sp] = (r7:3, p5:0);
        [--sp] = astat;


//      P0.h = 0x0000;
//      P0.l = 0x0000;
        // R0 has destination buffer
        // R1 has source RGB buffer
        P0.h = _rgb_buffer;
        P0.l = _rgb_buffer;
        [P0] = R1;
        R2 = 1440;
        P0.h = _cycrcbbuffer;
        P0.l = _cycrcbbuffer;
        R1 = R1 + R2;
        [P0] = R1;
        P0 = R0;


        // load base of system code map in P5
        P5.h = _SystemCodeMap;
        P5.l = _SystemCodeMap;

        // load base of ntsc line map in P1
        P4.h = _NtscLineMap;
        P4.l = _NtscLineMap;

        //number of frames ->  NUM_FRAMES
        p2 = NUM_OF_VOUT_FRAMES;
        LSETUP(ntscoutputfieldstart_init, ntscoutputfieldend_init) LC0 = P2;

ntscoutputfieldstart_init:
        P2.h = _cycrcbbuffer;
        P2.l = _cycrcbbuffer;
        R0 = [P2];
        P2.h = _rgb_buffer;
        P2.l = _rgb_buffer;
        [P2] = R0;

        r0 = 1;                 //line #1

        //number of lines ->  525
        P2 = 262;
        LSETUP(ntscoutputlinestart_init, ntscoutputlineend_init) LC1 = P2;
ntscoutputlinestart_init:
        call NtscOutputLine_init;
ntscoutputlineend_init:
        r0 += 1;                //increment line number
ntscoutputfieldend_init:
        nop;

        astat = [sp++];
        (r7:3, p5:0) = [sp++];
        rets = [sp++];
        rts;
._NtscVideoOutFrameBuffInit.end:
.global _NtscVideoOutFrameBuffInit ;
.type _NtscVideoOutFrameBuffInit, STT_FUNC ;

NtscOutputLine_init:
        [--sp] = rets;
        [--sp] = lc0;
        [--sp] = lb0;
        [--sp] = lt0;
        [--sp] = lc1;
        [--sp] = lb1;
        [--sp] = lt1;


// determine if this is a VBlank line
        R1 = R0>>5;             // get offset (divide line number by 32)
        R1 = R1<<2;             // multiply by 4 for word access
        P2 = R1;                // move computed offset to P register
        R3 = 0x1F;              // prepare mask
        nop;nop;
        P1 = P4 + P2;           // add offset to P1
        R2 = [P1];              // get line mask word
        R1 = R0 & R3;           // get bit offset in line mask word
        R2 >>= R1;              // shift to get flag in bit 0
        CC = BITTST(R2 , 0); // test bit 0
        R2 = 0;                 // default add 0 to P3
        R3 = 12;                // prepare to add 8 to P3
        if CC R2 = R3;          // if CC this is vertical blanking so add 8 to P3
        P2 = R2;                // move offset in P2
// see below for final offset in P3

// determine which field we are outputing
        R1 = 266;               // line number where we are changing field (266)
        CC = R1<R0;             // test line to see if this field 1 or 2
        R3 = 24;                // offset to add to P3 if this is field 2
        P3 = P5 + P2;           // finally add to P3
        R2 = 0;                 // by default don't offset P3
        if CC R2 = R3;          // if CC this is field 2

        R1 = 3;                 // line number where we are changing field (3)
        CC = R0<R1;             // test line to see if this field 1 or 2
        if CC R2 = R3;          // if CC this is field 2

        P2 = R2;                // move offset in P2
        nop;nop;nop;
        P3 = P3 + P2;           // finally add to P3
// **************** OUTPUT EAV ******************

        R1 = [P3 + 4];          // load EAV code , see down for storage
#if 0
        [P0++] = R1;            // store EAV in FIFO
#else
        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
        b[p0++] = r1;
#endif
// ***************** OUTPUT HORIZONTAL BLANKING ***************
// store blank data information
        R1.h = 0x8010;
        R1.l = 0x8010;

//number of sample to output 134/2
#if 0
        P2 = 67;
        LSETUP(ntscoutputblank1, ntscoutputblank1) LC0 = P2;
ntscoutputblank1:
        [P0++] = R1;
#else
        P2 = 67;
        LSETUP(ntscoutputblank1_s, ntscoutputblank1_e) LC0 = P2;
ntscoutputblank1_s:
        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
ntscoutputblank1_e:     b[p0++] = r1;
#endif

// **************** OUTPUT SAV ******************
        R2 = [P3 + 8];      // load video output flag
        R1 = [P3];          // load SAV code, see down for storage
        CC = BITTST(R2, 0); // test bit 0 to know if we have to output some video
#if 0
        [P0++] = R1;        // output SAV in FIFO
#else
        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
        b[p0++] = r1;
#endif
        IF CC JUMP NtscOutputColorBarLine_init;

// ***************** OUTPUT EMPTY HORIZONTAL DATA ***************
// store blanking information
        R1.h = 0x8010;
        R1.l = 0x8010;

//number of sample to output 720/2
#if 0
        P2 = 360;
        LSETUP(ntscoutputblank2, ntscoutputblank2) LC0 = P2;
ntscoutputblank2:
        [P0++] = R1;
#else
        P2 = 360;
        LSETUP(ntscoutputblank2_s, ntscoutputblank2_e) LC0 = P2;
ntscoutputblank2_s:
        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
ntscoutputblank2_e:     b[p0++] = r1;
#endif

//      r1  = [sp++];
        lt1 = [sp++];
        lb1 = [sp++];
        lc1 = [sp++];
        lt0 = [sp++];
        lb0 = [sp++];
        lc0 = [sp++];
        rets = [sp++];
        rts;

NtscOutputColorBarLine_init:
#ifdef REAL_DATA
// ***************** OUTPUT REFERENCE COLOR HORIZONTAL DATA **************
        // R0 has the line number
        // P0 has the destination buffer

        P2.L = _rgb_buffer;
        P2.H = _rgb_buffer;
        P3 = [P2];
        P1 = 2880; // 360 * 4 * 2 for alternate lines
        P3 = P3 + P1;
        [P2] = P3;
        // P3 now has the source rgb line
        [--sp]=(P5:4);
        [--SP]=(R7:0);

        P2 = 360;
        LSETUP(ntsclinestart_init, ntsclineend_init) LC0 = P2;
ntsclinestart_init:
        // now convert to YCrCb
        R3 = 0xff;
        R0 = [p3++];
        R1 = R0 >> 16;
        R1 = R1 & R3;
        R2 = R0 >> 24;
        R2 = R2 & R3;
        R0 = R0 & R3;
        [--sp] = P0;
        [--sp] = P3;
        sp += -12;
        CALL _rgb2crcb; // conversion every pixel
        sp += 12;
        p3 = [sp++];
        p0 = [sp++];
        // result is in R0

        R1 = R0;
//number of sample to output (720/8)/2
        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
ntsclineend_init:b[p0++] = r1;
        (R7:0)=[SP++];
        (P5:4)=[sp++];


        lt1 = [sp++];
        lb1 = [sp++];
        lc1 = [sp++];
        lt0 = [sp++];
        lb0 = [sp++];
        lc0 = [sp++];
        rets = [sp++];
        rts;
#else
// ***************** OUTPUT REFERENCE COLOR HORIZONTAL DATA **************
// get pointer to color bar table
        P3.h = _ColorBarTable;
        P3.l = _ColorBarTable;

//number of color bar
        P2.L = 0x0008;
        P2.H = 0x0000;
        LSETUP(ntsccolorbarstart, ntsccolorbarend) LC0 = P2;
ntsccolorbarstart:
#if 0
// get next color bar data
        R1 = [P3++];
#else
        [--sp]=R0;
        [--SP]=(R7:2);
        [--sp]=(P5:0);
        // now convert to YCrCb
        R3 = 0xff;
        R0 = [p3];
        R1 = R0 >> 16;
        R1 = R1 & R3;
        R2 = R0 >> 24;
        R2 = R2 & R3;
        R0 = R0 & R3;
        sp += -12;
        CALL _rgb2crcb; // conversion only once per color change
        sp += 12;
        // result is in R0

        R1 = R0;
        (P5:0)=[sp++];
        (R7:2)=[SP++];
        r0 = [sp++];
        P3 += 4;
#endif
//number of sample to output (720/8)/2
#if 0
        P2 = 45;
        LSETUP(ntscoutputcolorbardata, ntscoutputcolorbardata) LC1 = P2;
ntscoutputcolorbardata:
        [P0++] = R1;
#else
        P2 = 45;
        LSETUP(ntscoutputcolorbardata_s, ntscoutputcolorbardata_e) LC1 = P2;
ntscoutputcolorbardata_s:
        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
ntscoutputcolorbardata_e:b[p0++] = r1;
#endif

 ntsccolorbarend:
NOP;

        lt1 = [sp++];
        lb1 = [sp++];
        lc1 = [sp++];
        lt0 = [sp++];
        lb0 = [sp++];
        lc0 = [sp++];
        rets = [sp++];
        rts;

#endif

_NtscVideoOutFrameBuffInit.END:


.section .text.l1, "ax", @progbits;

// Use DMA to do a mem copy
// R2 has the size
// R0 has destination
// R1 has source
// Do not return until the DMA is complete
_DmaMemCpy:
	// save registers from the caller
	[--sp] = p0;

	// MDMA requires a pair, we will use '0'
	// ideally we should check what is available and
	// select the other putting traffic in round robin
	// if we select the second pair
	
	// first configure the source	
	P0.L = lo(MDMA_S0_START_ADDR);
	P0.H = hi(MDMA_S0_START_ADDR);	
	[P0] = R1;							
	
	
	//DMA0_X_COUNT
	P0.L = lo(MDMA_S0_X_COUNT);
	P0.H = hi(MDMA_S0_X_COUNT);	
	W[P0] = R2.L;						
		
	//DMA0_X_MODIFY
	R1.L = 0x0001;					
	P0.L = lo(MDMA_S0_X_MODIFY);
	P0.H = hi(MDMA_S0_X_MODIFY);	
	W[P0] = R1.L;						

	//DMA0_CONFIG
	// stop mode, 1d, 8bit, read
	// FLOW : 0x0
	// NDSIZE : 0x1
	//
	R1.L = 0x0001;		
	P0.L = lo(MDMA_S0_CONFIG);
	P0.H = hi(MDMA_S0_CONFIG);	
	W[P0] = R1.L;						

	// now configure the destination
	P0.L = lo(MDMA_D0_START_ADDR);
	P0.H = hi(MDMA_D0_START_ADDR);	
	[P0] = R0;							
	
	
	//DMA0_X_COUNT
	P0.L = lo(MDMA_D0_X_COUNT);
	P0.H = hi(MDMA_D0_X_COUNT);	
	W[P0] = R2.L;						
		
	//DMA0_X_MODIFY
	R0.L = 0x0001;					
	P0.L = lo(MDMA_D0_X_MODIFY);
	P0.H = hi(MDMA_D0_X_MODIFY);	
	W[P0] = R0.L;						

	//DMA0_CONFIG
	// stop mode, 1d, 8bit, write
	// FLOW : 0x0
	// NDSIZE : 0x1
	// DIR : 0x1
	R0.L = 0x0002;		
	
	P0.L = lo(MDMA_D0_CONFIG);
	P0.H = hi(MDMA_D0_CONFIG);	
	W[P0] = R0.L;						
	ssync;
	
	// now poll to see when dma completes
	P0.L = lo(MDMA_D0_IRQ_STATUS);
	P0.H = hi(MDMA_D0_IRQ_STATUS);	
memcpy_dma_wait :
	// wait for DMA_RUN bit to be 0 - signals completion
	R2 = W[P0] (Z);
	CC = BITTST(R2 , 3); // test bit 3, DMA RUN
	
	if CC jump memcpy_dma_wait;
	
	// restore the call save registers
	p0 = [sp++];
	
	rts;
// end _DmaMemCpy


// similar to Init, but skips the "constant" sections
// Parameters : R0 : destination buffer - YCrCb perhaps DMA buffer
//              R1 : source buffer      - RGB   data buffer
//		When calling from "C", first parameter is YCrCb buffer pointer
//                                     second parameter is RGB buffer pointer
// Abstract   : Converts RGB to YCrCb suitable for AD7171
//              Uses L1 RAM to create a line copying source to L1
//              using memdma, processing in L1 and then
//              transfers the result to the final destination using MemDMA
_NtscVideoOutBuffUpdate:

	[--sp] = rets;
	[--sp] = (r7:3, p5:0);
	[--sp] = astat;


	// R0 has destination buffer
	// R1 has source RGB buffer
	P0.h = _rgb_buffer;
	P0.l = _rgb_buffer;
	[P0] = R1; 					// save into static variable
	R2 = 1440;
	P0.h = _cycrcbbuffer;		
	P0.l = _cycrcbbuffer;
	R1 = R1 + R2;				
	[P0] = R1;					// save into static variable
	P0 = R0;


	// load base of system code map in P5
	P5.h = _SystemCodeMap;
	P5.l = _SystemCodeMap;

	// load base of ntsc line map in P4
	P4.h = _NtscLineMap;
	P4.l = _NtscLineMap;

	//number of frames ->  NUM_FRAMES
	p2 = NUM_OF_VOUT_FRAMES;
	LSETUP(ntscoutputfieldstart, ntscoutputfieldend) LC0 = P2;

ntscoutputfieldstart:
	P2.h = _cycrcbbuffer;
	P2.l = _cycrcbbuffer;
	R0 = [P2];
	P2.h = _rgb_buffer;
	P2.l = _rgb_buffer;
	[P2] = R0;
	
	r0 = 1;			//line #1

	//number of lines ->  525
	P2 = 262; // interlaced, so we go through twice
	LSETUP(ntscoutputlinestart, ntscoutputlineend) LC1 = P2;
ntscoutputlinestart:
.ALIGN 4 ;
	call NtscOutputLine;
ntscoutputlineend:
	r0 += 1;		//increment line number
ntscoutputfieldend:
	nop;

	astat = [sp++];
	(r7:3, p5:0) = [sp++];
	rets = [sp++];
	rts;
  
// Routine : NtscOutputLine 
// Parameters : R0 : Line number
//              R1 : Offset in RGB Buffer
// Abstract : Output a NTSC line. 
NtscOutputLine:
	[--sp] = rets;
	[--sp] = lc0;
	[--sp] = lb0;
	[--sp] = lt0;
	[--sp] = lc1;
	[--sp] = lb1;
	[--sp] = lt1;

#ifdef SLOW_DOWN
	// slow down line output ... flicker reduces
	// ideally send line output to L1ram and do
	// a mem dma to transfer to real output
	[--sp] = P1;	
	P1.l = 0x0000;
	p1.h = 0x0100;
	LSETUP(WAIT_1, WAIT_2) LC0 = P1;
WAIT_1 : nop;
WAIT_2 : nop;
	p1 = [sp++];
	// end slow down
#endif // SLOW_DOWN

// determine if this is a VBlank line
	R1 = R0>>5;       	// get offset (divide line number by 32)
	R1 = R1<<2;       	// multiply by 4 for word access
	P2 = R1;          	// move computed offset to P register
	R3 = 0x1F;        	// prepare mask
	nop;nop;
	P1 = P4 + P2;     	// add offset to P1
	R2 = [P1];   		// get line mask word
	R1 = R0 & R3;     	// get bit offset in line mask word
	R2 >>= R1;        	// shift to get flag in bit 0
	CC = BITTST(R2 , 0); // test bit 0
	R2 = 0;           	// default add 0 to P3
	R3 = 12;           	// prepare to add 8 to P3
	if CC R2 = R3;    	// if CC this is vertical blanking so add 8 to P3
	P2 = R2;          	// move offset in P2
// see below for final offset in P3

// determine which field we are outputing
	R1 = 266;         	// line number where we are changing field (266)
	CC = R1<R0;       	// test line to see if this field 1 or 2
	R3 = 24;          	// offset to add to P3 if this is field 2
	P3 = P5 + P2;     	// finally add to P3
	R2 = 0;           	// by default don't offset P3
	if CC R2 = R3;    	// if CC this is field 2

	R1 = 3;           	// line number where we are changing field (3)
	CC = R0<R1;       	// test line to see if this field 1 or 2
	if CC R2 = R3;    	// if CC this is field 2

	P2 = R2;          	// move offset in P2
	nop;nop;nop;
	P3 = P3 + P2;     	// finally add to P3
// **************** OUTPUT EAV ******************
    
	R1 = [P3 + 4];  	// load EAV code , see down for storage
#if 0
	[P0++] = R1;    	// store EAV in FIFO
#else
#ifdef UPDATE
	p0 += 4;				// would it increment by 4
#else
	r2 = r1 >> 24;
	b[p0++] = r2;
	r2 = r1 >> 16;
	b[p0++] = r2;
	r2 = r1 >> 8;
	b[p0++] = r2;
	b[p0++] = r1;
#endif
#endif	
// ***************** OUTPUT HORIZONTAL BLANKING ***************
// store blank data information
	R1.h = 0x8010;
	R1.l = 0x8010;
  
//number of sample to output 134/2
#if 0
	P2 = 67; 
	LSETUP(ntscoutputblank1, ntscoutputBlank1) LC0 = P2;
ntscoutputblank1:
	[P0++] = R1;
#else
#ifdef UPDATE
	p2 = 268;
	p0 = p0 + p2; // would it multiply by 4?
#else
	P2 = 67; 
	LSETUP(ntscoutputblank1_s, ntscoutputblank1_e) LC0 = P2;
ntscoutputblank1_s:
	r2 = r1 >> 24;
	b[p0++] = r2;
	r2 = r1 >> 16;
	b[p0++] = r2;
	r2 = r1 >> 8;
	b[p0++] = r2;
ntscoutputblank1_e:	b[p0++] = r1;	
#endif
#endif	
  
// **************** OUTPUT SAV ******************
	R2 = [P3 + 8];      // load video output flag
	R1 = [P3];          // load SAV code, see down for storage
	CC = BITTST(R2, 0); // test bit 0 to know if we have to output some video
#if 0
	[P0++] = R1;        // output SAV in FIFO
#else
#ifdef UPDATE
	p0 += 4;				// would it increment by 4
#else
	r2 = r1 >> 24;
	b[p0++] = r2;
	r2 = r1 >> 16;
	b[p0++] = r2;
	r2 = r1 >> 8;
	b[p0++] = r2;
	b[p0++] = r1;	
#endif
#endif	
	IF CC JUMP NtscOutputColorBarLine;   
  
// ***************** OUTPUT EMPTY HORIZONTAL DATA ***************
// store blanking information
	R1.h = 0x8010;
	R1.l = 0x8010;
  
//number of sample to output 720/2
#if 0
	P2 = 360;
	LSETUP(ntscoutputblank2, ntscoutputblank2) LC0 = P2;
ntscoutputblank2:
	[P0++] = R1; 
#else
#ifdef UPDATE
	P2 = 1440; 
	P0 = p0 + P2;			// would it multiply by 4?
#else
	P2 = 360; 
	LSETUP(ntscoutputblank2_s, ntscoutputblank2_e) LC0 = P2;
ntscoutputblank2_s:
	r2 = r1 >> 24;
	b[p0++] = r2;
	r2 = r1 >> 16;
	b[p0++] = r2;
	r2 = r1 >> 8;
	b[p0++] = r2;	
ntscoutputblank2_e:	b[p0++] = r1;	
#endif
#endif	
    
//	r1  = [sp++];
	lt1 = [sp++];
	lb1 = [sp++];
	lc1 = [sp++];
	lt0 = [sp++];
	lb0 = [sp++];
	lc0 = [sp++];
	rets = [sp++];
	rts;

NtscOutputColorBarLine:
#ifdef REAL_DATA
// ***************** OUTPUT REFERENCE COLOR HORIZONTAL DATA **************
	// R0 has the line number
	// P0 has the destination buffer
	
	P2.L = _rgb_buffer;
	P2.H = _rgb_buffer;
	P3 = [P2];
	P1 = 2880; // 360 * 4 * 2 for alternate lines
	P3 = P3 + P1;
	[P2] = P3;
	// P3 now has the source rgb line
	
	[--sp]=(P5:1);
	[--SP]=(R7:0);
#define MEM_DMA 1
#ifdef MEM_DMA
	[--sp] = P0;
	R0.L = YCrCbLine; 
	R0.H = YCrCbLine; 
	//R0.H = 0xff80;
	P0 = R0; // now P0 has the L1 destination buffer
	
	R0.L = RGBLineCache;
	R0.H = RGBLineCache;
	//R0.H = 0xff80;
	// MemDMA the source rgb line to L1 RAM
	
	R1 = P3;			// source and destination same??? TODO Moved from below, verify
	P3 = R0;			// P3 has the L1 source buffer in L1
	R2 = 1440;
	call _DmaMemCpy;
#endif	
	P2 = 360;
	LSETUP(ntsclinestart, ntsclineend) LC0 = P2;
ntsclinestart :
	// now convert to YCrCb
	R3 = 0xff;
	R0 = [p3++];
	R1 = R0 >> 16;
	R1 = R1 & R3;
	R2 = R0 >> 24;
	R2 = R2 & R3;
	R0 = R0 & R3;
	[--sp] = P0;
	[--sp] = P3;
	sp += -12;
	call _rgb2crcb; // conversion every pixel
	sp += 12;
	p3 = [sp++];
	p0 = [sp++];
	// result is in R0
 
	R1 = R0;
//number of sample to output (720/8)/2
	r2 = r1 >> 24;
	b[p0++] = r2;
	r2 = r1 >> 16;
	b[p0++] = r2;
	r2 = r1 >> 8;
	b[p0++] = r2;	
ntsclineend:b[p0++] = r1;	

#ifdef MEM_DMA
	// copy the L1 YCrCb into the memory
	P0 = [sp++];
	R0 = P0; // destination of our MEMDMA
	// MemDMA the source rgb line to L1 RAM
	R1.L = YCrCbLine;
	R1.H = YCrCbLine; // source for our MEMDMA
	//R1.H = 0xff80;
	
	R2 = 1440;
	call _DmaMemCpy;
#endif	

	(R7:0)=[SP++];
	(P5:1)=[sp++];
	
    
	lt1 = [sp++];
	lb1 = [sp++];
	lc1 = [sp++];
	lt0 = [sp++];
	lb0 = [sp++];
	lc0 = [sp++];
	rets = [sp++];
	rts;
#else // !REAL_DATA 
// ***************** OUTPUT REFERENCE COLOR HORIZONTAL DATA **************
// get pointer to color bar table
	P3.h = _ColorBarTable;
	P3.l = _ColorBarTable;
	
//number of color bar
	P2 = 8;
	LSETUP(ntsccolorbarstart, ntsccolorbarend) LC0 = P2;
ntsccolorbarStart:
#if 0
// get next color bar data
	R1 = [P3++];
#else
	[--sp]=R0;
	[--SP]=(R7:2);
	[--sp]=(P5:0);
	// now convert to YCrCb
	R3 = 0xff;
	R0 = [p3];
	R1 = R0 >> 16;
	R1 = R1 & R3;
	R2 = R0 >> 24;
	R2 = R2 & R3;
	R0 = R0 & R3;
	sp += -12;
	call _rgb2crcb; // conversion only once per color change
	sp += 12;
	// result is in R0
 
	R1 = R0;
	(P5:0)=[sp++];
	(R7:2)=[SP++];
	r0 = [sp++];
	P3 += 4; 
#endif  
//number of sample to output (720/8)/2
#if 0
	P2 = 45;
	LSETUP(ntscoutputcolorbardata, ntscoutputcolorbardata) LC1 = P2;
ntscoutputcolorbardata:    
	[P0++] = R1; 
#else
	P2 = 45; 
	LSETUP(ntscoutputcolorbardata_s, ntscoutputcolorbardata_e) LC1 = P2;
ntscoutputcolorbardata_s:
	r2 = r1 >> 24;
	b[p0++] = r2;
	r2 = r1 >> 16;
	b[p0++] = r2;
	r2 = r1 >> 8;
	b[p0++] = r2;	
ntscoutputcolorbardata_e:b[p0++] = r1;	
#endif	// REAL_DATA

ntsccolorbarend:
	NOP;
    
	lt1 = [sp++];
	lb1 = [sp++];
	lc1 = [sp++];
	lt0 = [sp++];
	lb0 = [sp++];
	lc0 = [sp++];
	rets = [sp++];
	rts;

#endif

_NtscVideoOutBuffUpdate.END:

_rgb2crcb:

// ".\rgb2ycrcb.c" line 4 col 1
		link  28;

._P1L2147483649:
		[FP+ 8] = R0;
		[FP+ 12] = R1;
		[FP+ 16] = R2;
.LN1:
// ".\rgb2ycrcb.c" line 21 col 9
		R0 = R0.B (Z);
		[FP+ -24] = R0;
.LN2:
// ".\rgb2ycrcb.c" line 22 col 9
		R1 = R1.B (Z);
		[FP+ -20] = R1;
.LN3:
// ".\rgb2ycrcb.c" line 23 col 9
		R2 = R2.B (Z);
		[FP+ -16] = R2;
.LN4:
// ".\rgb2ycrcb.c" line 25 col 9
		R6 =  263 (X);
		R7 = R0.H*R6.L, R6 = R0.L*R6.L(FU);
		R7 <<=  16;
		R6 = R7 + R6;
		R3 =  4080 (X);
		R7 = R3 + R6;
		R6=R1 <<  7;
		R6 = (R6 + R1) << 2;
		R5 = R7 + R6;
		R6 =  100 (X);
		R7 = R2.H*R6.L, R6 = R2.L*R6.L(FU);
		R7 <<=  16;
		R6 = R7 + R6;
		R7 = R5 + R6;
		[FP+ -12] = R7;
.LN5:
// ".\rgb2ycrcb.c" line 26 col 9
		R4 =  152 (X);
		R5 = R0.H*R4.L, R4 = R0.L*R4.L(FU);
		R5 <<=  16;
		R4 = R5 + R4;
		R6 =   0;
		BITSET( R6, 17);
		R5 = R6 - R4;
		R6 =  298 (X);
		R7 = R1.H*R6.L, R6 = R1.L*R6.L(FU);
		R7 <<=  16;
		R6 = R7 + R6;
		R7 = R5 - R6;
		R4 =  450 (X);
		R5 = R2.H*R4.L, R4 = R2.L*R4.L(FU);
		R5 <<=  16;
		R4 = R5 + R4;
		R6 = R7 + R4;
		[FP+ -8] = R6;
.LN6:
// ".\rgb2ycrcb.c" line 27 col 9
		R4 =  450 (X);
		R5 = R0.H*R4.L, R4 = R0.L*R4.L(FU);
		R5 <<=  16;
		R4 = R5 + R4;
		R7 =   0;
		BITSET( R7, 17);
		R5 = R7 + R4;
		R6 =  377 (X);
		R7 = R1.H*R6.L, R6 = R1.L*R6.L(FU);
		R7 <<=  16;
		R6 = R7 + R6;
		R7 = R5 - R6;
		R4 =  73 (X);
		R5 = R2.H*R4.L, R4 = R2.L*R4.L(FU);
		R5 <<=  16;
		R4 = R5 + R4;
		R6 = R7 - R4;
		[FP+ -4] = R6;
.LN7:
// ".\rgb2ycrcb.c" line 29 col 9
		R5=[FP+ -12];
		R5 >>>=  10;
		R7 = R5 ;
		R7 = R7.B (Z);
		R5 <<=  16;
		R5.L =  4104;
		R4=[FP+ -28];
		R4 = DEPOSIT(R4,R5);
		[FP+ -28] = R4;
		R7 <<=  16;
		R7.L =  8;
		R4 = DEPOSIT(R4,R7);
		[FP+ -28] = R4;
.LN8:
// ".\rgb2ycrcb.c" line 30 col 9
		R6 >>>=  10;
		R6 <<=  16;
		R6.L =  2056;
		R4 = DEPOSIT(R4,R6);
		[FP+ -28] = R4;
.LN9:
// ".\rgb2ycrcb.c" line 31 col 9
		R7=[FP+ -8];
		R7 >>>=  10;
		R7 <<=  16;
		R7.L =  6152;
		R0 = DEPOSIT(R4,R7);
		[FP+ -28] = R0;
.LN10:
// ".\rgb2ycrcb.c" line 32 col 9
		JUMP ._P1L2147483647;
.LN11:

._P1L2147483647:
		unlink;

		rts;
_rgb2crcb.end:
