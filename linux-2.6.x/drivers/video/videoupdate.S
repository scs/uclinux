/*****************************************************************************
**																			**
**	 Project Name: 	Video_Output											**	
**																			**
******************************************************************************

(C) Copyright 2003 - Analog Devices, Inc.  All rights reserved.

File Name:		videouptade.S

Date Modified:	4/4/03		CL		Rev 1.0

Software:       VisualDSP++ 3.1

Hardware:		ADSP-BF533 EZ-KIT Board

Special Connections:  None

Purpose:		This videograph.asm file sets generates an NTSC color bar 
				pattern and places the data in SDRAM memory.				
				
******************************************************************************/


#include <asm/board/defBF533.h>

#define NUM_OF_VOUT_FRAMES 2

#define RGB_LINE_OFFSET 2880

#define REAL_DATA 1
#define UPDATE 0
//#undef UPDATE
//#define MEM_DMA 1
#undef MEM_DMA

#ifdef MEM_DMA
RGBLineCache:
.space 1440 ;

YCrCbLine:
.space 1440;

.global RGBLineCache;
.global YCrCbLine;
#endif

#define LINE_LENGTH_IN_BYTES 1440
#define LINE_LENGTH_IN_PIXELS 360
#define BYTES_PER_PIXEL         4

.global iamhere1
.global iamhere2

//.section .text;
.section .text.l1, "ax", @progbits;
.extern _rgb2crcb;
.global _NtscVideoOutBuffUpdate;
.type _NtscVideoOutBuffUpdate , STT_FUNC;

.extern PalLineMap;
.extern _NtscLineMap;
.extern _SystemCodeMap;

.extern RGBLineCache;		// an extern variable pointing to L1 RAM of 1440 bytes
.extern YCrCbLine;			// an extern variable pointing to L1 RAM of 1440 bytes

.extern _rgb_buffer;
.extern _cycrcbbuffer;

.extern  _ColorBarTable;


.align 4;

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
       //R1.L = 0x0001;
        R1.L = DMAEN;
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
       //	R0.L = 0x0002;		
       
	R0.L = DMAEN |WNR;
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
	
	r0 = 1;			//line #1

	//number of lines ->  525
	P2 = 262; // interlaced, so we go through twice
	LSETUP(ntscoutputlinestart, ntscoutputlineend) LC1 = P2;
ntscoutputlinestart:
	call NtscOutputLine;
ntscoutputlineend:
	r0 += 1;		//increment line number

	P2.h = _cycrcbbuffer;
	P2.l = _cycrcbbuffer;
	R0 = [P2];
	P2.h = _rgb_buffer;
	P2.l = _rgb_buffer;
	[P2] = R0;

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
	P1 = RGB_LINE_OFFSET;
	P3 = P3 + P1;
	[P2] = P3;
	// P3 now has the source rgb line
	
	[--sp]=(P5:4);
	[--SP]=(R7:0);
iamhere1 :
#ifdef MEM_DMA
	[--sp] = P0;
	R0.L = YCrCbLine; 
	R0.H = YCrCbLine; 
	P0 = R0; // now P0 has the L1 destination buffer
	
	R0.L = RGBLineCache;
	R0.H = RGBLineCache;
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
iamhere2 :
#ifdef MEM_DMA
	// copy the L1 YCrCb into the memory
	P0 = [sp++];
	R0 = P0; // destination of our MEMDMA
	// MemDMA the source rgb line to L1 RAM
	R1.L = YCrCbLine;
	R1.H = YCrCbLine; // source for our MEMDMA
	
	R2 = 1440;
	P2 = R2;
	P0 = P0 + P2;
	P3 = P3 + P2;
	call _DmaMemCpy;
#endif	

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
dummy_end:

_NtscVideoOutBuffUpdate.END:




