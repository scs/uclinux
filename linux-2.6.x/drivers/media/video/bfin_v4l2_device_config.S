/********************************************************************************************
 *									    		    *
 * 	Project Name- Video For Linux 2 For Blackfin 533 supoorted Platfors 		    *
 *									    		    *
 ********************************************************************************************

(C) Copyright 2005 -	Rrap Software Private Limited 
 
File Name:		bfin_v4l2_device_config.S

Date Modified:		4th March 2005	

Purpose:		Contains hardware specific Assembly functions. Description of each func
			is given at respective places.

			This program is free software; you can redistribute it and/or modify
			it under the terms of the GNU General Public License as published by
			the Free Software Foundation; either version 2 of the License, or
			(at your option) any later version.
			
			 This program is distributed in the hope that it will be useful,
			 but WITHOUT ANY WARRANTY; without even the implied warranty of
			 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
			 GNU General Public License for more details.
			
			 You should have received a copy of the GNU General Public License
			 along with this program; if not, write to the Free Software
			 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *********************************************************************************************/ 
#include <asm/board/defBF533.h>

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

/***********************************************************************
 * 	_config_dma -
 *
 *	Function:	To set PPI as per driver's requirement.
 *	
 *	Parameters:	This function uses value stored in R0 as Buffer 
 *			address. So the if a c function wants to call
 *			it, it should pass buffer address as the only
 *			parameter.
 ***********************************************************************/
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

/********************************************************************
 *
 * _change_descriptor_start_address -
 *
 * Function:	To change start address field of descriptor in small
 *		descriptor model.
 *
 * Scope:	Global.
 *
 * Parameter	If called from C program pass start address as only
 *		parameter. If calling from Assembly program, set value
 *		of R0 as start address.
 *
 *********************************************************************/

_change_descriptor_start_address:
	[--sp] = P0 ;
	[--sp] = P1 ;
	
	P0.L = _dma_descriptor;
	P0.H = _dma_descriptor;
	//start address in R0
	P1 = 2 ;
	P0 = P0 + P1 ;
	w[P0]= R0.L
	P0 = P0 + P1 ;
	w[P0]= R0.H
	
	[sp++] = P1 ;
	[sp++] = P0 ;
	rts ;
.global _change_descriptor_start_address ;
.type _change_descriptor_start_address, STT_FUNC ;

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

/************************************************************************
 * 	_config_ppi -
 *
 * Function:		Configures PPI in required way.
 *
 * Parameters:		No Parameter
 *
 * Special Note: 	Before using this Function user should ensure that 
 *			no one else is using PPI.
 ***********************************************************************/  

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

/**************************************************************************
 * _Flash_Setup_ADV_Reset  -
 *
 * Function:	It sets up ADV7171 chip in the desired mode.
 *
 *************************************************************************/
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

.section .data;
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

/*****************************************************************************
 *
 * _NtscVideoOutFrameBuffInit  -
 *
 * Function:		Set up blaking info in the output buffer. Sets a Vertical 
 *			Color Bar pattern also. Needed to called only once.
 * Parameters : 	R0 : destination buffer - YCrCb data buffer
 *             		R1 : source buffer      - RGB   data buffer
 *             		When calling from "C", first parameter is pointer to Destination 
 *			buffer, secon parameter is pointer to source buffer.
 *
 *****************************************************************************/
_NtscVideoOutFrameBuffInit:

        [--sp] = rets;
        [--sp] = (r7:3, p5:0);
        [--sp] = astat;

        P0 = R0;	//Destination address

        // load base of system code map in P5
        P5.h = _SystemCodeMap;
        P5.l = _SystemCodeMap;

        // load base of ntsc line map in P1
        P4.h = _NtscLineMap;
        P4.l = _NtscLineMap;

        r1 = p0;	//Address of ycrcb_buffer
        [--sp] = r1;	//Save it
        r0 = 0;		//First line of even field
        [--sp] = r0;	//Save it


        //number of frames ->  NUM_FRAMES
        p2 = NUM_OF_VOUT_FRAMES;
        LSETUP(ntscoutputfieldstart_init, ntscoutputfieldend_init) LC0 = P2;

ntscoutputfieldstart_init:
        r0 = [sp++];	
        r1 = [sp++];
        r2 = 1716;	//offset between 1st and 2nd ycrcb line
        r1 = r1 + r2;	//first line of odd field
        [--sp] = r1;
        r1 = r1 - r2;	
        p0 = r1;	
        r0 += 1;	//first line of odd field
        [--sp] = r0;

        P2 = 262;
        LSETUP(ntscoutputlinestart_init, ntscoutputlineend_init) LC1 = P2;
ntscoutputlinestart_init:
        call NtscOutputLine_init;

        r2 = 1716;
        r1 = p0;
        r1 = r1 + r2; //next line
        p0 = r1;

ntscoutputlineend_init:
        r0 += 2;                //increment line number
ntscoutputfieldend_init:
        nop;
        r0 = 525;
        call NtscOutputLine_init;
        r0 = [sp++];
        p0 = [sp++];

        astat = [sp++];
//R0.l = debug_video;
//R0.h = (debug_video>>16);
//call printk;
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

        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
        b[p0++] = r1;

// ***************** OUTPUT HORIZONTAL BLANKING ***************
// store blank data information
        R1.h = 0x8010;
        R1.l = 0x8010;

//number of sample to output 134/2
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

// **************** OUTPUT SAV ******************
        R2 = [P3 + 8];      // load video output flag
        R1 = [P3];          // load SAV code, see down for storage
        CC = BITTST(R2, 0); // test bit 0 to know if we have to output some video

        r2 = r1 >> 24;
        b[p0++] = r2;
        r2 = r1 >> 16;
        b[p0++] = r2;
        r2 = r1 >> 8;
        b[p0++] = r2;
        b[p0++] = r1;

        IF CC JUMP NtscOutputColorBarLine_init;

// ***************** OUTPUT EMPTY HORIZONTAL DATA ***************
// store blanking information
        R1.h = 0x8010;
        R1.l = 0x8010;

//number of sample to output 720/2

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
// ***************** OUTPUT REFERENCE COLOR HORIZONTAL DATA **************
// get pointer to color bar table
        P3.h = _ColorBarTable;
        P3.l = _ColorBarTable;

//number of color bar
        P2.L = 0x0008;
        P2.H = 0x0000;
        LSETUP(ntsccolorbarstart, ntsccolorbarend) LC0 = P2;
ntsccolorbarstart:
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
//number of sample to output (720/8)/2
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


/***********************************************************************
 *
 * _rgb2crcb   -
 *
 * Function:	To convert RGB data into YCRCB format.
 *
 ***********************************************************************/
.align 2
_rgb2crcb:
	LINK 0;
	R3 = R2;
	R2 = R0.B (Z);
	[--sp] = ( r7:4 );

	R6 = R3.B (Z);
	R7 = R2;
	R5 = R1.B (Z);
	P2 = R6;
	R7 <<= 5;
	R7 = R7 + R2;
	R0 = R5;
	R7 <<= 3;
	R0 <<= 7;
	R0 = (R0 + R5) << 2;
	R7 = R7 - R2;
	R7 = R7 + R0;
	P2 = P2 + (P2 << 1);
	R0 = P2;
	R0 <<= 3;
	R0 = (R0 + R6) << 2;
	R7 = R7 + R0;
	R0 = 16384 (X);
	R7 = R7 + R0;
	R0 = -152 (X);
	R1 = -298 (X);
	R1 *=R5;
	R0 *=R2;
	R3 = R6;
	R0 = R0 + R1;
	R3 <<= 3;
	R1 = R3 - R6;
	R1 <<= 5;
	R1 = (R1 + R6) << 1;
	R0 = R0 + R1;
	R1 = R2;
	R1 <<= 3;
	R1 = R1 - R2;
	R1 <<= 5;
	R1 = (R1 + R2) << 1;
	R2 = -377 (X);
	R3 = R3 + R6;
	R5 *=R2;
	R3 <<= 3;
	R1 = R1 + R5;
	R3 = R3 + R6;
	R4 = 1 (X);
	R4 <<= 17;
	R1 = R1 - R3;
	R7 >>>= 10;
	R0 = R0 + R4;
	R1 = R1 + R4;
	R2 = R7;
	R1 >>>= 10;
	R0 >>>= 10;
	R1 <<= 10;
	R0 <<= 24;
	R2 <<= 16;
	R0 = R0 | R2;
	R1 >>>= 2;
	R0 = R0 | R1;
	R0 = R0 | R7;
	( r7:4 ) = [sp++];

	UNLINK;
	rts;
_rgb2crcb.end:
.global _rgb2crcb;
.type _rgb2crcb, STT_FUNC;
