/*****************************************************************************
Analog Devices, Inc.
BSD-Style License

This file is part of the libgdots library, an optimized codec library
for the Blackfin processor.

Copyright (c) 2007 Analog Devices, Inc.
All rights reserved.

The libgdots library, is free software, as in zero cost - it does not provide
the freedoms provided to you by other free software licenses.

For more information, see the top level COPYING file.

******************************************************************************
Project:		G.729AB for Blackfin
Title:			G729COMD
Description     :      Common Scratch variables
Prototype       :

*******************************************************************************/

.data;
//		.global xn2,wxzcode;
    .global rri0i0,rri1i1,rri2i2,rri3i3,rri4i4,rri0i1,rri2i4;
	.global rri0i2,rri0i3,rri0i4,rri1i2,rri1i3,rri1i4,rri2i3;
	.global scaled_signal,scal_sig;
	.align 4;
//	.byte2	 xn2[40];           // syn_pst use the buffer in Decoder     
//    .byte2	 wxzcode[40]; 
#if defined(__GNUC__)
	.align 4;
	rri0i0:
	.space	4;  //y[240] in Autocorr use the buffer 

	.align 2;
	scaled_signal:
	.space 12;
	
	.align 2;
	rri1i1: 
	.space 16;

	.align 2;
	rri2i2: 
	.space 16;
	

	.align 2;
	rri3i3: 
	.space 16;

	.align 2;
	rri4i4: 
	.space 16;

	.align 2;
	rri0i1: 
	.space 128;
	
	.align 2;
	rri0i2: 
	.space 82;

	.align 2;
	scal_sig: 
	.space 46;

	.align 2;
	rri0i3: 
	.space 128;
	
	.align 2;
	rri0i4: 
	.space 128;

	.align 2;
	rri1i2: 
	.space 128;

	.align 2;
	rri1i3: 
	.space 128;

	.align 2;
	rri1i4: 
	.space 128;

	.align 2;
	rri2i3: 
	.space 128;
	
	.align 2;
	rri2i4: 
	.space 128;
#else
	.align 4;
	.byte2	rri0i0[2];  //y[240] in Autocorr use the buffer 
	.byte2  scaled_signal[6];
    	.byte2  rri1i1[8];
	.byte2  rri2i2[8];
	.byte2  rri3i3[8];
	.byte2  rri4i4[8];
	.byte2  rri0i1[64];
	.byte2  rri0i2[41];
	.byte2  scal_sig[23];
	.byte2  rri0i3[64];
	.byte2  rri0i4[64];
	.byte2  rri1i2[64];
	.byte2  rri1i3[64];
	.byte2  rri1i4[64];
	.byte2  rri2i3[64];
	.byte2  rri2i4[64];
#endif
