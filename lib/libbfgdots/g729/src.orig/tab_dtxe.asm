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
Title:			Tab_DTXE
Description     :      G729A DTX tables for encoder only
Prototype       : 
*******************************************************************************/
 
.data;
.align 4;
.global lbf_corr;
#if defined(__GNUC__)
lbf_corr:
.short 7869, 7011, 4838, 2299, 321, -660, -782, -484, -164, 3, 39, 21, 4,0;
#else
.byte2 lbf_corr[14] = 7869, 7011, 4838, 2299, 321, -660, -782, -484, -164, 3, 39, 21, 4,0;
#endif

.global shift_fx;
#if defined(__GNUC__)
shift_fx:
.short 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5,0,0;
#else
.byte2 shift_fx[34] =
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5,0,0;
#endif

.global factor_fx;
#if defined(__GNUC__)
factor_fx:
.short    32767, 16913, 17476, 18079, 18725, 19418, 20165, 20972, 21845, 22795, 23831, 24966, 26214, 27594, 29127, 30840, 32767, 17476, 18725, 20165, 21845, 23831, 26214, 29127, 32767, 18725, 21845, 26214, 32767, 21845, 32767, 32767,0,0;
#else
.byte2 factor_fx[34] =    32767, 16913, 17476, 18079, 18725, 19418,
                          20165, 20972, 21845, 22795, 23831, 24966,
                          26214, 27594, 29127, 30840, 32767, 17476,
                          18725, 20165, 21845, 23831, 26214, 29127,
                          32767, 18725, 21845, 26214, 32767, 21845,
                          32767, 32767,0,0;
#endif

.global noise_fg_sum_inv;
#if defined(__GNUC__)
noise_fg_sum_inv:
.short 17210, 15888, 16357, 16183, 16516, 15833, 15888, 15421, 14840, 15597;
#else
.byte2 noise_fg_sum_inv[10] = 
17210, 15888, 16357, 16183, 16516, 15833, 15888, 15421, 14840, 15597;
#endif
.global noise_fg_sum_inv_1;
#if defined(__GNUC__)
noise_fg_sum_inv_1:
.short 12764, 10821, 10458, 11264, 11724, 11500, 12056, 11865, 11331, 11724;
#else
.byte2 noise_fg_sum_inv_1[10] = 
12764, 10821, 10458, 11264, 11724, 11500, 12056, 11865, 11331, 11724;
#endif

