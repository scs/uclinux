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
Title:			Tab_DTX
Description     :      G729A DTX tables for encoder and decoder
Prototype       :

*******************************************************************************/

.data;
.global PtrTab_1;
#if defined(__GNUC__)
PtrTab_1:
.short 96,52,20,54,86,114,82,68,36,121,48,92,18,120,94,124,50,125,4,100,28,76,12,117,81,22,90,116,127,21,108,66;
#else
.byte2  PtrTab_1[32] = 
96,52,20,54,86,114,82,68,36,121,48,92,18,120,
94,124,50,125,4,100,28,76,12,117,81,22,90,116,
127,21,108,66;
#endif

.global PtrTab_2_0;
#if defined(__GNUC__)
PtrTab_2_0:
.short 31,21,9,3,10,2,19,26,4,3,11,29,15,27,21,12;
#else
.byte2 PtrTab_2_0[16]= 
31,21,9,3,10,2,19,26,4,3,11,29,15,27,21,12;
#endif

.global PtrTab_2_1;
#if defined(__GNUC__)
PtrTab_2_1:
.short 16,1,0,0,8,25,22,20,19,23,20,31,4,31,20,31;
#else
.byte2 PtrTab_2_1[16]=
16,1,0,0,8,25,22,20,19,23,20,31,4,31,20,31;
#endif

//.data;
.global noise_fg_sum;
#if defined(__GNUC__)
noise_fg_sum:
.short 7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604;
#else
.byte2  noise_fg_sum[10] = 
7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604;
#endif

.global noise_fg_sum_1;
#if defined(__GNUC__)
noise_fg_sum_1:
.short 10514, 12402, 12833, 11914, 11447, 11670, 11132, 11311, 11844, 11447;
#else
.byte2  noise_fg_sum_1[10] = 
10514, 12402, 12833, 11914, 11447, 11670, 11132, 11311, 11844, 11447;
#endif

.global tab_Sidgain;
#if defined(__GNUC__)
tab_Sidgain:
.short 2,    5,    8,   13,   20,   32,   50,   64, 80,  101,  127,  160,  201,  253,  318,  401, 505,  635,  800, 1007, 1268, 1596, 2010, 2530, 3185, 4009, 5048, 6355, 8000,10071,12679,15962;
#else
.byte2 tab_Sidgain[32] = 
    2,    5,    8,   13,   20,   32,   50,   64,
   80,  101,  127,  160,  201,  253,  318,  401,
  505,  635,  800, 1007, 1268, 1596, 2010, 2530,
 3185, 4009, 5048, 6355, 8000,10071,12679,15962;
#endif
