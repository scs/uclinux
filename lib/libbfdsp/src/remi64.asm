/*
** Copyright (C) Analog Devices Inc
 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

**
** long long remainder.
**
** long long __umoddi3(long long, long long);
*/

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define CARRY AC
#else
#define CARRY AC0
#endif

.text;

.align 2;

___moddi3:
    [SP +0] = R0;
    [SP +4] = R1;
    [SP +8] = R2;
    R3 = [SP +12];
    LINK 16;
    // Compute d = x / y
    [SP +12] = R3;
    CALL.X ___divdi3;
    // then compute n = d * y
    R2 = [FP +16];
    R3 = [FP +20];
    [SP +12] = R3;
    CALL.X ___mulli3;
    UNLINK;
    // r = x (sp+0:sp+4) - n (r0:1) == ( -n + x )
	R2 = [SP +0];
	R0 = R2 - R0 (NS) || R2 = [SP+ 4] || NOP;
	CC = CARRY;
	CC = ! CC;
	R3 = CC;
	R2 = R2 - R3;
	R1 = R2 - R1;

	
return_x:
    RTS;


.___moddi3.end:
.global ___moddi3;
.type ___moddi3, STT_FUNC;
.extern ___divdi3;
.extern ___mulli3;
