/*============================================================================
=   Copyright (c) 2007 Analog Devices
=
= This file is subject to the terms and conditions of the GNU Library General
= Public License. See the file "COPYING.LIB" in the main directory of this
= archive for more details.
=
==============================================================================
=
=   $RCSfile:  fract24_8.asm,v $
=   $Revision: 1.2 $
=   $Date: 2007/03/12 00:00:00 $
=
=   Project:    libbfdsp
=   Title:      fract24_8.asm
=   Author(s):  Matthijs Paffen
=   Revised by:
=
=   Description:
=
============================================================================*/

/*============================================================================
=
=   Function
=    fract32 fract24_8mul_asm(fract32 A, fract32 B);
=
=   Description   : calculates 28.4 Fractional multiplication
=    fract32 A       : 24.8 fractional number
=    fract32 B       : 24.8 fractional number
=    return-value : 24.8 fractional number
=
==============================================================================
=
=   Function :
=    void MatrixMultVec3x1Frac24_8(fract32 A[][Dim3], fract32 B[], fract32 Res[]);
=
=   Description     : calculates 24.8 Fractional multiplication
=    fract32 A[][Dim3] : 3*3*24.8 fractional number
=    fract32 B[]       : 3*24.8 fractional number
=    fract32 Res[]     : 3*24.8 fractional number
=
=
==============================================================================
=   Target Processor:   ADSP-BF5xx
============================================================================*/

// fract32 fract24_8mul_asm(fract32 A, fract32 B);
.global _fract24_8mul_asm

#if !defined (__GNUC__)
.section program;
#else
.text;
.align 2
#endif

_fract24_8mul_asm:

    //    Multiplication of fr24.8* fr24.8 = fr24.8
    
    //    Unsigned fraction fr8.8 * fr8.8 = 16.16     (U*U)
    //    Mixed fraction    fr8.8 * fr8.8 = 15.17<<16 (S*U)
    //    Signed fraction   fr8.8 * fr8.8 = 15.17<<32 (S*S)

    //    Scratch register use only

    a1 = r0.h*r1.l (M), a0 = r0.h*r1.h; // 16msb*16lsb, 16msb*16msb
    a0 = a0 << (32-9+8); // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    r3 = (a1 += r1.h*r0.l) (M), r2=(a0 += r1.l*r0.l) (FU); // 16msb*16lsb, 16lsb*16lsb    
    a0 = a0 >>> 8;     // shift from (8.8*8.8=16.16)>>8 to 24.8
    r2 = a0, r3 = a1;
    r3 = r3 << (16-8); // shift from 15.17<<16 to 24.8
    r0 = r2+r3 (S);

    rts;
#if !defined (__GNUC__)
_fract24_8mul_asm.end:
#endif

/*==========================================================================*/

// void MatrixMultVec3x1Frac24_8(fract32 A[][3], fract32 B[], fract32 Res[]);
.global _MatrixMultVec3x1Frac24_8

#if !defined (__GNUC__)
.section program;
#else
.text;
.align 2
#endif

_MatrixMultVec3x1Frac24_8:


    //  ---------------------------------------------------------
    //
    //  --       --    --   --     --                 --
    //  |  A B C  |    |  J  |     |  A*J + B*K + C*L  |
    //  |  D E F  |  * |  K  |  =  |  D*J + E*K + F*L  |
    //  |  G H I  |    |  L  |     |  G*J + H*K + I*L  |
    //  --       --    --   --     --                 --
    //
    //  ---------------------------------------------------------

    // Matrix*Vector multiplication

    //  effort estimate:
    //  12 * 32bit-Load
    //   3 * 32bit-Store
    //  36 * 16bit-MACs (=9 * 32bit-MACs)
    //   3 * 32bit-Add
    //   9 * 32bit-Arith. Shift
    //  12 * Stack Push/Pop-cycles
    //   5 * Direct loads
    //   6 * 32bit-Move
    // ----
    //  86 instructions without parallel issued instr.
    //  On L1 perfomance is around 87 cycles


   // Prologue:
    // ---------------------------------------------------------
    LINK 8;
    [--SP]=(R7:4); // save preserved registers R7-R4
    SP += -8;
    // ---------------------------------------------------------

    i0=r0; 
    i1=r1;
    i2=r2;
    m0 = 4;
    p0 = 2;
    r2=[i0++m0] || r5=[i1++m0];                                         // load A || load J
    a1  = r2.h*r5.l (M), a0  = r2.h*r5.h || r3=[i0++m0] || r6=[i1++m0]; // 16msb*16lsb, 16msb*16msb:A*J, D*J, G*J || load B || load K
    a1 += r3.h*r6.l (M), a0 += r3.h*r6.h || r4=[i0++m0] || r7=[i1++m0]; // 16msb*16lsb, 16msb*16msb:B*K, E*K, H*K || load C || load L
    LSETUP (looping_start, looping_end) lc0=p0;
looping_start:
    a1 += r4.h*r7.l (M), a0 += r4.h*r7.h;                               // 16msb*16lsb, 16msb*16msb:C*L, F*L, I*L
    a0 = a0 << (32-9+8);                                                // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    a1 += r5.h*r2.l (M), a0 += r5.l*r2.l (FU) || r2=[i0++m0];           // 16msb*16lsb, 16lsb*16lsb:A*J, D*J, G*J, load D, G
    a1 += r6.h*r3.l (M), a0 += r6.l*r3.l (FU) || r3=[i0++m0];           // 16msb*16lsb, 16lsb*16lsb:B*K, E*K, H*K, load E, H
    a1 += r7.h*r4.l (M), a0 += r7.l*r4.l (FU) || r4=[i0++m0];           // 16msb*16lsb, 16lsb*16lsb:C*L, F*L, I*L, load F, I
    a0 = a0 >>> 8;                                                      // shift from (8.8*8.8=16.16)>>8 to 24.8
    r0 = a0, r1 = a1;
    r1 = r1 << (16-8);
    r0 = r0 + r1 (S);
    a1  = r2.h*r5.l (M), a0  = r2.h*r5.h || [i2++m0]=r0;                // 2*16msb*16lsb:A*J, D*J, G*J, store result
looping_end:
    a1 += r3.h*r6.l (M), a0 += r3.h*r6.h;                               // 2*16msb*16lsb:B*K, E*K, H*K
    a1 += r4.h*r7.l (M), a0 += r4.h*r7.h;                               // 2*16msb*16lsb:C*L, F*L, I*L
    a0 = a0 << (32-9+8);                                                // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    a1 += r5.h*r2.l (M), a0 += r5.l*r2.l (FU);                          // 16lsb*16lsb, 16msb*16msb:A*J, D*J, G*J, load D, G
    a1 += r6.h*r3.l (M), a0 += r6.l*r3.l (FU);                          // 16lsb*16lsb, 16msb*16msb:B*K, E*K, H*K, load E, H
    a1 += r7.h*r4.l (M), a0 += r7.l*r4.l (FU);                          // 16lsb*16lsb, 16msb*16msb:C*L, F*L, I*L, load F, I
    a0 = a0 >>> 8;                                                      // shift from (8.8*8.8=16.16)>>8 to 24.8
    r0 = a0, r1 = a1;
    r1 = r1 << (16-8);                                                  // shift from 15.17<<16 to 24.8
    r0 = r0 + r1 (S);
    [i2++m0]=r0;

    // Epilogue:
    // -----------------------------------------------------------
    SP += 8;
    (R7:4)=[SP++]; // restore preserved registers R7-R4
    UNLINK;
    // -----------------------------------------------------------

    rts;
#if !defined (__GNUC__)
_MatrixMultVec3x1Frac24_8.end:
#endif

/*==========================================================================*/

// void MatrixMultVec4x1Frac24_8(fract32 A[][4], fract32 B[], fract32 Res[]);
.global _MatrixMultVec4x1Frac24_8

#if !defined (__GNUC__)
.section program;
#else
.text;
.align 2
#endif

_MatrixMultVec4x1Frac24_8:


    //  ---------------------------------------------------------
    //
    //  --         --    --   --     --                      --
    //  |  A B C D  |    |  Q  |     |  A*Q + B*R + C*S + D*T |
    //  |  E F G H  |  * |  R  |  =  |  E*Q + F*R + G*S + H*T |
    //  |  I J K L  |    |  S  |     |  I*Q + J*R + K*S + L*T |
    //  |  M N O P  |    |  T  |     |  M*Q + N*R + O*S + P*T |
    //  --         --    --   --     --                      --
    //
    //  ---------------------------------------------------------

    // Matrix*Vector multiplication

    //  effort estimate:
    //  20 * 32bit-Load
    //   4 * 32bit-Store
    //  64 * 16bit-MACs (=16 * 32bit-MACs)
    //   4 * 32bit-Add
    //  16 * 32bit-Arith. Shift
    //  12 * Stack Push/Pop-cycles
    //   5 * Direct loads
    //   8 * 32bit-Move
    // ----
    // 133 instructions without parallel issued instr.
    // On L1 perfomance is around 112 cycles


   // Prologue:
    // ---------------------------------------------------------
    LINK 8;
    [--SP]=(R7:4); // save preserved registers R7-R4
    SP += -8;
    // ---------------------------------------------------------

    i0 = r0;
    i1 = r1;
    i2 = r2;
    m0 = 4;                                                             // modify 4 = 32bit
    p0 = 3;                                                             // number of iterations-1
    r0=[i0++m0] || r4=[i1++m0];                                         // load A || load Q
    a1  = r0.h*r4.l (M), a0  = r0.h*r4.h || r1=[i0++m0] || r5=[i1++m0]; // 16msb*16lsb, 16msb*16msb:A*Q, E*Q, I*Q, M*Q || load B || load R
    a1 += r1.h*r5.l (M), a0 += r1.h*r5.h || r2=[i0++m0] || r6=[i1++m0]; // 16msb*16lsb, 16msb*16msb:B*R, F*R, J*R, N*R || load C || load S 
    a1 += r2.h*r6.l (M), a0 += r2.h*r6.h || r3=[i0++m0] || r7=[i1++m0]; // 16msb*16lsb, 16msb*16msb:C*S, G*S, K*S, O*S || load D || load T 

    LSETUP (looping2_start, looping2_end) lc0=p0;
looping2_start:    
    a1 += r3.h*r7.l (M), a0 += r3.h*r7.h;                               // 16msb*16lsb, 16msb*16msb:D*T, F*T, J*T, N*T
    a0 = a0 << (32-9+8);                                                // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    a1 += r4.h*r0.l (M), a0 += r4.l*r0.l (FU) || r0=[i0++m0];           // 16msb*16lsb, 16lsb*16lsb:A*Q, E*Q, I*Q, M*Q
    a1 += r5.h*r1.l (M), a0 += r5.l*r1.l (FU) || r1=[i0++m0];           // 16msb*16lsb, 16lsb*16lsb:B*R, F*R, J*R, N*R
    a1 += r6.h*r2.l (M), a0 += r6.l*r2.l (FU);                          // 16msb*16lsb, 16lsb*16lsb:C*S, G*S, K*S, O*S
    a1 += r7.h*r3.l (M), a0 += r7.l*r3.l (FU);                          // 16msb*16lsb, 16lsb*16lsb:D*T, F*T, J*T, N*T
    a0 = a0 >>> (8);                                                    // shift from (8.8*8.8=16.16)>>8 to 24.8
    r2 = a0, r3 = a1;                                                   // dual move
    r3 = r3 << (16-8);                                                  // 32b
    r2 = r2 + r3 (S);                                                   // 32b
    a1  = r0.h*r4.l (M), a0  = r0.h*r4.h || r2=[i0++m0] || [i2++m0]=r2; // 2*16msb*16lsb:A*J, D*J, G*J, store result
    a1 += r1.h*r5.l (M), a0 += r1.h*r5.h || r3=[i0++m0];                // 16msb*16lsb, 16msb*16msb:B*R, F*R, J*R, N*R
looping2_end:
    a1 += r2.h*r6.l (M), a0 += r2.h*r6.h;                               // 16msb*16lsb, 16msb*16msb:C*S, G*S, K*S, O*S

    a1 += r3.h*r7.l (M), a0 += r3.h*r7.h;                               // 16msb*16lsb, 16msb*16msb:D*T, F*T, J*T, N*T
    a0 = a0 << (32-9+8);                                                // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    a1 += r4.h*r0.l (M), a0 += r4.l*r0.l (FU);                          // 16msb*16lsb, 16lsb*16lsb:A*Q, E*Q, I*Q, M*Q
    a1 += r5.h*r1.l (M), a0 += r5.l*r1.l (FU);                          // 16msb*16lsb, 16lsb*16lsb:B*R, F*R, J*R, N*R
    a1 += r6.h*r2.l (M), a0 += r6.l*r2.l (FU);                          // 16msb*16lsb, 16lsb*16lsb:C*S, G*S, K*S, O*S
    a1 += r7.h*r3.l (M), a0 += r7.l*r3.l (FU);                          // 16msb*16lsb, 16lsb*16lsb:D*T, F*T, J*T, N*T
    a0 = a0 >>> (8);                                                    // shift from (8.8*8.8=16.16)>>8 to 24.8
    r0 = a0, r1 = a1;                                                   // dual move
    r1 = r1 << (16-8);                                                  // shift from 15.17<<16 to 24.8
    r0 = r0 + r1 (S);     
    [i2++m0]=r0;

    // Epilogue:
    // -----------------------------------------------------------
    SP += 8;
    (R7:4)=[SP++]; // restore preserved registers R7-R4
    UNLINK;
    // -----------------------------------------------------------

    rts;
#if !defined (__GNUC__)
_MatrixMultVec4x1Frac24_8.end:
#endif
/*============================================================================
=   Copyright (c) 2007 Analog Devices
=
= This file is subject to the terms and conditions of the GNU Library General
= Public License. See the file "COPYING.LIB" in the main directory of this
= archive for more details.
=
==============================================================================
=
=   $RCSfile:  fract24_8.asm,v $
=   $Revision: 1.1 $
=   $Date: 2007/03/07 00:00:00 $
=
=   Project:    libbfdsp
=   Title:      fract24_8.asm
=   Author(s):  Matthijs Paffen
=   Revised by:
=
=   Description:
=
============================================================================*/

/*============================================================================
=
=   Function
=    long fract24_8mul_asm(long A, long B);
=
=   Description   : calculates 28.4 Fractional multiplication
=    long A       : 24.8 fractional number
=    long B       : 24.8 fractional number
=    return-value : 24.8 fractional number
=
==============================================================================
=
=   Function :
=    void MatrixMultVec3x1Frac24_8(long A[][Dim3], long B[], long Res[]);
=
=   Description     : calculates 24.8 Fractional multiplication
=    long A[][Dim3] : 3*3*24.8 fractional number
=    long B[]       : 3*24.8 fractional number
=    long Res[]     : 3*24.8 fractional number
=
=
==============================================================================
=   Target Processor:   ADSP-BF5xx
============================================================================*/

// long fract24_8mul_asm(long A, long B);
.global _fract24_8mul_asm

#if !defined (__GNUC__)
.section program;
#else
.text;
.align 2
#endif

_fract24_8mul_asm:

    //    Multiplication of fr24.8* fr24.8 = fr24.8
    
    //    Unsigned fraction fr8.8 * fr8.8 = 16.16     (U*U)
    //    Mixed fraction    fr8.8 * fr8.8 = 15.17<<16 (S*U)
    //    Signed fraction   fr8.8 * fr8.8 = 15.17<<32 (S*S)

    //    Scratch register use only

    a1 = r0.h*r1.l (M), a0 = r0.h*r1.h; // 16msb*16lsb, 16msb*16msb
    a0 = a0 << (32-9+8); // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    r3 = (a1 += r1.h*r0.l) (M), r2=(a0 += r1.l*r0.l) (FU); // 16msb*16lsb, 16lsb*16lsb
    r3 = a1 (S2RND);
    a0 = a0 >>> 8;     // shift from (8.8*8.8=16.16)>>8 to 24.8
    r2 = a0;
    r3 = r3 << (16-9); // shift from 15.17<<16 to 24.8
    r0 = r2+r3;

    rts;
#if !defined (__GNUC__)
_fract24_8mul_asm.end:
#endif

/*==========================================================================*/

// void MatrixMultVec3x1Frac24_8(long A[][Dim3], long B[], long Res[]);
.global _MatrixMultVec3x1Frac24_8

#if !defined (__GNUC__)
.section program;
#else
.text;
.align 2
#endif

_MatrixMultVec3x1Frac24_8:


    //  ---------------------------------------------------------
    //
    //  --       --    --   --     --                 --
    //  |  A B C  |    |  J  |     |  A*J + B*K + C*L  |
    //  |  D E F  |  * |  K  |  =  |  D*J + E*K + F*L  |
    //  |  G H I  |    |  L  |     |  G*J + H*K + I*L  |
    //  --       --    --   --     --                 --
    //
    //  ---------------------------------------------------------

    // Matrix*Vector multiplication

    //  effort estimate:
    //  12 * 32bit-Load
    //   3 * 32bit-Store
    //  36 * 16bit-MACs (=9 * 32bit-MACs)
    //   3 * 32bit-Add
    //   9 * 32bit-Arith. Shift
    //  12 * Stack Push/Pop-cycles
    //   5 * Direct loads
    //   6 * 32bit-Move
    // ----
    //  86 instructions without parallel issued instr.


   // Prologue:
    // ---------------------------------------------------------
    LINK 8;
    [--SP]=(R7:4); // save preserved registers R7-R4
    SP += -8;
    // ---------------------------------------------------------

    i0=r0;
    i1=r1;
    i2=r2;
    m0 = 4;
    p0 = 2;
    r2=[i0++m0] || r5=[i1++m0];  // load A || load J
    r3=[i0++m0] || r6=[i1++m0];  // load B || load K
    r4=[i0++m0] || r7=[i1++m0];  // load C || load L
    a1  = r2.h*r5.l (M), a0  = r2.h*r5.h; // 16msb*16lsb, 16msb*16msb:A*J, D*J, G*J
    LSETUP (looping_start, looping_end) lc0=p0;
looping_start:
    a1 += r3.h*r6.l (M), a0 += r3.h*r6.h; // 16msb*16lsb, 16msb*16msb:B*K, E*K, H*K
    a1 += r4.h*r7.l (M), a0 += r4.h*r7.h; // 16msb*16lsb, 16msb*16msb:C*L, F*L, I*L
    a0 = a0 << (32-9+8); // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    a1 += r5.h*r2.l (M), a0 += r5.l*r2.l (FU) || r2=[i0++m0]; // 16msb*16lsb, 16lsb*16lsb:A*J, D*J, G*J, load D, G
    a1 += r6.h*r3.l (M), a0 += r6.l*r3.l (FU) || r3=[i0++m0]; // 16msb*16lsb, 16lsb*16lsb:B*K, E*K, H*K, load E, H
    a1 += r7.h*r4.l (M), a0 += r7.l*r4.l (FU) || r4=[i0++m0]; // 16msb*16lsb, 16lsb*16lsb:C*L, F*L, I*L, load F, I
    a0 = a0 >>> 8;     // shift from (8.8*8.8=16.16)>>8 to 24.8
    r0 = a0;
    r1 = a1 (S2RND);
    r1 = r1 << (16-9); //32b
    r0 = r0 + r1;      //32b
looping_end:
    a1  = r2.h*r5.l (M), a0  = r2.h*r5.h || [i2++m0]=r0; // 2*16msb*16lsb:A*J, D*J, G*J, store result
    a1 += r3.h*r6.l (M), a0 += r3.h*r6.h; // 2*16msb*16lsb:B*K, E*K, H*K
    a1 += r4.h*r7.l (M), a0 += r4.h*r7.h; // 2*16msb*16lsb:C*L, F*L, I*L
    a0 = a0 << (32-9+8); // combine MSB-shift (15.17<<32 to 24.8) with LSB-shift (>>8)
    a1 += r5.h*r2.l (M), a0 += r5.l*r2.l (FU); // 16lsb*16lsb, 16msb*16msb:A*J, D*J, G*J, load D, G
    a1 += r6.h*r3.l (M), a0 += r6.l*r3.l (FU); // 16lsb*16lsb, 16msb*16msb:B*K, E*K, H*K, load E, H
    a1 += r7.h*r4.l (M), a0 += r7.l*r4.l (FU); // 16lsb*16lsb, 16msb*16msb:C*L, F*L, I*L, load F, I
    a0 = a0 >>> 8;     // shift from (8.8*8.8=16.16)>>8 to 24.8
    r0 = a0;
    r1 = a1 (S2RND);
    r1 = r1 << (16-9); //32b  // shift from 15.17<<16 to 24.8
    r0 = r0 + r1;      //32b
    [i2++m0]=r0;       //16b

    // Epilogue:
    // -----------------------------------------------------------
    SP += 8;
    (R7:4)=[SP++]; // restore preserved registers R7-R4
    UNLINK;
    // -----------------------------------------------------------

    rts;
#if !defined (__GNUC__)
_MatrixMultVec3x1Frac24_8.end:
#endif
