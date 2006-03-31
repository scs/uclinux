/******************************************************************************
Copyright(c) 2000-2004 Analog Devices Inc.

 This file is subject to the terms and conditions of the GNU Library General
 Public License. See the file "COPYING.LIB" in the main directory of this
 archive for more details.

 Non-LGPL License also available as part of VisualDSP++
 http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

*******************************************************************************
File Name      : fir_fr16.asm
Function Name  : __fir
Module Name    : FILTER Library
Description    : This function performs FIR filter operation on given input.
Operands       : R0 - Address of input vector,
		 R1 - Address of output vector,
		 R2 - Number of input elements
		 Filter structure is on stack.

Prototype:
	void fir(const fract16 x[],fract16 y[],int n,fir_state_fr16 *s);

Structure of fir_state_fr16:
	{
	    fract16 *h, // filter coefficients 
	    fract16 *d, // start of delay line 
	    fract16 *p, // read/write pointer 
	    int k,      // no. of coefficients 
	    int l       // interpolation/decimation index 
	} fir_state_fr16;

Registers used   :   

    R0, R1, R2, R3, R3, R4, R5, R6, R7

    I0 -> Address of delay line (used for updating the delay line)
    I1 -> Address of delay line (used for fetching the delay line data)
    I2 -> Address of filter coeff. h0, h1 , ... , hn-1
    I3 -> Address of output array y[]

    P0 -> Address of input array x[]
    P1, P2, P4
    P5 -> Address of structure s


    Code size: 354 bytes
____________________________________________________________________________
    Computation time:

	a) Even Taps, Even no. inputs   : 64 + Ni/2*(3 + Nc)
	   For Ni=256, L=8              : 1472

	b) Odd Taps, Even no. inputs    : 70 + Ni/2*(3 + Nc)
	   For Ni=256, L=9              : 1606

	c) Even Taps, Odd no. inputs    : 64 + (Ni-1)/2*(3 + Nc) + Nc
	   For Ni=257, L=8              : 1480

	d) Odd Taps, Odd no. inputs     : 73 + (Ni-1)/2*(3 + Nc) + Nc
	   For Ni=257, L=9              : 1618
_______________________________________________________________________________


******************************************************************************/

#if defined(__ADSPLPBLACKFIN__) && defined(__WORKAROUND_AVOID_DAG1)
#define __WORKAROUND_BF532_ANOMALY38__
#endif

.text;
.global    __fir_fr16;
.align 2;
__fir_fr16:
	    [--SP]=(R7:4,P5:4); //PUSH R7-R4,P5-P4 ON STACK
	    P5=[SP+36];         // ADDRESS OF FILTER STRUCTURE
	    P0=R0;              // ADDRESS OF INPUT ARRAY    
	    I3=R1;              // ADDRESS OF OUTPUT ARRAY
	    CC=R2<=0;           // CHECK IF NUMBER OF INPUT ELEMENTS<=0
	    P1=[P5++];          // POINTER TO FILTER COEFFICIENTS
	    P2=[P5++];          // POINTER TO DELAY LINE
	    P4=[P5++];          // ADDRESS TO READ/WRITE POINTER
	    R1=[P5--];          // NUMBER OF COEFFICIENTS

	    IF CC JUMP _fir_fr16_RET_END;
	    CC=R1<=0;           // CHECK IF NUMBER OF COEFF. <=0
	    IF CC JUMP _fir_fr16_RET_END;        
	    R5=R1;              // STORE NUMBER OF FILTER COEFF. IN R5
	    R1=R1+R1;           // DOUBLE R1 TO INCREMENT AS HALF WORD
	    I2=P1;              // INITIALISE I2 TO FILTER COEFF. ARRAY
	    B2=P1;              // MAKE FILTER COEFFS. AS CIRCULAR BUFFER 
	    L2=R1;              
	    I1=P4;              // INDEX TO READ/WRITE POINTER
	    B1=P2;              // INITIALISE B1 AND L1
	    L1=R1;              // FOR  DELAY LINE CIRCULAR BUFFER
	    I0=P4;              // INDEX TO READ/WRITE POINTER
	    B0=P2;              // INITIALISE B0 AND L0 
	    L0=R1;              // FOR  DELAY LINE CIRCULAR BUFFER

	    P1=R2;              // SET OUTER LOOP COUNTER
	    P2=R5;              // SET INNER LOOP COUNTER
	    L3 = 0;

	    R6=PACK(R2.H,R2.L) || I1+=4;
	    CC=R6==1;

	    IF CC JUMP _fir_fr16_SING_SAMP;

	    CC=BITTST(R5,0);    //Check if the number of filter taps are odd
	    P2+=-2;             //Nc-2

	    IF CC JUMP _fir_fr16_FIR_ODD;   //Odd tap FIR

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
			NOP;
			NOP;
			NOP;
#endif

/*****************************************************************************/
	/** Even number of input samples **/
	/** Even number of filter taps   **/

#if defined(__WORKAROUND_BF532_ANOMALY38__)

    /* ---------- Start of BF532 Anomaly#38 Safe Code ----------        **
    **                                                                  **
    ** which implements the IIR filter for an even number of samples    **
    ** and an even number of filter coefficients                        **
    **                                                                  */

	I0+=2 || R2=[I2++];
	R0=[P0++];
	I1+=2;

	LSETUP(_fir_fr16_E_FIR_START,_fir_fr16_E_FIR_END) LC0=P1>>1;
					    // Loop 1 to Ni/2
_fir_fr16_E_FIR_START:
	    A1=R0.H*R2.L,A0=R0.L*R2.L ||I1-=2 || W[I0--]=R0.L;
	    R4=PACK(R0.H,R4.L) || R0.H=W[I1++];

	    LSETUP(_fir_fr16_E_MAC_ST,_fir_fr16_E_MAC_END) LC1=P2>>1;
					    //Loop 1 to Nc-1/2
_fir_fr16_E_MAC_ST:  R2.L=W[I2++];
		     A1+=R0.L*R2.H,A0+=R0.H*R2.H || R0.L=W[I1++];
		     R2.H=W[I2++];
_fir_fr16_E_MAC_END: A1+=R0.H*R2.L,A0+=R0.L*R2.L || R0.H=W[I1++];

	    R3.H=(A1+=R0.L*R2.H),R3.L=(A0+=R0.H*R2.H) || R0=[P0++] || W[I0--]=R4.H;
_fir_fr16_E_FIR_END:
	    R2=[I2++] || [I3++]=R3;

#else  /* End of BF532 Anomaly#38 Safe Code */

    /* ---------- Start of NON BF532 Anomaly#38 Safe Code ----------    **
    **                                                                  **
    ** which implements the IIR filter for an even number of samples    **
    ** and an even number of filter coefficients                        **
    **                                                                  */

	I0+=2 || R0.L=W[I1++];
	R0=[P0++] || R2=[I2++];

	LSETUP(_fir_fr16_E_FIR_START,_fir_fr16_E_FIR_END) LC0=P1>>1;
					    // Loop 1 to Ni/2
_fir_fr16_E_FIR_START:
	    A1=R0.H*R2.L,A0=R0.L*R2.L ||I1-=2 || W[I0--]=R0.L;
	    R4=PACK(R0.H,R4.L) || R0.H=W[I1++] || NOP;

	    LSETUP(_fir_fr16_E_MAC_ST,_fir_fr16_E_MAC_END)LC1=P2>>1;
					    //Loop 1 to Nc-1/2

_fir_fr16_E_MAC_ST:  A1+=R0.L*R2.H,A0+=R0.H*R2.H || R2.L=W[I2++] || R0.L=W[I1++];
_fir_fr16_E_MAC_END: A1+=R0.H*R2.L,A0+=R0.L*R2.L || R0.H=W[I1++] || R2.H=W[I2++];
	    R3.H=(A1+=R0.L*R2.H),R3.L=(A0+=R0.H*R2.H) || R0=[P0++] || W[I0--]=R4.H;
_fir_fr16_E_FIR_END:
	    R2=[I2++] || [I3++]=R3;

#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

	R0.L=W[I0--] || I2-=4;
	R0=I0;
	R2.L=W[I1--];
	P0+=-4;

	JUMP _fir_fr16_DATA;

/*****************************************************************************/
	/** Even number of input samples **/
	/** Odd number of filter taps    **/

_fir_fr16_FIR_ODD:

	B3=I3;
	R2>>=1;
	R2=R2 << 2 || R6.H=W[I1++];
	L3=R2;
	R5=[P0];

#if defined(__WORKAROUND_BF532_ANOMALY38__)

    /* ---------- Start of BF532 Anomaly#38 Safe Code ----------        **
    **                                                                  **
    ** which implements the IIR filter for an even number of samples    **
    ** and an odd number of filter coefficients                         **
    **                                                                  */

	R2=[I2++] || I3-=4;
	R3=[I3];

	LSETUP(_fir_fr16_O_FIR_START,_fir_fr16_O_FIR_END) LC0=P1>>1;
					    //Loop 1 to Ni/2
_fir_fr16_O_FIR_START:
	    R4.H=W[I0] || W[I0++]=R5.H;
	    R0=PACK(R6.H,R5.L) || R7=[P0++];
	    A1=R5.H*R2.L,A0=R5.L*R2.L || R5=[P0] || W[I0--]=R5.L;

	    LSETUP(_fir_fr16_O_MAC_ST,_fir_fr16_O_MAC_END) LC1=P2>>1;
					    //Loop 2 to Nc/2-1
_fir_fr16_O_MAC_ST:  A1+=R0.L*R2.H,A0+=R0.H*R2.H || R2=[I2++];
		     R0.L=W[I1++];
_fir_fr16_O_MAC_END: A1+=R0.H*R2.L,A0+=R0.L*R2.L || R0.H=W[I1++];

	    A1+=R0.L*R2.H,A0+=R0.H*R2.H || R2.H=W[I2++] || I0-=4;
					    //Done only for Odd number of coeffs
	    R3.L=(A0+=R4.H*R2.H) || R6.H=W[I1++] ||  [I3++]=R3 ;
_fir_fr16_O_FIR_END:
	    R3.H=(A1+=R0.H*R2.H) || R2=[I2++];

#else  /* End of BF532 Anomaly#38 Safe Code */

    /* ---------- Start of NON BF532 Anomaly#38 Safe Code ----------    **
    **                                                                  **
    ** which implements the IIR filter for an even number of samples    **
    ** and an odd number of filter coefficients                         **
    **                                                                  */

	R4.H=W[I0] || I3-=4;
	R3=[I3] || R2=[I2++];

	LSETUP(_fir_fr16_O_FIR_START,_fir_fr16_O_FIR_END) LC0=P1>>1;
					    //Loop 1 to Ni/2
_fir_fr16_O_FIR_START:
	    R0=PACK(R6.H,R5.L) || R7=[P0++] || W[I0++]=R5.H ;
	    A1=R5.H*R2.L,A0=R5.L*R2.L || R5=[P0] || W[I0--]=R5.L;

	    LSETUP(_fir_fr16_O_MAC_ST,_fir_fr16_O_MAC_END) LC1=P2>>1;
					    //Loop 2 to Nc/2-1
_fir_fr16_O_MAC_ST:  A1+=R0.L*R2.H,A0+=R0.H*R2.H || R2=[I2++] || R0.L=W[I1++];
_fir_fr16_O_MAC_END: A1+=R0.H*R2.L,A0+=R0.L*R2.L || R0.H=W[I1++];

	    A1+=R0.L*R2.H,A0+=R0.H*R2.H || R2.H=W[I2++] || I0-=4;
					    //Done only for Odd number of coeffs
	    R3.L=(A0+=R4.H*R2.H) || R6.H=W[I1++] ||  [I3++]=R3 ;
_fir_fr16_O_FIR_END:
	    R3.H=(A1+=R0.H*R2.H) || R2=[I2++] || R4.H=W[I0]; 

#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

	L3 = 0;
	R0 = I0;
	I2-=4;
	[I3++] = R3 || I1-=2;

/*****************************************************************************/

_fir_fr16_DATA:
	CC=BITTST(R6,0);
	IF !CC JUMP _fir_fr16_RET_END1;
			    //If even number of input samples, jump to ret_end

/*****************************************************************************/
	/** Process the last sample separately **/
	/** for an odd number of input samples **/

	P2+=2;

_fir_fr16_SING_SAMP:

#if defined(__WORKAROUND_BF532_ANOMALY38__)

    /* ---------- Start of BF532 Anomaly#38 Safe Code ----------        **
    **                                                                  **
    ** which processes the last sample separately for an odd number of  **
    ** number of input samples                                          **
    **                                                                  */

#if defined(__WORKAROUND_CSYNC) || defined(__WORKAROUND_SPECULATIVE_LOADS)
		NOP;
		NOP;
		NOP;
#endif

	A1=A0=0 || R0=W[P0] (Z);
	R4 = PACK(R0.H,R0.L) || R2.H=W[I0++];

	LSETUP(_fir_fr16_L_MAC_ST,_fir_fr16_L_MAC_END)LC1=P2;//Loop 1 to Nc
_fir_fr16_L_MAC_ST:  R2.L=W[I2++];
_fir_fr16_L_MAC_END: R3.L=(A0+=R0.L*R2.L) || R0.L=W[I1++];

#else  /* End of BF532 Anomaly#38 Safe Code */

    /* ---------- Start of NON BF532 Anomaly#38 Safe Code ----------    **
    **                                                                  **
    ** which processes the last sample separately for an odd number of  **
    ** number of input samples                                          **
    **                                                                  */

	A1=A0=0 || R0=W[P0] (Z) || R2.L=W[I2++];
	R4 = PACK(R0.H,R0.L) || R2.H=W[I0++];

	LSETUP(_fir_fr16_L_MAC_ST,_fir_fr16_L_MAC_ST)LC1=P2;//Loop 1 to Nc
_fir_fr16_L_MAC_ST:R3.L=(A0+=R0.L*R2.L) || R2.L=W[I2++] || R0.L=W[I1++];

#endif /* End of Alternative to BF532 Anomaly#38 Safe Code */

	W[I0--]=R4.L;
	W[I3++]=R3.L || I0-=2;
	R0=I0;

_fir_fr16_RET_END1:
	[P5]=R0;

/*****************************************************************************/

_fir_fr16_RET_END:
	L0=0;
	L1=0;
	L2=0;
	(R7:4,P5:4)=[SP++];             //POP R7-R4,P5-P4 FROM STACK
	RTS;

.__fir_fr16.end:
