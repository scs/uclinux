/****************************************************************************************************

Description     : The assembly function implements radix4 outplace IFFT 
                  algorithm for complex inputs, input is 32 bits, twiddles are 16 bits.
                 
                  The twiddle factor array to be passed to the function must be 
                  initialized with real(cos) and imaginary(-sine) values 
                  alternately.
                  The length of the twiddle factor array should be 3*N/4, 
                  where N is the number of FFT points.
                     
                             twiddles(3k)   = exp(-2*j*pi*2*k/N)
                             twiddles(3k+1) = exp(-2*j*pi*  k/N)
                             twiddles(3k+2) = exp(-2*j*pi*3*k/N)
                             
                             k=0,1,...,N/4-1
                             
				  Note the swap of the first two terms.                             

                  The input array to be passed to the function also must be 
                  initialized with real and imaginary values alternately.
                  The real and imaginary output values will be stored 
                  alternately in the output array.

                  No scaling is done. If static scaling (i.e. by 4 at the output
                  of each stage is desired, it can be done with no cycle hit by
                  simply adding (ASR) option to each vector add/subtract.

Assumptions     : 1. There should be atleast 2 stages since first stage is done 
                     separately. In the first stage, bit reversal is done and it
                     required no multiplies, so it is separated out. Last stage
                     is also separated out to allow for loop unrolling in the
                     middle stages. If N = 16, computation for intermediate stages
                     are skipped by a conditional jump.
                     
                     Thus, FFT length should be at least 16 and should be an 
                     integer power of 4.

                  2. The input array base address _input[] should be 4*N byte aligned
                     for bit reversing to work properly.

                  3. _twiddles[] and _output[] should be 4 byte aligned.

                  4. _output[] and _twiddles[] should be in different minibanks.

                  5. _input[] and _output[] should be in different minibanks.


Registers used  : A0,A1, R0-R7, I0-I2, B0-B2, M0-M3, L0-L2, P1-P5, LC0,LC1, CC

Initial revision - December 5, 2005     BL                    

****************************************************************************************************/

#if 0
#.section L1_data_B;
.section .data;
.align 4;
	.size	_TempStore, 32
_TempStore:
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
#endif

.data;
.align 4;
.TempStore:
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;
	.long 0;	

//****************************************************************************************************

.global _IFFTRad4;
                    
//****************************************************************************************************
#.section L1_code;
.section .text;
.align 8;
_IFFTRad4:
	[--SP] = (R7:4);        // Save registers R4-R7
	[--SP] = (P5:3);        // Save registers P3-P5

//************************************ Stage 1 *******************************************************

	b2 = r1;
	p2 = r2;
	
	i0 = r0;														// pointer to input data  
	l0 = 0;
	
	i1 = r1;		 												// pointer to ping-pong buffer 2
	r1 += 4;
	b1 = r1;														// pointer to ping-pong buffer 1
	
	l1 = 0;
	
	r1 = r2;
	m0 = r1;
	
	r1 = r2 >> 2;
	r1 += -1;
	p5 = r1;

	r2 = r2 << 1;
	m1 = r2;
	
	r1 = r2 << 1;
	r1 = r1 + r2;
	r1 = -r1;
	r2 = 4;
	r1=r1+r2, r2=r1-r2;
	m2 = r1;
	m3 = r2;
		
	p0 = i1;
	p1 = 12;
	p3 = 8;
	p4 = -24;

						  r0=[i0++m1];
		  			  	  r2=[i0++m1];
				 		  r1=[i0++m1];
	r0=r0+r1, r1=r0-r1 || r3=[i0++m2];
	r2=r2+r3, r3=r2-r3 || r4=[i0++m1];
	r0=r0+r2, r2=r0-r2 || r6=[i0++m1];
		  			  	  r5=[i0++m1];
	r4=r4+r5, r5=r4-r5 || r7=[i0++m3];
	r6=r6+r7, r7=r6-r7 || i0+=m0 (BREV);
	
	lsetup(Stage1Start, Stage1End) lc0 = p5;
	
Stage1Start:	
				   			  	   				   			  	   
			r4=r4+r6, r6=r4-r6 || r0=[i0++m1] || [p0]=r0;
			r7=r1+r7, r1=r1-r7 || r2=[i0++m1] || [p0+16]=r2;
			r5=r5+r3, r3=r5-r3 || r1=[i0++m1] || [p0+8]=r1;
			r0=r0+r1, r1=r0-r1 || r3=[i0++m2] || [p0+28]=r3;
			r2=r2+r3, r3=r2-r3 || r4=[i0++m1] || [p0+4]=r4;
			r0=r0+r2, r2=r0-r2 || r6=[i0++m1] || [p0+20]=r6;
				  			  	  r5=[i0++m1] || [p0+12]=r5;
			r4=r4+r5, r5=r4-r5 || r7=[i0++m3] || [p0+24]=r7;
												  p0+=32;
Stage1End:	r6=r6+r7, r7=r6-r7 || i0+=m0 (BREV);

	r4=r4+r6, r6=r4-r6 || [p0]=r0;
	r7=r1+r7, r1=r1-r7 || [p0+16]=r2;
	r5=r5+r3, r3=r5-r3 || [p0+8]=r1;
		    			  [p0+28]=r3;
						  [p0+4]=r4;
						  [p0+20]=r6;
						  [p0+12]=r5;
						  [p0+24]=r7;

//************************************ Middle Stage *******************************************************

	r2 = p2;
	r1 = r2 << 3;
	r1 += -4;
	l1 = r1;
	
	b0 = b1;
	l0 = l1;

	r0 = p2;	

	p2 = b2;		 												// pointer to ping-pong buffer 2
	i1 = b2;	

	r2 = [SP + 40];														// pointer to twiddles
	i2 = r2;
	
	r1 = r0 >> 4;
	r1 += -1;
	p4 = r1;

	m0 = (32-4);
	m1 = 32;
	m3 = -(3*32-4);
	
	p0 = (32+4);
	p1 = m1;
	p3 = -(3*32);
	
	p5 = 3;
	
	m2 = r0;
	r1 = r0 >> 1;
	r2 = r0 >> 2;
	r0 = r1 + r2;
	m2 = r0;

	i3.l = .TempStore;
	i3.h = .TempStore;
	
	CC = p4 < 1;      
	if CC jump SLastRad4;
	
//****************************************************************************************************
SMidStartOut:	

       	                  r0=[i1++m1];
	                      r2=[i1++m1];
	r0=r0+r2, r2=r0-r2 || r4=[i1++m1];
	                      r6=[i1++m3];
	r4=r4+r6, r6=r4-r6 || r1=[i1++m1];
	r0=r0+r4, r4=r0-r4 || r3=[i1++m1];
	r1=r1+r3, r3=r1-r3 || r5=[i1++m1];
	r3=r3+r6, r6=r3-r6 || r7=[i1++m0];
		
	lsetup(SMidStartIn3, SMidEndIn3) lc1 = p4;

SMidStartIn3:

		r5=r5+r7, r7=r5-r7;
		
		r7=r2+r7, r2=r2-r7 || r0=[i1++m1] || [p2++p1]=r0;
		                      r2=[i1++m1] || [p2++p1]=r2;
		r0=r0+r2, r2=r0-r2 || r4=[i1++m1] || [p2++p0]=r4;
		r1=r1+r5, r5=r1-r5 || r6=[i1++m3] || [p2++p3]=r6;
		r4=r4+r6, r6=r4-r6 || r1=[i1++m1] || [p2++p1]=r1;
		r0=r0+r4, r4=r0-r4 || r3=[i1++m1] || [p2++p1]=r3;
		r1=r1+r3, r3=r1-r3 || r5=[i1++m1] || [p2++p1]=r5;
									          p2+=-4;
SMidEndIn3:	r3=r3+r6, r6=r3-r6 || r7=[i1++m0] || [p2++p1]=r7;
		
 	r5=r5+r7, r7=r5-r7;
	r7=r2+r7, r2=r2-r7 || [p2++p1]=r0;
	r1=r1+r5, r5=r1-r5 || [p2++p1]=r2;
	                      [p2++p0]=r4 || r0=[i2++m2];
	                      [p2++p3]=r6 || r0=[i1++];
	[p2++p1]=r1;
	[p2++p1]=r3;
	[p2++p1]=r5;
	p2+=-4;
	[p2++p1]=r7;

	i0=i1;
 	
	lsetup(SMidStartMid4, SMidEndMid4) lc0 = p5;

SMidStartMid4:	
 	                                                        r0=[i1++];
	                                                        [i3++]=r0   || r1=[i1++m0];
	                                                        r0=[i2++]   || r2=[i1++];
	 	                                                        
	    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h			 || r1=[i1++m0] || [i3++]=r1;
	    a1-=r0.l*r1.l  (M),		a0-=r0.l*r1.h;
		a1=a1>>>15									     || r4=[i1++];
		r3=(a0+=a1);
    	a1 =r0.h*r1.l  (M),		a0 =r0.h*r1.h;
   		a1+=r0.l*r2.l  (M),		a0+=r0.l*r2.h;
		a1=a1>>>15;
		r2=(a0+=a1)										 || r0=[i2++];
		
    	a1 =r0.h*r4.l  (M),		a0 =r0.h*r4.h			 || r2=[i1++m0] || [i3]=r2;
	    a1-=r0.l*r2.l  (M),		a0-=r0.l*r2.h;
		a1=a1>>>15;
		r5=(a0+=a1);
	    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h;
    	a1+=r0.l*r4.l  (M),		a0+=r0.l*r4.h;
		a1=a1>>>15								         || r6=[i1++];
		r4=(a0+=a1)										 || r0=[i2--]	|| r2=[i3];
												 			
	    a1 =r0.h*r6.l  (M),		a0 =r0.h*r6.h			 || r4=[i1++m0] || [i3]=r4;	
    	a1-=r0.l*r4.l  (M),		a0-=r0.l*r4.h;
		a1=a1>>>15;
		r7=(a0+=a1)										 || i2-=4;
   		a1 =r0.h*r4.l  (M),		a0 =r0.h*r4.h;
	    a1+=r0.l*r6.l  (M),		a0+=r0.l*r6.h			 || r4=[i3--];
		a1=a1>>>15										 || r1=[i3--];
		r6=(a0+=a1)										 || r0=[i3];
	 	                                                        
		lsetup(SMidStartIn5, SMidEndIn5) lc1 = p4;

SMidStartIn5:	
			r0=r0+r2, r2=r0-r2;
			r4=r4+r6, r6=r4-r6;
			r0=r0+r4, r4=r0-r4;
			r3=r1+r3, r1=r1-r3                               || [i0++]=r0;
			r5=r5+r7, r7=r5-r7                               || r0=[i1++];
			r5=r1+r5, r1=r1-r5                               || [i3++]=r0   || r0=[i2++];
			r2=r2+r7, r7=r2-r7                               || [i0++m0]=r1 || r1=[i1++m0];
			r3=r3+r6, r6=r3-r6                               || [i0++]=r2   || r2=[i1++];
																    
		    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h			 || r1=[i1++m0] || [i3++]=r1;
		    a1-=r0.l*r1.l  (M),		a0-=r0.l*r1.h			 || [i0++m0]=r3;
			a1=a1>>>15									     || r4=[i1++]   || [i0++]=r4;
			r3=(a0+=a1);
    		a1 =r0.h*r1.l  (M),		a0 =r0.h*r1.h;
   			a1+=r0.l*r2.l  (M),		a0+=r0.l*r2.h;
			a1=a1>>>15										 || [i0++m0]=r5;
			r5=(a0+=a1)										 || r0=[i2++]   || r2=[i1++m0];
		
	    	a1 =r0.h*r4.l  (M),		a0 =r0.h*r4.h			 || [i3]=r5;
	    	a1-=r0.l*r2.l  (M),		a0-=r0.l*r2.h			 || [i0++]=r7;
			a1=a1>>>15;
			r5=(a0+=a1);
		    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h;
    		a1+=r0.l*r4.l  (M),		a0+=r0.l*r4.h;
			a1=a1>>>15								         || r6=[i1++]   || [i0++m0]=r6;
			r7=(a0+=a1)										 || r0=[i2--]   || r4=[i1++m0];	
												 			
		    a1 =r0.h*r6.l  (M),		a0 =r0.h*r6.h			 || [i3]=r7	    || r2=[i3];
	    	a1-=r0.l*r4.l  (M),		a0-=r0.l*r4.h;
			a1=a1>>>15;
			r7=(a0+=a1)										 || i2-=4;
   			a1 =r0.h*r4.l  (M),		a0 =r0.h*r4.h;
	    	a1+=r0.l*r6.l  (M),		a0+=r0.l*r6.h			 || r4=[i3--];
			a1=a1>>>15										 || r1=[i3--];
SMidEndIn5:	r6=(a0+=a1)										 || r0=[i3];

 		r0=r0+r2, r2=r0-r2;
		r4=r4+r6, r6=r4-r6;
		r0=r0+r4, r4=r0-r4;
		r3=r1+r3, r1=r1-r3                                   || [i0++]=r0;
		r5=r5+r7, r7=r5-r7;
		r5=r1+r5, r1=r1-r5;
		r2=r2+r7, r7=r2-r7                                   || [i0++m0]=r1;
		r3=r3+r6, r6=r3-r6                                   || [i0++]=r2;
		
		                                         r0=[i2++m2] || [i0++m0]=r3;
		                                         r0=[i1++]   || [i0++]=r4;
		[i0++m0]=r5;
		[i0++]=r7;
		[i0++m0]=r6;
SMidEndMid4: i0=i1;
		
	r0 = m1;
	r0 = r0 << 2;
	m1 = r0;

	p1 = m1;
	
	p0 = m1;
	p0 += 4;
		
	r1 = r0 << 1;
	r1 = r0 + r1;
	r1 = -r1;
	p3 = r1;

	r1 += 4;
	m3 = r1;
		
	r0 += -4;
	m0 = r0;

	r0 = m2;
	r0 = r0 >> 2;
	m2 = r0;
		
	p4 += 1;
	p4 = p4 >> 2;
	p4 += -1;

	p5 = p5 << 2;
	p5 += 3;

	p2 = b2;														// pointer to ping-pong buffer 1
	i1 = b2;		 												// pointer to ping-pong buffer 2
	r2 = [SP + 40];
	i2 = r2;
		
	CC = p4 <= 0;
	if !CC jump SMidStartOut;

	CC = p4 < 0;
	if CC jump SLastRad2;
	
//********************************** Last Stage Rad4 *****************************************************
SLastRad4:
	                      r0=[i1++m1];
	                      r2=[i1++m1];
	r0=r0+r2, r2=r0-r2 || r4=[i1++m1];
	                      r6=[i1++m3];
	r4=r4+r6, r6=r4-r6 || r1=[i1++m1];
	r0=r0+r4, r4=r0-r4 || r3=[i1++m1];
	r1=r1+r3, r3=r1-r3 || r5=[i1++m1];
	r3=r3+r6, r6=r3-r6 || r7=[i1++m0];
	r5=r5+r7, r7=r5-r7;
	r7=r2+r7, r2=r2-r7 || [p2++p1]=r0;
	r1=r1+r5, r5=r1-r5 || [p2++p1]=r2;
		
	[p2++p0]=r4;
	[p2++p3]=r6;
	[p2++p1]=r1;
	[p2++p1]=r3;
	[p2++p1]=r5;
	p2+=-4;
	[p2++p1]=r7;

	i2+=m2;
	i1+=4;
	i0=i1;
	p5+=-1;

 	r0=[i1++];
 	[i3++]=r0 || r0=[i2++];
 	r1=[i1++m0];
 	r2=[i1++];
													    
    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h			 || r1=[i1++m0] || [i3++]=r1;
    a1-=r0.l*r1.l  (M),		a0-=r0.l*r1.h;
	a1=a1>>>15									     || r4=[i1++];
	r3=(a0+=a1);
   	a1 =r0.h*r1.l  (M),		a0 =r0.h*r1.h;
	a1+=r0.l*r2.l  (M),		a0+=r0.l*r2.h;
	a1=a1>>>15;
	r5=(a0+=a1)										 || r0=[i2++]	|| r2=[i1++m0];
		
	a1 =r0.l*r2.l  (M),		a0 =r0.l*r2.h			 || [i3]=r5;
    a1-=r0.h*r4.l  (M),		a0-=r0.h*r4.h;
	a1=a1>>>15;
	r5=(a0+=a1);
	a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h;
    a1+=r0.l*r4.l  (M),		a0+=r0.l*r4.h	         || r6=[i1++];
	a1=a1>>>15										 || r0=[i2++]	|| r2=[i3];
	r7=(a0+=a1)										 || r4=[i1++m0];
												 			
    a1 =r0.l*r4.l  (M),		a0 =r0.l*r4.h			 || [i3]=r7;
	a1-=r0.h*r6.l  (M),		a0-=r0.h*r6.h;
	a1=a1>>>15;
	r7=(a0+=a1);
   	a1 =r0.h*r4.l  (M),		a0 =r0.h*r4.h;
	a1+=r0.l*r6.l  (M),		a0+=r0.l*r6.h			 || r4=[i3--];
	a1=a1>>>15										 || r1=[i3--];
	r6=(a0+=a1)										 || r0=[i3];
	 	                                                        
	lsetup(SLastStartMid4, SLastEndMid4) lc0 = p5;

SLastStartMid4:	

		r0=r0+r2, r2=r0-r2;
		r4=r4+r6, r6=r4-r6 || i1+=4;
		r0=r0+r4, r4=r0-r4;
		r3=r1+r3, r1=r1-r3 || [i0++]=r0;
		r5=r5+r7, r7=r5-r7 || r0=[i1++];
		r1=r1+r5, r5=r1-r5 || [i3++]=r0   || r0=[i2++];
		r7=r2+r7, r2=r2-r7 || [i0++m0]=r1 || r1=[i1++m0];
		r3=r3+r6, r6=r3-r6 || [i0++]=r2   || r2=[i1++];

	    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h			 || r1=[i1++m0] || [i3++]=r1;
	    a1-=r0.l*r1.l  (M),		a0-=r0.l*r1.h			 || [i0++m0]=r3;
		a1=a1>>>15									     || r4=[i1++]   || [i0++]=r4;
		r3=(a0+=a1);
   		a1 =r0.h*r1.l  (M),		a0 =r0.h*r1.h;
		a1+=r0.l*r2.l  (M),		a0+=r0.l*r2.h;
		a1=a1>>>15										 || [i0++m0]=r5;
		r5=(a0+=a1)										 || r0=[i2++] || r2=[i1++m0];
														    		
    	a1 =r0.l*r2.l  (M),		a0 =r0.l*r2.h			 || [i3]=r5;
    	a1-=r0.h*r4.l  (M),		a0-=r0.h*r4.h			 || [i0++]=r7;
		a1=a1>>>15;
		r5=(a0+=a1);
	    a1 =r0.h*r2.l  (M),		a0 =r0.h*r2.h;
   		a1+=r0.l*r4.l  (M),		a0+=r0.l*r4.h			 || r6=[i1++]   || [i0++m0]=r6;
		a1=a1>>>15										 || r0=[i2++]	|| r2=[i3];
		r7=(a0+=a1)										 || r4=[i1++m0];
												 			
    	a1 =r0.l*r4.l  (M),		a0 =r0.l*r4.h			 || [i3]=r7;
	    a1-=r0.h*r6.l  (M),		a0-=r0.h*r6.h;
		a1=a1>>>15;
		r7=(a0+=a1)										 || i0+=4;
		a1 =r0.h*r4.l  (M),		a0 =r0.h*r4.h;
    	a1+=r0.l*r6.l  (M),		a0+=r0.l*r6.h			 || r4=[i3--];
		a1=a1>>>15										 || r1=[i3--];
SLastEndMid4: 
		r6=(a0+=a1)										 || r0=[i3];

	r0=r0+r2, r2=r0-r2;
	r4=r4+r6, r6=r4-r6;
	r0=r0+r4, r4=r0-r4;
	r3=r1+r3, r1=r1-r3 || [i0++]=r0;
	r5=r5+r7, r7=r5-r7;
	r1=r1+r5, r5=r1-r5;
	r7=r2+r7, r2=r2-r7 || [i0++m0]=r1;
	r3=r3+r6, r6=r3-r6 || [i0++]=r2;
		
	[i0++m0]=r3;
	[i0++]=r4;
	[i0++m0]=r5;
	[i0++]=r7;
	[i0++m0]=r6;

	jump _IFFTRad4Exit;

//********************************** Last Stage Rad2 *****************************************************
SLastRad2:
	l0 = 0;
	l1 = 0;
	r0 = m0;
	r0 += 8;
	m3 = r0;
	r0 = -r0;
	m0 = r0;
	i1 += m3;
	i1 -= 4;
	i0 = i1;
	i2 += 4;
	m1 = 12;
	m2 = -12;
	p5 = p5 >> 1;

	// Prologue	
	r7=[i2++m1];
	r2=[i1++];				// Real
	r3=[i1++m0];			// Imag

    a1 =r7.h*r2.l  (M),		a0 =r7.h*r2.h;
    a1-=r7.l*r3.l  (M),		a0-=r7.l*r3.h	|| r0=[i1++];							// Real
	a1=a1>>>15								|| r1=[i1++m3];							// Imag
	r5=(a0+=a1);
	
   	a1 =r7.h*r3.l  (M),		a0 =r7.h*r3.h;
	a1+=r7.l*r2.l  (M),		a0+=r7.l*r2.h;
	a1=a1>>>15;
	r4=(a0+=a1);
					
	// First half of twiddles
	lsetup(SLastRad2Start1, SLastRad2End1) lc0 = p5;

SLastRad2Start1:
		r0=r0+r4, r2=r0-r4						|| r7=[i2++m1];
		r3=r1+r5, r1=r1-r5						|| [i0++]=r2	|| r2=[i1++];		// Real;

	    a1 =r7.h*r2.l  (M),		a0 =r7.h*r2.h	|| r3=[i1++m0]	|| [i0++m0]=r3;		// Imag
	    a1-=r7.l*r3.l  (M),		a0-=r7.l*r3.h	|| r0=[i1++]	|| [i0++]=r0;		// Real
		a1=a1>>>15								|| r1=[i1++m3]	|| [i0++m3]=r1;		// Imag
		r5=(a0+=a1);

    	a1 =r7.h*r3.l  (M),		a0 =r7.h*r3.h;
   		a1+=r7.l*r2.l  (M),		a0+=r7.l*r2.h;
		a1=a1>>>15;
SLastRad2End1:
		r4=(a0+=a1);

	// Second half of twiddles
	lsetup(SLastRad2Start2, SLastRad2End2) lc0 = p5;

SLastRad2Start2:
		r0=r0+r4, r2=r0-r4						|| r7=[i2++m2];
		r3=r1+r5, r1=r1-r5						|| [i0++]=r2	|| r2=[i1++];		// Real;

	    a1 =r7.h*r2.l  (M),		a0 =r7.h*r2.h	|| r3=[i1++m0]	|| [i0++m0]=r3;		// Imag
	    a1+=r7.l*r3.l  (M),		a0+=r7.l*r3.h	|| r0=[i1++]	|| [i0++]=r0;		// Real
		a1=a1>>>15								|| r1=[i1++m3]	|| [i0++m3]=r1;		// Imag
		r5=(a0+=a1);

    	a1 =r7.h*r3.l  (M),		a0 =r7.h*r3.h;
   		a1-=r7.l*r2.l  (M),		a0-=r7.l*r2.h;
		a1=a1>>>15;
SLastRad2End2:
		r4=(a0+=a1);

	r0=r0+r4, r2=r0-r4							|| r7=[i2++m2];
	r3=r1+r5, r1=r1-r5							|| [i0++]=r2	|| r2=[i1++];		// Real;

	// Epilogue		
    a1 =r7.h*r2.l  (M),		a0 =r7.h*r2.h		|| r3=[i1++m0]	|| [i0++m0]=r3;		// Imag
    a1+=r7.l*r3.l  (M),		a0+=r7.l*r3.h		|| r0=[i1++]	|| [i0++]=r0;		// Real
	a1=a1>>>15									|| r1=[i1++m3]	|| [i0++m3]=r1;		// Imag
	r5=(a0+=a1);

   	a1 =r7.h*r3.l  (M),		a0 =r7.h*r3.h;
	a1-=r7.l*r2.l  (M),		a0-=r7.l*r2.h;
	a1=a1>>>15;
	r4=(a0+=a1);

	r0=r0+r4, r2=r0-r4;
	r3=r1+r5, r1=r1-r5							|| [i0++]=r2;

	[i0++m0]=r3;
	[i0++]=r0;
	[i0++m3]=r1;

//************************************ Exit *******************************************************
_IFFTRad4Exit:
	l0 = 0;
	l1 = 0;	

    (P5:3) = [SP++];        
    (R7:4) = [SP++];        // Restore all registers that were saved

    RTS;
    NOP;                    // If link or unlink happens to be the next 
                            // instruction after RTS in memory, RTS takes one 
                            // extra cycle than expected. NOP is put to avoid 
                            // this.
	
_IFFTRad4.end: nop;

