
/****************************************************************************
 *									    *
 * 	Project Name- Video For Linux 2 For Blackfin 533 supoorted Platfors *
 *									    *
 ****************************************************************************

(C) Copyright 2005 -	Rrap Software Private Limited 
 
File Name:		bfin_v4l2_buffer_copy.S

Date Modified:		3rd March 3005	

Purpose:		This file copies YCRCB data from user buffer to output
			buffer which has blanking information embedded in it.
				
******************************************************************************/

/* This update function is written to address Even and Odd field issue.
 * In earlier function even field used to get written after copletion of
 * write to odd field. This can cause overlapping of images. The desired
 * way of doing is to "write fist line of odd field then first line of
 * even field, then second line of odd field and then second line of even
 k field and so on ..... This update functin do it in this way.
 */
.section .text.l1, "ax", @progbits;
.global _bfin_v4l2_copy_buffer ;
.type _bfin_v4l2_copy_buffer, STT_FUNC;

_bfin_v4l2_copy_buffer:


        [--SP]=(R7:0);
        [--sp]=(P5:0);
        [--sp] = rets;
        [--sp] = lc0;
        [--sp] = lb0;
        [--sp] = lt0;
        [--sp] = lc1;
        [--sp] = lb1;
        [--sp] = lt1;
	P0 = R0 ;	//Destination address
	P1.l = 0x79BC;
	P1.h = 0x0000;
	P0 = P0 + P1;
	P1 = R1 ;	//Source address

	P2.l = 0xDC38;	//Even odd field offset
	P2.h = 0x0006;	//Even odd field offset
	P2 = P0 +P2;	//Address of first line of Even field.

	P3 = 0x000005A0;	//(=1440 Decimal)Length of one YCRCB line.	
	P3 = P3 + P1 ;

	P4 = 0x00000106;	//(=262
	LSETUP(frame_copy_start, frame_copy_end) LC1 = P4;

	frame_copy_start:
		P4 = 0x00000168;	//No. of lines per field
		LSETUP(line_copy_start, line_copy_end) LC0=P4; 
line_copy_start:
			R0 = [P1++];
			[P0++] = R0 ;
	
			R0 = [P3++] ;
line_copy_end: 		[P2++] = R0 ;

		P4 = 0x00000114 ;
		P0 = P0 + P4; 
		P2 = P2 + P4;
		
		P4 = 0x000005A0 ;
		P1 = P1 + P4 ;
frame_copy_end:	P3 = P3 + P4 ;
	

        lt1 = [sp++];
        lb1 = [sp++];
        lc1 = [sp++];
        lt0 = [sp++];
        lb0 = [sp++];
        lc0 = [sp++];
        rets = [sp++];
        (P5:0)=[sp++];
        (R7:0)=[SP++];
	rts;
