; effect_asm.asm
;
; MMX assembly language video effect functions
;
; 2004 Richard Goedeken <SirRichard@fascinationsoftware.com>
;
; This software code is licensed under the MAME license. For
; more information about this license, read the following web page:
;
; http://www.mame.net/readme.html
;
;
; HISTORY:
;
;  2004-10-03
;   - added effect functions:
;     - effect_6tap_addline_15,    effect_6tap_render_15
;     - effect_scan2_15_15_direct, effect_scan2_16_15
;   - removed effect_setpalette_asm function
;   - added color conversion (blit_line_xx_yy_z) functions
;  2004-09-25
;   - added effect_6tap_render_16 function
;  2004-09-22:
;   - modified 6-tap filter to work with simplified effect.c code
;  2004-07-24:
;   - initial version, including the 6-tap sinc filter, and the scanline effect


bits 32
section .text
align 64

; functions exported for use from the C code
global blit_6tap_mmx_addline_15
global blit_6tap_mmx_addline_16
global blit_6tap_mmx_addline_32
global blit_6tap_mmx_render_line_15
global blit_6tap_mmx_render_line_16
global blit_6tap_mmx_render_line_32
global blit_scan2_h_mmx_15_15_direct
global blit_scan2_h_mmx_16_15
global blit_scan2_h_mmx_16_16
global blit_scan2_h_mmx_16_32
global blit_scan2_h_mmx_32_32_direct
global blit_line_32_16_1
global blit_line_32_16_1_mmx
global blit_line_32_15_1
global blit_line_32_15_1_mmx
global blit_line_32_16_2
global blit_line_32_15_2
global blit_line_32_16_3
global blit_line_32_15_3
global blit_line_32_16_x
global blit_line_32_15_x

; these are defined in effect.c
extern _6tap2x_buf0
extern _6tap2x_buf1
extern _6tap2x_buf2
extern _6tap2x_buf3
extern _6tap2x_buf4
extern _6tap2x_buf5

;**************************************************************************
;***                       6-Tap Sinc Filter                           ****
;**************************************************************************

;--------------------------------------------------------
;extern void blit_6tap_mmx_addline_15(const void *src0, unsigned count
;                                   unsigned int *u32lookup);
blit_6tap_mmx_addline_15:
  push ebp
  mov ebp, esp
  pushad

  ; first, move all of the previous lines up
  mov eax, [_6tap2x_buf0]
  mov ebx, [_6tap2x_buf1]
  mov [_6tap2x_buf0], ebx
  mov ebx, [_6tap2x_buf2]
  mov [_6tap2x_buf1], ebx
  mov ebx, [_6tap2x_buf3]
  mov [_6tap2x_buf2], ebx
  mov ebx, [_6tap2x_buf4]
  mov [_6tap2x_buf3], ebx
  mov ebx, [_6tap2x_buf5]
  mov [_6tap2x_buf4], ebx
  mov [_6tap2x_buf5], eax

  ; check to see if we have a new line or if we should just clear it
  mov esi, [ebp+8]
  test esi, esi
  jne input15_6tap_n1
  
  ; no new line (we are at bottom of image), so just clear the last line
  mov ecx, [ebp+12]			; count
  xor eax, eax
  shl ecx, 1
  mov edi, [_6tap2x_buf5]
  rep stosd
  jmp input15_6tap_done

  ; we have a new line, so first we need to do 15bpp to 32bpp conversion
input15_6tap_n1:
  mov ecx, [ebp+12]	;count
  xor edi, edi     	;index
  add ecx, 1
  shr ecx, 1
  mov [uCount], ecx
input15_tap6_convert_loop:
  movzx eax, word [esi+edi*2]
  movzx ebx, word [esi+edi*2+2]
  mov ecx, eax
  mov edx, ebx
  shl eax, 9
  shl ebx, 9
  shl ecx, 3
  shl edx, 3
  and eax, 0f80000h
  and ebx, 0f80000h
  shl ch, 3
  shl dh, 3
  and ecx, 0f8f8h
  and edx, 0f8f8h
  or eax, ecx
  or ebx, edx
  mov [PixLine+edi*4], eax
  mov [PixLine+edi*4+4], ebx
  add edi, 2
  sub dword [uCount], 1
  jne input15_tap6_convert_loop

  ; now let's horizontally filter it
  mov esi, PixLine
  mov edi, [_6tap2x_buf5]
  ; just replicate the first two pixels
  mov eax, [esi]
  mov ebx, [esi+4]
  add esi, 8
  mov [edi], eax
  mov [edi+4], eax
  mov [edi+8], ebx
  mov [edi+12], ebx
  add edi, 16
  ; now start the main loop  
  mov ecx, [ebp+12]
  sub ecx, 5
  pxor mm7, mm7
  movq mm6, [QW_6tapAdd]
input15_6tap_loop1:
  movd mm0, [esi]
  movd [edi], mm0
  punpcklbw mm0, mm7
  movd mm1, [esi+4]
  punpcklbw mm1, mm7
  movd mm2, [esi-4]
  punpcklbw mm2, mm7
  movd mm3, [esi+8]
  punpcklbw mm3, mm7
  movd mm4, [esi-8]
  punpcklbw mm4, mm7
  movd mm5, [esi+12]
  punpcklbw mm5, mm7
  paddw mm0, mm1
  paddw mm2, mm3
  psllw mm0, 2
  paddw mm4, mm5
  psubw mm0, mm2
  movq mm5, mm0
  psllw mm0, 2
  add esi, 4
  paddw mm0, mm5
  paddw mm4, mm6
  paddw mm0, mm4
  psraw mm0, 5
  packuswb mm0, mm0
  movd [edi+4], mm0
  add edi, 8
  sub ecx, 1
  jne input15_6tap_loop1
  ; finally, replicate the last three pixels
  mov eax, [esi]
  mov ebx, [esi+4]
  mov ecx, [esi+8]
  mov [edi], eax
  mov [edi+4], eax
  mov [edi+8], ebx
  mov [edi+12], ebx
  mov [edi+16], ecx
  mov [edi+20], ecx

input15_6tap_done:
  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;extern void blit_6tap_mmx_addline_16(const void *src0, unsigned count
;                                   unsigned int *u32lookup);
blit_6tap_mmx_addline_16:
  push ebp
  mov ebp, esp
  pushad

  ; first, move all of the previous lines up
  mov eax, [_6tap2x_buf0]
  mov ebx, [_6tap2x_buf1]
  mov [_6tap2x_buf0], ebx
  mov ebx, [_6tap2x_buf2]
  mov [_6tap2x_buf1], ebx
  mov ebx, [_6tap2x_buf3]
  mov [_6tap2x_buf2], ebx
  mov ebx, [_6tap2x_buf4]
  mov [_6tap2x_buf3], ebx
  mov ebx, [_6tap2x_buf5]
  mov [_6tap2x_buf4], ebx
  mov [_6tap2x_buf5], eax

  ; check to see if we have a new line or if we should just clear it
  mov esi, [ebp+8]
  test esi, esi
  jne indirect_6tap_n1
  
  ; no new line (we are at bottom of image), so just clear the last line
  mov edx, [ebp+12]			; count
  shl edx, 1
  xor eax, eax
  mov ecx, edx
  mov edi, [_6tap2x_buf5]
  rep stosd
  jmp indirect_6tap_done

  ; we have a new line, so first we need to do the palette lookup
indirect_6tap_n1:
  push ebp
  mov ecx, [ebp+12]	;count
  xor edi, edi     	;index
  add ecx, 3
  mov ebp, [ebp+16]	;lookup
  shr ecx, 2
  mov [uCount], ecx
tap6_lookup_loop:
  movzx eax, word [esi+edi*2]
  movzx ebx, word [esi+edi*2+2]
  movzx ecx, word [esi+edi*2+4]
  movzx edx, word [esi+edi*2+6]
  mov eax, [ebp+eax*4]
  mov ebx, [ebp+ebx*4]
  mov ecx, [ebp+ecx*4]
  mov edx, [ebp+edx*4]
  mov [PixLine+edi*4], eax
  mov [PixLine+edi*4+4], ebx
  mov [PixLine+edi*4+8], ecx
  mov [PixLine+edi*4+12], edx
  add edi, 4
  sub dword [uCount], 1
  jne tap6_lookup_loop
  pop ebp

  ; now let's horizontally filter it
  mov esi, PixLine
  mov edi, [_6tap2x_buf5]
  ; just replicate the first two pixels
  mov eax, [esi]
  mov ebx, [esi+4]
  add esi, 8
  mov [edi], eax
  mov [edi+4], eax
  mov [edi+8], ebx
  mov [edi+12], ebx
  add edi, 16
  ; now start the main loop  
  mov ecx, [ebp+12]
  sub ecx, 5
  pxor mm7, mm7
  movq mm6, [QW_6tapAdd]
indirect_6tap_loop1:
  movd mm0, [esi]
  movd [edi], mm0
  punpcklbw mm0, mm7
  movd mm1, [esi+4]
  punpcklbw mm1, mm7
  movd mm2, [esi-4]
  punpcklbw mm2, mm7
  movd mm3, [esi+8]
  punpcklbw mm3, mm7
  movd mm4, [esi-8]
  punpcklbw mm4, mm7
  movd mm5, [esi+12]
  punpcklbw mm5, mm7
  paddw mm0, mm1
  paddw mm2, mm3
  psllw mm0, 2
  paddw mm4, mm5
  psubw mm0, mm2
  movq mm5, mm0
  psllw mm0, 2
  add esi, 4
  paddw mm0, mm5
  paddw mm4, mm6
  paddw mm0, mm4
  psraw mm0, 5
  packuswb mm0, mm0
  movd [edi+4], mm0
  add edi, 8
  sub ecx, 1
  jne indirect_6tap_loop1
  ; finally, replicate the last three pixels
  mov eax, [esi]
  mov ebx, [esi+4]
  mov ecx, [esi+8]
  mov [edi], eax
  mov [edi+4], eax
  mov [edi+8], ebx
  mov [edi+12], ebx
  mov [edi+16], ecx
  mov [edi+20], ecx

indirect_6tap_done:
  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;extern void blit_6tap_mmx_addline_32(const void *src0, unsigned count,
;                                   unsigned int *u32lookup);
blit_6tap_mmx_addline_32:
  push ebp
  mov ebp, esp
  pushad

  ; first, move all of the previous lines up
  mov eax, [_6tap2x_buf0]
  mov ebx, [_6tap2x_buf1]
  mov [_6tap2x_buf0], ebx
  mov ebx, [_6tap2x_buf2]
  mov [_6tap2x_buf1], ebx
  mov ebx, [_6tap2x_buf3]
  mov [_6tap2x_buf2], ebx
  mov ebx, [_6tap2x_buf4]
  mov [_6tap2x_buf3], ebx
  mov ebx, [_6tap2x_buf5]
  mov [_6tap2x_buf4], ebx
  mov [_6tap2x_buf5], eax
  
  ; check to see if we have a new line or if we should just clear it
  mov esi, [ebp+8]
  test esi, esi
  jne direct_6tap_n1
  
  ; no new line (we are at bottom of image), so just clear the last line
  xor eax, eax
  mov ecx, [ebp+12]			; count
  shl ecx, 1
  mov edi, [_6tap2x_buf5]
  rep stosd
  jmp direct_6tap_done  

  ; we have a new line, so let's horizontally filter it
direct_6tap_n1:
  mov edi, [_6tap2x_buf5]
  ; just replicate the first two pixels
  mov eax, [esi]
  mov ebx, [esi+4]
  add esi, 8
  mov [edi], eax
  mov [edi+4], eax
  mov [edi+8], ebx
  mov [edi+12], ebx
  add edi, 16
  ; now start the main loop  
  mov ecx, [ebp+12]
  sub ecx, 5
  pxor mm7, mm7
  movq mm6, [QW_6tapAdd]
direct_6tap_loop1:
  movd mm0, [esi]
  movd [edi], mm0
  punpcklbw mm0, mm7
  movd mm1, [esi+4]
  punpcklbw mm1, mm7
  movd mm2, [esi-4]
  punpcklbw mm2, mm7
  movd mm3, [esi+8]
  punpcklbw mm3, mm7
  movd mm4, [esi-8]
  punpcklbw mm4, mm7
  movd mm5, [esi+12]
  punpcklbw mm5, mm7
  paddw mm0, mm1
  paddw mm2, mm3
  psllw mm0, 2
  paddw mm4, mm5
  psubw mm0, mm2
  movq mm5, mm0
  psllw mm0, 2
  add esi, 4
  paddw mm0, mm5
  paddw mm4, mm6
  paddw mm0, mm4
  psraw mm0, 5
  packuswb mm0, mm0
  movd [edi+4], mm0
  add edi, 8
  sub ecx, 1
  jne direct_6tap_loop1
  ; finally, replicate the last three pixels
  mov eax, [esi]
  mov ebx, [esi+4]
  mov ecx, [esi+8]
  mov [edi], eax
  mov [edi+4], eax
  mov [edi+8], ebx
  mov [edi+12], ebx
  mov [edi+16], ecx
  mov [edi+20], ecx

direct_6tap_done:
  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;extern void effect_6tap_15(void *dst0, void *dst1, unsigned count);
blit_6tap_mmx_render_line_15:
  push ebp
  mov ebp, esp
  pushad

  ; first we need to just copy the 3rd line into the first destination line
  mov ecx, [ebp+16]			; count
  mov esi, [_6tap2x_buf2]
  mov edi, [ebp+8]			; dst0
  shl ecx, 1
  call ConvertPix32To15

  ; now we need to vertically filter for the second line
  ; but we have to store it in a temporary buffer because it's 32 bits
  mov ecx, [ebp+16]			; count
  push ebp
  shl ecx, 1
  mov ebp, PixLine
  mov [uCount], ecx
  pxor mm7, mm7
  movq mm6, [QW_6tapAdd]
  ; load the index registers
  mov eax, [_6tap2x_buf0]
  mov ebx, [_6tap2x_buf1]
  mov ecx, [_6tap2x_buf2]
  mov edx, [_6tap2x_buf3]
  mov esi, [_6tap2x_buf4]
  mov edi, [_6tap2x_buf5]
VFilter_6tap_15_loop1:
  movd mm0, [ecx]
  add ecx, 4
  punpcklbw mm0, mm7
  movd mm1, [edx]
  add edx, 4
  punpcklbw mm1, mm7
  movd mm2, [ebx]
  add ebx, 4
  punpcklbw mm2, mm7
  movd mm3, [esi]
  add esi, 4
  punpcklbw mm3, mm7
  movd mm4, [eax]
  add eax, 4
  punpcklbw mm4, mm7
  movd mm5, [edi]
  add edi, 4
  punpcklbw mm5, mm7
  paddw mm0, mm1
  paddw mm2, mm3
  psllw mm0, 2
  paddw mm4, mm5
  psubw mm0, mm2
  paddw mm4, mm6
  movq mm5, mm0
  psllw mm0, 2
  paddw mm0, mm5
  paddw mm0, mm4
  movq mm1, mm0
  psraw mm0, 5
  psraw mm1, 7
  psubw mm0, mm1
  packuswb mm0, mm0
  movd [ebp], mm0
  add ebp, 4
  sub dword [uCount], 1
  jne VFilter_6tap_15_loop1
  pop ebp

  ; now convert the filtered pixels from 32 bits to 15
  mov ecx, [ebp+16]			; count
  mov esi, PixLine
  shl ecx, 1
  mov edi, [ebp+12]			; dst1
  call ConvertPix32To15
  
  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;extern void effect_6tap_16(void *dst0, void *dst1, unsigned count);
blit_6tap_mmx_render_line_16:
  push ebp
  mov ebp, esp
  pushad

  ; first we need to just copy the 3rd line into the first destination line
  mov ecx, [ebp+16]			; count
  mov esi, [_6tap2x_buf2]
  mov edi, [ebp+8]			; dst0
  shl ecx, 1
  call ConvertPix32To16

  ; now we need to vertically filter for the second line
  ; but we have to store it in a temporary buffer because it's 32 bits
  mov ecx, [ebp+16]			; count
  push ebp
  shl ecx, 1
  mov ebp, PixLine
  mov [uCount], ecx
  pxor mm7, mm7
  movq mm6, [QW_6tapAdd]
  ; load the index registers
  mov eax, [_6tap2x_buf0]
  mov ebx, [_6tap2x_buf1]
  mov ecx, [_6tap2x_buf2]
  mov edx, [_6tap2x_buf3]
  mov esi, [_6tap2x_buf4]
  mov edi, [_6tap2x_buf5]
VFilter_6tap_16_loop1:
  movd mm0, [ecx]
  add ecx, 4
  punpcklbw mm0, mm7
  movd mm1, [edx]
  add edx, 4
  punpcklbw mm1, mm7
  movd mm2, [ebx]
  add ebx, 4
  punpcklbw mm2, mm7
  movd mm3, [esi]
  add esi, 4
  punpcklbw mm3, mm7
  movd mm4, [eax]
  add eax, 4
  punpcklbw mm4, mm7
  movd mm5, [edi]
  add edi, 4
  punpcklbw mm5, mm7
  paddw mm0, mm1
  paddw mm2, mm3
  psllw mm0, 2
  paddw mm4, mm5
  psubw mm0, mm2
  paddw mm4, mm6
  movq mm5, mm0
  psllw mm0, 2
  paddw mm0, mm5
  paddw mm0, mm4
  movq mm1, mm0
  psraw mm0, 5
  psraw mm1, 7
  psubw mm0, mm1
  packuswb mm0, mm0
  movd [ebp], mm0
  add ebp, 4
  sub dword [uCount], 1
  jne VFilter_6tap_16_loop1
  pop ebp

  ; now convert the filtered pixels from 32 bits to 16
  mov ecx, [ebp+16]			; count
  mov esi, PixLine
  shl ecx, 1
  mov edi, [ebp+12]			; dst1
  call ConvertPix32To16
  
  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;extern void effect_6tap_32(void *dst0, void *dst1, unsigned count);
blit_6tap_mmx_render_line_32:
  push ebp
  mov ebp, esp
  pushad

  ; first we need to just copy the 3rd line into the first destination line
  mov ecx, [ebp+16]
  mov esi, [_6tap2x_buf2]
  mov edi, [ebp+8]
  shl ecx, 1
  rep movsd

  ; now we need to vertically filter for the second line
  mov ecx, [ebp+16]			; count
  push ebp
  shl ecx, 1
  mov ebp, [ebp+12]			; dst1
  mov [uCount], ecx
  pxor mm7, mm7
  movq mm6, [QW_6tapAdd]
  ; load the index registers
  mov eax, [_6tap2x_buf0]
  mov ebx, [_6tap2x_buf1]
  mov ecx, [_6tap2x_buf2]
  mov edx, [_6tap2x_buf3]
  mov esi, [_6tap2x_buf4]
  mov edi, [_6tap2x_buf5]
VFilter_6tap_loop1:
  movd mm0, [ecx]
  add ecx, 4
  punpcklbw mm0, mm7
  movd mm1, [edx]
  add edx, 4
  punpcklbw mm1, mm7
  movd mm2, [ebx]
  add ebx, 4
  punpcklbw mm2, mm7
  movd mm3, [esi]
  add esi, 4
  punpcklbw mm3, mm7
  movd mm4, [eax]
  add eax, 4
  punpcklbw mm4, mm7
  movd mm5, [edi]
  add edi, 4
  punpcklbw mm5, mm7
  paddw mm0, mm1
  paddw mm2, mm3
  psllw mm0, 2
  paddw mm4, mm5
  psubw mm0, mm2
  paddw mm4, mm6
  movq mm5, mm0
  psllw mm0, 2
  paddw mm0, mm5
  paddw mm0, mm4
  movq mm1, mm0
  psraw mm0, 5
  psraw mm1, 7
  psubw mm0, mm1
  packuswb mm0, mm0
  movd [ebp], mm0
  add ebp, 4
  sub dword [uCount], 1
  jne VFilter_6tap_loop1
  pop ebp

  popad
  pop ebp
  emms
  ret

;**************************************************************************
;***                       Scanlines Effect                            ****
;**************************************************************************

;--------------------------------------------------------
;void blit_scan2_h_mmx_15_15_direct(void *dst0, void *dst1, const void *src,
;                               unsigned count, unsigned int *u32lookup);
blit_scan2_h_mmx_15_15_direct:
  push ebp
  mov ebp, esp
  pushad

  ; now do the shading, 8 pixels at a time
  mov edi, [ebp+8]	;dst0
  mov edx, [ebp+12]	;dst1
  mov esi, [ebp+16]	;src0
  mov ecx, [ebp+20]	;count
  and edi, 0fffffff8h	;align destination
  add ecx, 7
  and edx, 0fffffff8h	;align destination
  shr ecx, 3
  movq mm7, [QW_15QuartMask]
scan2_15_direct_shade_loop:
  movq mm0, [esi]
  movq mm1, mm0
  movq mm2, [esi+8]
  movq mm3, mm2
  punpcklwd mm0, mm0
  punpckhwd mm1, mm1
  punpcklwd mm2, mm2
  punpckhwd mm3, mm3
  movq mm4, mm0
  movq mm5, mm1
  movq [edi], mm0
  psrlw mm4, 2
  movq [edi+8], mm1
  psrlw mm5, 2
  movq [edi+16], mm2
  pand mm4, mm7
  movq [edi+24], mm3
  pand mm5, mm7
  psubw mm0, mm4
  movq mm4, mm2
  psubw mm1, mm5
  movq mm5, mm3
  movq [edx], mm0
  psrlw mm4, 2
  movq [edx+8], mm1
  psrlw mm5, 2
  pand mm4, mm7
  pand mm5, mm7
  psubw mm2, mm4
  psubw mm3, mm5
  add esi, 16
  movq [edx+16], mm2
  add edi, 32
  movq [edx+24], mm3
  add edx, 32
  sub ecx, 1
  jne scan2_15_direct_shade_loop

  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;void blit_scan2_h_mmx_16_15 (void *dst0, void *dst1, const void *src,
;                         unsigned count, unsigned int *u32lookup);
blit_scan2_h_mmx_16_15:
  push ebp
  mov ebp, esp
  pushad

  ; first, do the table lookup
  push ebp
  mov ecx, [ebp+20]	;count
  xor edi, edi     	;index
  mov esi, [ebp+16]	;src0
  add ecx, 3
  mov ebp, [ebp+24]	;lookup
  shr ecx, 2
  mov [uCount], ecx
scan2_15_lookup_loop:
  movzx eax, word [esi+edi*2]
  movzx ebx, word [esi+edi*2+2]
  movzx ecx, word [esi+edi*2+4]
  movzx edx, word [esi+edi*2+6]
  mov eax, [ebp+eax*4]
  mov ebx, [ebp+ebx*4]
  mov ecx, [ebp+ecx*4]
  mov edx, [ebp+edx*4]
  mov [PixLine+edi*2], ax
  mov [PixLine+edi*2+2], bx
  mov [PixLine+edi*2+4], cx
  mov [PixLine+edi*2+6], dx
  add edi, 4
  sub dword [uCount], 1
  jne scan2_15_lookup_loop
  pop ebp

  ; now do the shading, 8 pixels at a time
  mov edi, [ebp+8]	;dst0
  mov edx, [ebp+12]	;dst1
  mov esi, PixLine
  mov ecx, [ebp+20]	;count
  and edi, 0fffffff8h	;align destination
  add ecx, 7
  and edx, 0fffffff8h	;align destination
  shr ecx, 3
  movq mm7, [QW_15QuartMask]
scan2_15_shade_loop:
  movq mm0, [esi]
  movq mm1, mm0
  movq mm2, [esi+8]
  movq mm3, mm2
  punpcklwd mm0, mm0
  punpckhwd mm1, mm1
  punpcklwd mm2, mm2
  punpckhwd mm3, mm3
  movq mm4, mm0
  movq mm5, mm1
  movq [edi], mm0
  psrlw mm4, 2
  movq [edi+8], mm1
  psrlw mm5, 2
  movq [edi+16], mm2
  pand mm4, mm7
  movq [edi+24], mm3
  pand mm5, mm7
  psubw mm0, mm4
  movq mm4, mm2
  psubw mm1, mm5
  movq mm5, mm3
  movq [edx], mm0
  psrlw mm4, 2
  movq [edx+8], mm1
  psrlw mm5, 2
  pand mm4, mm7
  pand mm5, mm7
  psubw mm2, mm4
  psubw mm3, mm5
  add esi, 16
  movq [edx+16], mm2
  add edi, 32
  movq [edx+24], mm3
  add edx, 32
  sub ecx, 1
  jne scan2_15_shade_loop

  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;void blit_scan2_h_mmx_16_16 (void *dst0, void *dst1, const void *src, 
;                         unsigned count, unsigned int *u32lookup);
blit_scan2_h_mmx_16_16:
  push ebp
  mov ebp, esp
  pushad

  ; first, do the table lookup
  push ebp
  mov ecx, [ebp+20]	;count
  xor edi, edi     	;index
  mov esi, [ebp+16]	;src0
  add ecx, 3
  mov ebp, [ebp+24]	;lookup
  shr ecx, 2
  mov [uCount], ecx
scan2_16_lookup_loop:
  movzx eax, word [esi+edi*2]
  movzx ebx, word [esi+edi*2+2]
  movzx ecx, word [esi+edi*2+4]
  movzx edx, word [esi+edi*2+6]
  mov eax, [ebp+eax*4]
  mov ebx, [ebp+ebx*4]
  mov ecx, [ebp+ecx*4]
  mov edx, [ebp+edx*4]
  mov [PixLine+edi*2], ax
  mov [PixLine+edi*2+2], bx
  mov [PixLine+edi*2+4], cx
  mov [PixLine+edi*2+6], dx
  add edi, 4
  sub dword [uCount], 1
  jne scan2_16_lookup_loop
  pop ebp

  ; now do the shading, 8 pixels at a time
  mov edi, [ebp+8]	;dst0
  mov edx, [ebp+12]	;dst1
  mov esi, PixLine
  mov ecx, [ebp+20]	;count
  and edi, 0fffffff8h	;align destination
  add ecx, 7
  and edx, 0fffffff8h	;align destination
  shr ecx, 3
  movq mm7, [QW_16QuartMask]
scan2_16_shade_loop:
  movq mm0, [esi]
  movq mm1, mm0
  movq mm2, [esi+8]
  movq mm3, mm2
  punpcklwd mm0, mm0
  punpckhwd mm1, mm1
  punpcklwd mm2, mm2
  punpckhwd mm3, mm3
  movq mm4, mm0
  movq mm5, mm1
  movq [edi], mm0
  psrlw mm4, 2
  movq [edi+8], mm1
  psrlw mm5, 2
  movq [edi+16], mm2
  pand mm4, mm7
  movq [edi+24], mm3
  pand mm5, mm7
  psubw mm0, mm4
  movq mm4, mm2
  psubw mm1, mm5
  movq mm5, mm3
  movq [edx], mm0
  psrlw mm4, 2
  movq [edx+8], mm1
  psrlw mm5, 2
  pand mm4, mm7
  pand mm5, mm7
  psubw mm2, mm4
  psubw mm3, mm5
  add esi, 16
  movq [edx+16], mm2
  add edi, 32
  movq [edx+24], mm3
  add edx, 32
  sub ecx, 1
  jne scan2_16_shade_loop

  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;void blit_scan2_h_mmx_16_32 (void *dst0, void *dst1, const void *src,
;                         unsigned count, unsigned int *u32lookup);
;
blit_scan2_h_mmx_16_32:
  push ebp
  mov ebp, esp
  pushad

  ; first, do the table lookup
  push ebp
  mov ecx, [ebp+20]	;count
  xor edi, edi     	;index
  mov esi, [ebp+16]	;src0
  add ecx, 3
  mov ebp, [ebp+24]	;lookup
  shr ecx, 2
  mov [uCount], ecx
scan2_lookup_loop:
  movzx eax, word [esi+edi*2]
  movzx ebx, word [esi+edi*2+2]
  movzx ecx, word [esi+edi*2+4]
  movzx edx, word [esi+edi*2+6]
  mov eax, [ebp+eax*4]
  mov ebx, [ebp+ebx*4]
  mov ecx, [ebp+ecx*4]
  mov edx, [ebp+edx*4]
  mov [PixLine+edi*4], eax
  mov [PixLine+edi*4+4], ebx
  mov [PixLine+edi*4+8], ecx
  mov [PixLine+edi*4+12], edx
  add edi, 4
  sub dword [uCount], 1
  jne scan2_lookup_loop
  pop ebp

  ; now do the shading, 8 pixels at a time
  mov edi, [ebp+8]	;dst0
  mov edx, [ebp+12]	;dst1
  mov esi, PixLine
  mov ecx, [ebp+20]	;count
  and edi, 0fffffff8h	;align destination
  add ecx, 3
  and edx, 0fffffff8h	;align destination
  shr ecx, 2
scan2_shade_loop:
  movq mm0, [esi]
  movq mm1, mm0
  movq mm2, [esi+8]
  movq mm3, mm2
  punpckldq mm0, mm0
  punpckhdq mm1, mm1
  movq [edi], mm0
  punpckldq mm2, mm2
  movq [edi+8], mm1
  punpckhdq mm3, mm3
  movq [edi+16], mm2
  movq mm4, mm0
  movq [edi+24], mm3
  movq mm5, mm1
  psrlq mm0, 2
  movq mm6, mm2
  psrlq mm1, 2
  pand mm0, [QW_32QuartMask]
  movq mm7, mm3
  psrlq mm2, 2
  psubw mm4, mm0
  movq mm0, [QW_32QuartMask]
  psrlq mm3, 2
  pand mm1, mm0
  movq [edx], mm4
  pand mm2, mm0
  psubw mm5, mm1
  pand mm3, mm0
  movq [edx+8], mm5
  psubw mm6, mm2
  psubw mm7, mm3
  movq [edx+16], mm6
  add esi, 16
  movq [edx+24], mm7
  add edi, 32
  add edx, 32
  sub ecx, 1
  jne scan2_shade_loop

  popad
  pop ebp
  emms
  ret

;--------------------------------------------------------
;void blit_scan2_h_mmx_32_32_direct(void *dst0, void *dst1, const void *src,
;                               unsigned count, unsigned int *u32lookup);
;
blit_scan2_h_mmx_32_32_direct:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+8]	;dst0
  mov edx, [ebp+12]	;dst1
  mov esi, [ebp+16]	;src0
  mov ecx, [ebp+20]	;count
  and edi, 0fffffff8h	;align destination
  add ecx, 3
  and edx, 0fffffff8h	;align destination
  shr ecx, 2
scan2_direct_shade_loop:
  movq mm0, [esi]
  movq mm1, mm0
  movq mm2, [esi+8]
  movq mm3, mm2
  punpckldq mm0, mm0
  punpckhdq mm1, mm1
  movq [edi], mm0
  punpckldq mm2, mm2
  movq [edi+8], mm1
  punpckhdq mm3, mm3
  movq [edi+16], mm2
  movq mm4, mm0
  movq [edi+24], mm3
  movq mm5, mm1
  psrlq mm0, 2
  movq mm6, mm2
  psrlq mm1, 2
  pand mm0, [QW_32QuartMask]
  movq mm7, mm3
  psrlq mm2, 2
  psubw mm4, mm0
  movq mm0, [QW_32QuartMask]
  psrlq mm3, 2
  pand mm1, mm0
  movq [edx], mm4
  pand mm2, mm0
  psubw mm5, mm1
  pand mm3, mm0
  movq [edx+8], mm5
  psubw mm6, mm2
  psubw mm7, mm3
  movq [edx+16], mm6
  add esi, 16
  movq [edx+24], mm7
  add edi, 32
  add edx, 32
  sub ecx, 1
  jne scan2_direct_shade_loop

  popad
  pop ebp
  emms
  ret

;**************************************************************************
;***                   Internal Color Conversions                      ****
;**************************************************************************

;--------------------------------------------------------
; IN:  esi == source  edi == destination  ecx == count
; OUT: trashed eax, ebx, ecx, edx, esi, edi
ConvertPix32To15:
  ; the idea here is to do 2 pixels at once
  push ebp
  mov ebp, ecx

cp15loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 3
  shr ch, 3
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 9
  shr edx, 9
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], cx
  add edi, 4
  sub ebp, 2
  jg cp15loop1

  pop ebp
  ret
  
;--------------------------------------------------------
; IN:  esi == source  edi == destination  ecx == count
; OUT: trashed eax, ebx, ecx, edx, esi, edi
ConvertPix32To16:
  ; the idea here is to do 2 pixels at once
  push ebp
  mov ebp, ecx

cp16loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 2
  shr ch, 2
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 8
  shr edx, 8
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], cx
  add edi, 4
  sub ebp, 2
  jg cp16loop1

  pop ebp
  ret
  
;**************************************************************************
;***                   External Color Conversions                      ****
;**************************************************************************

;------------------------------------------------------------------------------
; blit_line_32_16_1_mmx(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_16_1_mmx:
  push ebp
  mov ebp, esp
  push edi
  push esi

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  movq mm7, [QW_16BlueMask]
  sub ebp, esi
  movq mm6, [QW_16GreenMask]
  shr ebp, 4
  movq mm5, [QW_16RedMask]

bl3216_1mmx_loop1:
  movq mm0, [esi]
  movq mm1, [esi+8]
  add esi, 16
  movq mm2, mm0
  movq mm3, mm1
  pslld mm0, 8
  pslld mm1, 8
  pand mm0, mm7
  movq mm4, mm2
  pand mm1, mm7
  pslld mm2, 11
  pslld mm4, 13
  pand mm2, mm6
  pand mm4, mm5
  por mm2, mm4
  
  movq mm4, mm3
  pslld mm3, 11
  pslld mm4, 13
  pand mm3, mm6
  pand mm4, mm5
  por mm3, mm4
  por mm0, mm2
  por mm1, mm3

  psrad mm0, 16
  psrad mm1, 16
  packssdw mm0, mm1
  movq [edi], mm0
  add edi, 8
  sub ebp, 1
  jg bl3216_1mmx_loop1

  pop esi
  pop edi
  pop ebp
  emms
  ret

;------------------------------------------------------------------------------
; blit_line_32_16_1(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_16_1:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3216_1_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 2
  shr ch, 2
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 8
  shr edx, 8
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], cx
  add edi, 4
  sub ebp, 1
  jg bl3216_1_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_15_1_mmx(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_15_1_mmx:
  push ebp
  mov ebp, esp
  push edi
  push esi

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  movq mm7, [QW_15BlueMask]
  sub ebp, esi
  movq mm6, [QW_15GreenMask]
  shr ebp, 4
  movq mm5, [QW_15RedMask]

bl3215_1mmx_loop1:
  movq mm0, [esi]
  movq mm1, [esi+8]
  add esi, 16
  movq mm2, mm0
  movq mm3, mm1
  psrld mm0, 9
  psrld mm1, 9
  pand mm0, mm7
  movq mm4, mm2
  pand mm1, mm7
  psrld mm2, 6
  psrld mm4, 3
  pand mm2, mm6
  pand mm4, mm5
  por mm2, mm4
  
  movq mm4, mm3
  psrld mm3, 6
  psrld mm4, 3
  pand mm3, mm6
  pand mm4, mm5
  por mm3, mm4
  por mm0, mm2
  por mm1, mm3

  packssdw mm0, mm1
  movq [edi], mm0
  add edi, 8
  sub ebp, 1
  jg bl3215_1mmx_loop1

  pop esi
  pop edi
  pop ebp
  emms
  ret

;------------------------------------------------------------------------------
; blit_line_32_15_1(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_15_1:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3215_1_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 3
  shr ch, 3
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 9
  shr edx, 9
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], cx
  add edi, 4
  sub ebp, 1
  jg bl3215_1_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_16_2(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_16_2:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3216_2_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 2
  shr ch, 2
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 8
  shr edx, 8
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], ax
  mov [edi+4], cx
  mov [edi+6], cx
  add edi, 8
  sub ebp, 1
  jg bl3216_2_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_15_2(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_15_2:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3215_2_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 3
  shr ch, 3
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 9
  shr edx, 9
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], ax
  mov [edi+4], cx
  mov [edi+6], cx
  add edi, 8
  sub ebp, 1
  jg bl3215_2_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_16_3(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_16_3:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3216_3_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 2
  shr ch, 2
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 8
  shr edx, 8
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], ax
  mov [edi+4], ax
  mov [edi+6], cx
  mov [edi+8], cx
  mov [edi+10], cx
  add edi, 12
  sub ebp, 1
  jg bl3216_3_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_15_3(unsigned int *src, unsigned int *end, unsigned short *dest);
blit_line_32_15_3:
  push ebp
  mov ebp, esp
  pushad

  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3215_3_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 3
  shr ch, 3
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 9
  shr edx, 9
  or eax, ebx
  or ecx, edx
  mov [edi], ax
  mov [edi+2], ax
  mov [edi+4], ax
  mov [edi+6], cx
  mov [edi+8], cx
  mov [edi+10], cx
  add edi, 12
  sub ebp, 1
  jg bl3215_3_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_16_x(unsigned int *src, unsigned int *end, unsigned short *dest,
;                   unsigned int scale);
blit_line_32_16_x:
  push ebp
  mov ebp, esp
  pushad

  mov ecx, [ebp+20]
  mov [uCount], ecx
  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3216_x_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 2
  shr ch, 2
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 8
  shr edx, 8
  or eax, ebx
  or edx, ecx
  mov ecx, [uCount]
  rep stosw
  mov eax, edx
  mov ecx, [uCount]
  rep stosw
  sub ebp, 1
  jg bl3216_x_loop1

  popad
  pop ebp
  ret

;------------------------------------------------------------------------------
; blit_line_32_15_x(unsigned int *src, unsigned int *end, unsigned short *dest,
;                   unsigned int scale);
blit_line_32_15_x:
  push ebp
  mov ebp, esp
  pushad

  mov ecx, [ebp+20]
  mov [uCount], ecx
  mov edi, [ebp+16]
  mov esi, [ebp+8]
  mov ebp, [ebp+12]
  sub ebp, esi
  shr ebp, 3

bl3215_x_loop1:
  mov eax, [esi]
  mov ecx, [esi+4]
  add esi, 8
  mov ebx, eax
  mov edx, ecx
  shr ah, 3
  shr ch, 3
  and ebx, 0f80000h
  and edx, 0f80000h
  shr ax, 3
  shr cx, 3
  shr ebx, 9
  shr edx, 9
  or eax, ebx
  or edx, ecx
  mov ecx, [uCount]
  rep stosw
  mov eax, edx
  mov ecx, [uCount]
  rep stosw
  sub ebp, 1
  jg bl3215_x_loop1

  popad
  pop ebp
  ret

;**************************************************************************
;***                              Data                                 ****
;**************************************************************************
;____________________________________________________________________________
; Data_Block:
section .data
align 16

; memory pointers to various buffers


; global variables
uCount		dd	0

; MMX constants
align 32
QW_6tapAdd	dd	000100010h, 000000010h
QW_32QuartMask	dd	03f3f3f3fh, 03f3f3f3fh
QW_16QuartMask	dd	039e739e7h, 039e739e7h	; 0011 1001 1110 0111
QW_15QuartMask	dd	01ce71ce7h, 01ce71ce7h	; 0001 1100 1110 0111

QW_16RedMask    dd  0001f0000h, 0001f0000h
QW_16GreenMask  dd  007e00000h, 007e00000h
QW_16BlueMask   dd  0f8000000h, 0f8000000h

QW_15RedMask    dd  00000001fh, 00000001fh
QW_15GreenMask  dd  0000003e0h, 0000003e0h
QW_15BlueMask   dd  000007c00h, 000007c00h

;____________________________________________________________________________
; Uninitialized data
section .bss
align 64

PixLine		resd    4096

end
