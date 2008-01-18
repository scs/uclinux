/*
 * imgcvt.S
 *
 * Copyright (C) 2007 Marc Hoffman <marc.hoffman@analog.com>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "config_bfin.h"




#define ARG_vdst        20
#define ARG_width       24
#define ARG_height      28
#define ARG_lumStride   32
#define ARG_chromStride 36
#define ARG_srcStride   40

DEFUN(uyvytoyv12, mL3,  (const uint8_t *src, uint8_t *ydst, uint8_t *udst, uint8_t *vdst,
                         long width, long height,
                         long lumStride, long chromStride, long srcStride)):
        link 0;
        [--sp] = (r7:4,p5:4);

        p0 = r1;       // Y top even

        i2 = r2; // *u
        r2 = [fp + ARG_vdst];
        i3 = r2; // *v

        r1 = [fp + ARG_srcStride];
        r2 = r0 + r1;
        r1 += -8;  // i0,i1 is pre read need to correct
        m0 = r1;

        i0 = r0;  // uyvy_T even
        i1 = r2;  // uyvy_B odd

        p2 = [fp + ARG_lumStride];
        p1 = p0 + p2;  // Y bot odd

        p5 = [fp + ARG_width];
        p4 = [fp + ARG_height];
        r0 = p5;
        p4 = p4 >> 1;
        p5 = p5 >> 2;

        r2 = [fp + ARG_chromStride];
        r0 = r0 >> 1;
        r2 = r2 - r0;
        m1 = r2;

        /*   I0,I1 - src input line pointers
         *   p0,p1 - luma output line pointers
         *   I2    - dstU
         *   I3    - dstV
         */

        lsetup (0f, 1f) lc1 = p4;   // H/2
0:        r0 = [i0++] || r2 = [i1++];
          r1 = [i0++] || r3 = [i1++];
          r4 = byteop1p(r1:0, r3:2);
          r5 = byteop1p(r1:0, r3:2) (r);
          lsetup (2f, 3f) lc0 = p5; // W/4
2:          r0 = r0 >> 8(v);
            r1 = r1 >> 8(v);
            r2 = r2 >> 8(v);
            r3 = r3 >> 8(v);
            r0 = bytepack(r0, r1);
            r2 = bytepack(r2, r3)         ||  [p0++] = r0;    // yyyy
            r6 = pack(r5.l, r4.l)         ||  [p1++] = r2;    // yyyy
            r7 = pack(r5.h, r4.h)         ||  r0 = [i0++] || r2 = [i1++];
            r6 = bytepack(r6, r7)         ||  r1 = [i0++] || r3 = [i1++];
            r4 = byteop1p(r1:0, r3:2)     ||  w[i2++] = r6.l; // uu
3:          r5 = byteop1p(r1:0, r3:2) (r) ||  w[i3++] = r6.h; // vv

          i0 += m0;
          i1 += m0;
          i2 += m1;
          i3 += m1;
          p0 = p0 + p2;
1:        p1 = p1 + p2;

        (r7:4,p5:4) = [sp++];
        unlink;
        rts;
DEFUN_END(uyvytoyv12)



DEFUN(yuyvtoyv12, mL3,  (const uint8_t *src, uint8_t *ydst, uint8_t *udst, uint8_t *vdst,
                         long width, long height,
                         long lumStride, long chromStride, long srcStride)):
        link 0;
        [--sp] = (r7:4,p5:4);

        p0 = r1;       // Y top even

        i2 = r2; // *u
        r2 = [fp + ARG_vdst];
        i3 = r2; // *v

        r1 = [fp + ARG_srcStride];
        r2 = r0 + r1;
        r1 += -8;  // i0,i1 is pre read need to correct
        m0 = r1;

        i0 = r0;  // uyvy_T even
        i1 = r2;  // uyvy_B odd

        p2 = [fp + ARG_lumStride];
        p1 = p0 + p2;  // Y bot odd

        p5 = [fp + ARG_width];
        p4 = [fp + ARG_height];
        r0 = p5;
        p4 = p4 >> 1;
        p5 = p5 >> 2;

        r2 = [fp + ARG_chromStride];
        r0 = r0 >> 1;
        r2 = r2 - r0;
        m1 = r2;

        /*   I0,I1 - src input line pointers
         *   p0,p1 - luma output line pointers
         *   I2    - dstU
         *   I3    - dstV
         */

        lsetup (0f, 1f) lc1 = p4;   // H/2
0:        r0 = [i0++] || r2 = [i1++];
          r1 = [i0++] || r3 = [i1++];
          r4 = bytepack(r0, r1);
          r5 = bytepack(r2, r3);
          lsetup (2f, 3f) lc0 = p5; // W/4
2:          r0 = r0 >> 8(v) || [p0++] = r4;  // yyyy-even
            r1 = r1 >> 8(v) || [p1++] = r5;  // yyyy-odd
            r2 = r2 >> 8(v);
            r3 = r3 >> 8(v);
            r4 = byteop1p(r1:0, r3:2);
            r5 = byteop1p(r1:0, r3:2) (r);
            r6 = pack(r5.l, r4.l);
            r7 = pack(r5.h, r4.h)         ||  r0 = [i0++] || r2 = [i1++];
            r6 = bytepack(r6, r7)         ||  r1 = [i0++] || r3 = [i1++];
            r4 = bytepack(r0, r1)         ||  w[i2++] = r6.l; // uu
3:          r5 = bytepack(r2, r3)         ||  w[i3++] = r6.h; // vv

          i0 += m0;
          i1 += m0;
          i2 += m1;
          i3 += m1;
          p0 = p0 + p2;
1:        p1 = p1 + p2;

        (r7:4,p5:4) = [sp++];
        unlink;
        rts;
DEFUN_END(yuyvtoyv12)
