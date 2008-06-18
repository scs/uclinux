#ifndef __SBC_MATH_H
#define __SBC_MATH_H

#include <stdint.h>

#define fabs(x) ((x) < 0 ?-(x) : (x))

#ifdef USE_FIXED

#ifndef USE_FIXED64

#define SCALE_PROTO4_TBL 15
#define SCALE_ANA4_TBL 16
#define SCALE_PROTO8_TBL 15
#define SCALE_ANA8_TBL 16
#define SCALE_SPROTO4_TBL 16
#define SCALE_SPROTO8_TBL 16
#define SCALE_NPROTO4_TBL 10
#define SCALE_NPROTO8_TBL 12
#define SCALE_SAMPLES 14
#define SCALE4_STAGE1_BITS 16
#define SCALE4_STAGE2_BITS 18
#define SCALE4_STAGED1_BITS 15
#define SCALE4_STAGED2_BITS 15
#define SCALE8_STAGE1_BITS 16
#define SCALE8_STAGE2_BITS 18
#define SCALE8_STAGED1_BITS 15
#define SCALE8_STAGED2_BITS 15

typedef int32_t sbc_fixed_t;

#else // USE_FIXED64

#define SCALE_PROTO4_TBL 0
#define SCALE_ANA4_TBL 0
#define SCALE_PROTO8_TBL 0
#define SCALE_ANA8_TBL 0
#define SCALE_SPROTO4_TBL 6
#define SCALE_SPROTO8_TBL 6
#define SCALE_NPROTO4_TBL 0
#define SCALE_NPROTO8_TBL 0
#define SCALE_SAMPLES 3
#define SCALE4_STAGE1_BITS 24
#define SCALE4_STAGE2_BITS 38
#define SCALE4_STAGED1_BITS 32
#define SCALE4_STAGED2_BITS 32
#define SCALE8_STAGE1_BITS 24
#define SCALE8_STAGE2_BITS 39
#define SCALE8_STAGED1_BITS 32
#define SCALE8_STAGED2_BITS 32

typedef int64_t sbc_fixed_t;

#endif // USE_FIXED64

#define DIV2(dst, src) {dst = src >> 1;}
#define SCALE4_STAGE1(src) (src >> SCALE4_STAGE1_BITS)
#define SCALE4_STAGE2(src) (src >> SCALE4_STAGE2_BITS)
#define SCALE4_STAGED1(src) (src >> SCALE4_STAGED1_BITS)
#define SCALE4_STAGED2(src) (src >> SCALE4_STAGED2_BITS)
#define SCALE8_STAGE1(src) (src >> SCALE8_STAGE1_BITS)
#define SCALE8_STAGE2(src) (src >> SCALE8_STAGE2_BITS)
#define SCALE8_STAGED1(src) (src >> SCALE8_STAGED1_BITS)
#define SCALE8_STAGED2(src) (src >> SCALE8_STAGED2_BITS)

#else // USE_FIXED

typedef double sbc_fixed_t;

#define DIV2(dst, src) {dst = src / 2;}
#define SCALE4_STAGE1(src) (src)
#define SCALE4_STAGE2(src) (src)
#define SCALE4_STAGED1(src) (src)
#define SCALE4_STAGED2(src) (src)
#define SCALE8_STAGE1(src) (src)
#define SCALE8_STAGE2(src) (src)
#define SCALE8_STAGED1(src) (src)
#define SCALE8_STAGED2(src) (src)

#endif // USE_FIXED

#define SBC_FIXED_0(val) {val = 0;}
#define ADD(dst, src)  {dst += src;}
#define SUB(dst, src)  {dst -= src;}
#define MUL(dst, a, b) {dst = (sbc_fixed_t)a * b;}
#define MULA(dst, a, b)  {dst += (sbc_fixed_t)a * b;}
#if 0
// replace one MULA invocation with MULAc to impose overflow tests
// use it to adjust scaling values in one place at a time
static inline void MULAc(sbc_fixed_t *dst, const int32_t a, const int32_t b) {
	sbc_fixed_t p = (sbc_fixed_t)a * b;
	// make sure the product isn't flipping the sign
	if((float)a * (float)b * (float)p < 0) {
		printf("sign flipped a = %x (%d) b = %x (%d) p = %x (%d)\n", a, a, b, b, p, p);
		exit(1);
	}
	// make sure the add isn't overflowing
	if( ((float)(*dst) + (float)p) * ((*dst) + p) < 0) {
		printf("sum overflowed dst = %x (%d) p = %x (%d) dst+p = %x (%d)\n", *dst, *dst, p, p, *dst+p, *dst+p);
		exit(1);
	}
	*dst += p;
}
#endif
#endif // __SBC_MATH_H
