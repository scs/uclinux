#/************************************************************************
#*
#* Makefile - LIBDSP (Blackfin)
#*
#* (c) Copyright 2002-2003 2006 Analog Devices, Inc.
#*
#*     Makefile developed for Blackfin Distributed Library Components.
#*     Libraries are built using uClinux GCC tool chain 
#************************************************************************/

# Libraries

LIBDSP       = libbfdsp$(PART)$(CSYNC).a
LIBDSP_M3RES = libbfdspm3res$(PART)$(CSYNC).a

# Utilities

#CROSS_COMPILE = bfin-uclinux-
#CC            = $(CROSS_COMPILE)gcc
#AR            = $(CROSS_COMPILE)ar

ARFLAGS   = rc
CFLAGS   += -Wall
CPPFLAGS += -I../include -D__ADSPBLACKFIN__
CFLAGS_M3RES = -ffixed-M3

# Source Path

VPATH = ..

# <complex.h> Lists

COMPLEX_C_SRC = \
   arg.c        \
   arg16.c      \
   cabs.c       \
   cadd16.c     \
   cdiv.c       \
   cexp.c       \
   cmlt16.c     \
   conj16.c     \
   csub16.c     \
   polar.c      \
   polar16.c    \
   cartesian16.c \
   norm.c \
   cartesian.c 

COMPLEX_ASM_SRC = \
   cabfr16.asm    \
   cdiv_fr16.asm  \
   cmul_fr32.asm

COMPLEX_C_OBJS   = $(COMPLEX_C_SRC:.c=.o)
COMPLEX_ASM_OBJS = $(COMPLEX_ASM_SRC:.asm=.o)

COMPLEX_C_M3RES_OBJS   = $(COMPLEX_C_SRC:.c=_m3res.o)
COMPLEX_ASM_M3RES_OBJS = $(COMPLEX_ASM_OBJS)

COMPLEX_OBJS       = $(COMPLEX_C_OBJS)       $(COMPLEX_ASM_OBJS)
COMPLEX_M3RES_OBJS = $(COMPLEX_C_M3RES_OBJS) $(COMPLEX_ASM_M3RES_OBJS)

# <filter.h> Lists

FILTER_C_SRC =        \
   twiddle_fr16.c     \
   twidfft2d_fr16.c   \
   twidfftrad2_fr16.c \
   twidfftrad4_fr16.c \
   twidfftf_fr16.c

FILTER_ASM_SRC =      \
   a_compress16.asm   \
   a_expand16.asm     \
   cfftf_fr16.asm     \
   cfftrad4_fr16.asm  \
   cfir_fr16.asm      \
   cifftrad4_fr16.asm \
   conv2d3x3_asm.asm  \
   conv2dasm.asm      \
   convolve_asm.asm   \
   cr2fftnasm.asm     \
   cr2x2fftnasm.asm   \
   fir_decima16.asm   \
   fir_fr16.asm       \
   fir_interp16.asm   \
   i2fftnasm.asm      \
   iir_fr16.asm       \
   ir2x2fftasm.asm    \
   mu_compress16.asm  \
   mu_expand16.asm    \
   r2fftnasm.asm      \
   r2x2fftnasm.asm    \
   rfftrad4asm.asm

FILTER_ASM_M3RES_SRC =      \
   a_compress16.asm         \
   a_expand16.asm           \
   cfftf_fr16.asm     \
   cfftrad4_m3res_fr16.asm  \
   cfir_fr16.asm            \
   cifftrad4_m3res_fr16.asm \
   conv2d3x3_asm.asm        \
   conv2dasm.asm            \
   convolve_asm.asm         \
   cr2fftnasm_m3res.asm     \
   cr2x2fftnasm_m3res.asm   \
   fir_decima16.asm         \
   fir_fr16.asm             \
   fir_interp16.asm         \
   i2fftnasm_m3res.asm      \
   iir_fr16.asm             \
   ir2x2fftasm_m3res.asm    \
   mu_compress16.asm        \
   mu_expand16.asm          \
   r2fftnasm.asm            \
   r2x2fftnasm_m3res.asm    \
   rfftrad4asm_m3res.asm

FILTER_C_OBJS   = $(FILTER_C_SRC:.c=.o)
FILTER_ASM_OBJS = $(FILTER_ASM_SRC:.asm=.o)

FILTER_C_M3RES_OBJS   = $(FILTER_C_SRC:.c=_m3res.o)
FILTER_ASM_M3RES_OBJS = $(FILTER_ASM_M3RES_SRC:.asm=.o)

FILTER_OBJS       = $(FILTER_C_OBJS)       $(FILTER_ASM_OBJS)
FILTER_M3RES_OBJS = $(FILTER_C_M3RES_OBJS) $(FILTER_ASM_M3RES_OBJS)

# <matrix.h> Lists

MATRIX_C_SRC = \
   cmatmmlt.c  \
   matmmltf.c  \
   transpm.c

MATRIX_ASM_SRC =    \
   cmatmmlt_asm.asm \
   matmmlt_fr16.asm \
   transpm_fr16.asm \
   fract28_4mul.asm

MATRIX_ASM_M3RES_SRC = \
   cmatmmlt_asm.asm    \
   matmmlt_fr16.asm    \
   transpm_fr16.asm

MATRIX_C_OBJS   = $(MATRIX_C_SRC:.c=.o)
MATRIX_ASM_OBJS = $(MATRIX_ASM_SRC:.asm=.o)

MATRIX_C_M3RES_OBJS   = $(MATRIX_C_SRC:.c=_m3res.o)
MATRIX_ASM_M3RES_OBJS = $(MATRIX_ASM_M3RES_SRC:.asm=.o)

MATRIX_OBJS       = $(MATRIX_C_OBJS)       $(MATRIX_ASM_OBJS)
MATRIX_M3RES_OBJS = $(MATRIX_C_M3RES_OBJS) $(MATRIX_ASM_M3RES_OBJS)

# <stats.h> Lists

STATS_C_SRC =  \
   autocoh.c   \
   autocorr.c  \
   crosscoh.c  \
   crosscorr.c \
   histogram.c \
   mean.c      \
   means.c     \
   rms.c       \
   var.c       

STATS_ASM_SRC =       \
   autocoh_fr16.asm   \
   autocorr_fr16.asm  \
   crosscoh_fr16.asm  \
   crosscorr_fr16.asm \
   histogram_fr16.asm \
   mean_fr16.asm      \
   rms_fr16.asm       \
   var_fr16.asm       \
   zerocross.asm      \
   zero_crossf.asm

STATS_C_OBJS   = $(STATS_C_SRC:.c=.o)
STATS_ASM_OBJS = $(STATS_ASM_SRC:.asm=.o)

STATS_C_M3RES_OBJS   = $(STATS_C_SRC:.c=_m3res.o)
STATS_ASM_M3RES_OBJS = $(STATS_ASM_OBJS)

STATS_OBJS       = $(STATS_C_OBJS)       $(STATS_ASM_OBJS)
STATS_M3RES_OBJS = $(STATS_C_M3RES_OBJS) $(STATS_ASM_M3RES_OBJS)

# <math.h> fract16 trig functions Lists

TRIG_16_C_SRC =

TRIG_16_ASM_SRC = \
   acos_fr16.asm  \
   asin_fr16.asm  \
   atan_fr16.asm  \
   atan2_fr16.asm \
   cos_fr16.asm   \
   sin_fr16.asm   \
   sqrt_fr16.asm  \
   tan_fr16.asm

TRIG_16_C_OBJS   = $(TRIG_16_C_SRC:.c=.o)
TRIG_16_ASM_OBJS = $(TRIG_16_ASM_SRC:.asm=.o)

TRIG_16_C_M3RES_OBJS   = $(TRIG_16_C_SRC:.c=_m3res.o)
TRIG_16_ASM_M3RES_OBJS = $(TRIG_16_ASM_OBJS)

TRIG_16_OBJS       = $(TRIG_16_C_OBJS)       $(TRIG_16_ASM_OBJS)
TRIG_16_M3RES_OBJS = $(TRIG_16_C_M3RES_OBJS) $(TRIG_16_ASM_M3RES_OBJS)

# <math.h> non-ANSI floating point trig functions Lists

TRIG_NSTDFLT_C_SRC = \
   alogf.c           \
   alog10f.c         \
   rsqrt.c           \
   cot.c

TRIG_NSTDFLT_ASM_SRC =

TRIG_NSTDFLT_C_OBJS   = $(TRIG_NSTDFLT_C_SRC:.c=.o)
TRIG_NSTDFLT_ASM_OBJS = $(TRIG_NSTDFLT_ASM_SRC:.asm=.o)

TRIG_NSTDFLT_C_M3RES_OBJS   = $(TRIG_NSTDFLT_C_SRC:.c=_m3res.o)
TRIG_NSTDFLT_ASM_M3RES_OBJS = $(TRIG_NSTDFLT_ASM_OBJS)

TRIG_NSTDFLT_OBJS       = $(TRIG_NSTDFLT_C_OBJS)       $(TRIG_NSTDFLT_ASM_OBJS)
TRIG_NSTDFLT_M3RES_OBJS = $(TRIG_NSTDFLT_C_M3RES_OBJS) \
                          $(TRIG_NSTDFLT_ASM_M3RES_OBJS)

# <math.h> floating point trig functions Lists

TRIG_FLT_C_SRC = \
   asin.c        \
   atan.c        \
   atan2.c       \
   ceil.c        \
   cos.c         \
   cosh.c        \
   exp.c         \
   floor.c       \
   fmod.c        \
   frexp.c       \
   log.c         \
   log10.c       \
   modf.c        \
   pow.c         \
   sin.c         \
   sinh.c        \
   tan.c         \
   tanh.c


TRIG_FLT_ASM_SRC = \
   sqrt.asm      

TRIG_FLT_C_OBJS   = $(TRIG_FLT_C_SRC:.c=.o)
TRIG_FLT_ASM_OBJS = $(TRIG_FLT_ASM_SRC:.asm=.o)

TRIG_FLT_C_M3RES_OBJS   = $(TRIG_FLT_C_SRC:.c=_m3res.o)
TRIG_FLT_ASM_M3RES_OBJS = $(TRIG_FLT_ASM_OBJS)

TRIG_FLT_OBJS       = $(TRIG_FLT_C_OBJS)       $(TRIG_FLT_ASM_OBJS)
TRIG_FLT_M3RES_OBJS = $(TRIG_FLT_C_M3RES_OBJS) $(TRIG_FLT_ASM_M3RES_OBJS)

# <vector.h> Lists

VECTOR_C_SRC = \
   cvecdotf.c  \
   cvecsaddf.c \
   cvecsmlt.c  \
   cvecssubf.c \
   cvecvaddf.c \
   cvecvmltf.c \
   cvecvsubf.c \
   vecdotf.c   \
   vecmaxf.c   \
   vecminf.c   \
   vecsaddf.c  \
   vecsmltf.c  \
   vecssubf.c  \
   vecvaddf.c  \
   vecvmltf.c  \
   vecvsubf.c  \
   vmaxlocf.c  \
   vminlocf.c

VECTOR_ASM_SRC =      \
   csadd.asm          \
   cssub.asm          \
   cvecdot_fr16.asm   \
   cvecsmult_fr16.asm \
   cvecvmult_fr16.asm \
   cvvadd.asm         \
   cvvsub.asm         \
   vecdot.asm         \
   vmax.asm           \
   vmaxloc.asm        \
   vmin.asm           \
   vminloc.asm        \
   vsadd.asm          \
   vsmlt.asm          \
   vssub.asm          \
   vvadd.asm          \
   vvmlt.asm          \
   vvsub.asm

VECTOR_C_OBJS   = $(VECTOR_C_SRC:.c=.o)
VECTOR_ASM_OBJS = $(VECTOR_ASM_SRC:.asm=.o)

VECTOR_C_M3RES_OBJS   = $(VECTOR_C_SRC:.c=_m3res.o)
VECTOR_ASM_M3RES_OBJS = $(VECTOR_ASM_OBJS)

VECTOR_OBJS       = $(VECTOR_C_OBJS)       $(VECTOR_ASM_OBJS)
VECTOR_M3RES_OBJS = $(VECTOR_C_M3RES_OBJS) $(VECTOR_ASM_M3RES_OBJS)

# <window.h> Lists

WINDOW_C_SRC =  \
   Lib_cos16_2PIx.c \
   gen_bart.c   \
   gen_black.c  \
   gen_gauss.c  \
   gen_hamm.c   \
   gen_hann.c   \
   gen_harris.c \
   gen_kaiser.c \
   gen_rect.c   \
   gen_trian.c  \
   gen_vonh.c

WINDOW_ASM_SRC =

WINDOW_C_OBJS   = $(WINDOW_C_SRC:.c=.o)
WINDOW_ASM_OBJS = $(WINDOW_ASM_SRC:.asm=.o)

WINDOW_C_M3RES_OBJS   = $(WINDOW_C_SRC:.c=_m3res.o)
WINDOW_ASM_M3RES_OBJS = $(WINDOW_ASM_OBJS)

WINDOW_OBJS       = $(WINDOW_C_OBJS)       $(WINDOW_ASM_OBJS)
WINDOW_M3RES_OBJS = $(WINDOW_C_M3RES_OBJS) $(WINDOW_ASM_M3RES_OBJS)

# Miscellaneous functions Lists

MISC_C_SRC = \
   counti.c  \
   countl.c  \
   fclipf.c  \
   max16.c   \
   min16.c   \
   signf.c   \
   fl32max.c \
   fl32min.c \
   trncr4u4.c \

MISC_ASM_SRC =    \
   clip_asm.asm   \
   clip_fr16.asm  \
   div16.asm      \
   divfract32.asm \
   fltcmp.asm     \
   fltsif.asm     \
   fltuif.asm     \
   fpadd.asm      \
   fpdiv.asm      \
   fpmult.asm     \
   fpsub.asm      \
   roundflti.asm  \
   sdiv32.asm     \
   sign_fr16.asm  \
   srem32.asm     \
   f32toi32z.asm  \
   f32tou32z.asm  \
   udiv32.asm     \
   urem32.asm     \
   isinf.asm      \
   isnan.asm      \
   ashfti64.asm   \
   lshfti64.asm   \
   muli64.asm     \
   mulu64.asm     \
   sdiv64.asm     \
   udiv64.asm     \
   remi64.asm     \
   remu64.asm     \
   trncr4i8.asm   \
   trncr4u8.asm   \
   floatdisf.asm  \
   floatdiuf.asm  \

FLOAT16_ASM_SRC = \
   absfl16.S \
   add_fl16.S \
   cmp_fl16.S \
   div_fl16.S \
   fitsfl16.S \
   fl162fl.S \
   fl162fr16.S \
   fl2fl16.S \
   fr162fl16.S \
   mul_fl16.S \
   negfl16.S \
   normfl16.S \
   sub_fl16.S \

FLOAT32_ASM_SRC = \
   absfl32.S \
   addfl32.S \
   cmpfl32.S \
   divfl32.S \
   fl322fl.S \
   fl322fr32.S \
   fl2fl32.S \
   fr322fl32.S \
   mulfl32.S \
   negfl32.S \
   normfl32.S \
   subfl32.S \

MISC_C_OBJS   = $(MISC_C_SRC:.c=.o)
MISC_ASM_OBJS = $(MISC_ASM_SRC:.asm=.o)

MISC_C_M3RES_OBJS   = $(MISC_C_SRC:.c=_m3res.o)
MISC_ASM_M3RES_OBJS = $(MISC_ASM_OBJS)

MISC_OBJS       = $(MISC_C_OBJS)       $(MISC_ASM_OBJS) $(FLOAT16_ASM_OBJS) $(FLOAT32_ASM_OBJS)
MISC_M3RES_OBJS = $(MISC_C_M3RES_OBJS) $(MISC_ASM_M3RES_OBJS) $(FLOAT16_ASM_OBJS) $(FLOAT32_ASM_OBJS)

FLOAT16_ASM_OBJS = $(FLOAT16_ASM_SRC:.S=.o)
FLOAT32_ASM_OBJS = $(FLOAT32_ASM_SRC:.S=.o)

# The version file

# Library Object Lists

LIBDSP_LIST       = $(COMPLEX_OBJS)      \
                    $(FILTER_OBJS)       \
                    $(MATRIX_OBJS)       \
                    $(STATS_OBJS)        \
                    $(TRIG_16_OBJS)      \
                    $(TRIG_NSTDFLT_OBJS) \
                    $(VECTOR_OBJS)       \
                    $(WINDOW_OBJS)       \
                    $(MISC_OBJS)        
                    #$(TRIG_FLT_OBJS)     

LIBDSP_M3RES_LIST = $(COMPLEX_M3RES_OBJS)      \
                    $(FILTER_M3RES_OBJS)       \
                    $(MATRIX_M3RES_OBJS)       \
                    $(STATS_M3RES_OBJS)        \
                    $(TRIG_16_M3RES_OBJS)      \
                    $(TRIG_NSTDFLT_M3RES_OBJS) \
                    $(VECTOR_M3RES_OBJS)       \
                    $(WINDOW_M3RES_OBJS)       \
                    $(MISC_M3RES_OBJS)        
                    #$(TRIG_FLT_M3RES_OBJS)     

# Suffix Rules

.SUFFIXES: .asm .c .o _m3res.o .S

%.a:
	$(AR) $(ARFLAGS) $@ $^

.asm.o:
	$(COMPILE.S) -x assembler-with-cpp $< -o $@

.c_m3res.o:
	$(COMPILE.c) $(CFLAGS_M3RES) $< -o $@

# Targets
#
#   all         : rebuild libdsp.a and libdspm3res.a and copies them
#                 into the parent directory
#   libdsp      : rebuild libdsp.a only
#   libdspm3res : rebuild libdspm3res.a only
#   clean       : remove all object files and libraries

all: $(LIBDSP) $(LIBDSP_M3RES)

libdsp: $(LIBDSP)

libdspm3res: $(LIBDSP_M3RES)

$(LIBDSP): $(LIBDSP_LIST)

$(LIBDSP_M3RES): $(LIBDSP_M3RES_LIST)

clean:
	rm -f $(LIBDSP_LIST) $(LIBDSP_M3RES_LIST)
	rm -f *.a

.PHONY: all clean libdsp libdspm3res

# Special Rules

cadd16.o:       CFLAGS += -fno-builtin
cadd16_m3res.o: CFLAGS += -fno-builtin
cmlt16.o:       CFLAGS += -fno-builtin
cmlt16_m3res.o: CFLAGS += -fno-builtin
csub16.o:       CFLAGS += -fno-builtin
csub16_m3res.o: CFLAGS += -fno-builtin
