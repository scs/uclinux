CROSS := bfin-uclinux-
CC = $(CROSS)gcc
AS = $(CC)
AR = $(CROSS)ar

CFLAGS   = -Wall
CPPFLAGS = -DFLAG533 -DNOTIMER
ASFLAGS  = $(CFLAGS) $(CPPFLAGS)
ARFLAGS  := rc

LIBG729AB = libg729ab.a
LIBG729AB_SRC = \
	acelp_code_a.asm \
	dtx.asm \
	lpc.asm \
	pitch_a.asm \
	tab_dtxe.asm \
	allinitialdnew.asm \
	allinitialenew.asm \
	dec_ld8a.asm \
	lpcfunc.asm \
	postfilt.asm \
	coder.asm \
	dec_sid.asm \
	gainped.asm \
	lspgetq.asm \
	qua_lsp.asm \
	vad.asm \
	cod_ld8a.asm \
	dspfunc.asm \
	l1_function.asm \
	decoder.asm \
	tab_ld8a.asm \
	tab_ld8ae.asm \
	g729comd.asm \
	g729comc.asm \
	lspdec.asm \
	qua_gain.asm \
	tab_dtx.asm 

FLAT_SRC = \
	acelp_code_a.asm \
	dtx.asm \
	lpc.asm \
	pitch_a.asm \
	tab_dtxe.asm \
	allinitialdnew.asm \
	allinitialenew.asm \
	dec_ld8a.asm \
	gainped.asm \
	lspgetq.asm \
	qua_lsp.asm \
	lpcfunc.asm \
	postfilt.asm \
	coder.asm \
	dec_sid.asm \
	vad.asm \
	cod_ld8a.asm \
	dspfunc.asm \
	l1_function.asm \
	decoder.asm \
	tab_ld8a.asm \
	tab_ld8ae.asm \
	g729comd.asm \
	g729comc.asm \
	lspdec.asm \
	qua_gain.asm \
	tab_dtx.asm 

LIBG729AB_OBJS = $(LIBG729AB_SRC:.asm=.o)

.SUFFIXES:
.SUFFIXES: .asm .o

.asm.o:
	$(AS) $(ASFLAGS) -x assembler-with-cpp -c -o $@ $^
%.a:
	$(AR) $(ARFLAGS) $@ $^

all: $(LIBG729AB) 

$(FLAT_SRC): %.asm: ../src.orig/%.asm globals.txt
	../script/flat2fdpic.pl $< $@ --simgot=simgot.c

$(LIBG729AB): $(LIBG729AB_OBJS)

clean:
	rm -f *.o $(LIBG729AB)

.PHONY: all clean
