# Makefile for src.simgot

LIBG729AB = libg729ab.a

COMPILER = bfin-uclinux-gcc
ASM = $(COMPILER) -c
ARCHIVER = bfin-uclinux-ar 

UCLINUX_OPTS = -Wall 
TARGET_OPTS = -DFLAG533 -DNOTIMER

ASM_OPTS = $(UCLINUX_OPTS) $(TARGET_OPTS) 

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

#suffix rules

.SUFFIXES:
.SUFFIXES: .asm .o

.asm.o:
	@echo "Assembling $<"
	$(ASM) $(ASM_OPTS) -x assembler-with-cpp -o $@ $<

all: $(LIBG729AB) 

# static pattern rule to convert FLAT to simulated GOT asm

$(FLAT_SRC): %.asm: ../src.orig/%.asm globals.txt
	../script/flat2fdpic.pl $< $@ --simgot=simgot.c


$(LIBG729AB): $(LIBG729AB_OBJS)
	@echo "Linking $(LIBG729AB)"
	$(ARCHIVER) r $(LIBG729AB) $(LIBG729AB_OBJS)

clean:
	rm -f *.o
	rm -f $(LIBG729AB)
 




