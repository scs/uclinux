# Makefile for src.fdpic

LIBG729AB = libg729ab.a
LIBG729AB_SO = libg729ab.so

COMPILER = bfin-linux-uclibc-gcc
ARCHIVER = bfin-linux-uclibc-ar 
ASM = $(COMPILER) -c  -DFDPIC

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

all: $(LIBG729AB) $(LIBG729AB_SO) 

# static pattern rule to convert FLAT to FDPIC

$(FLAT_SRC): %.asm: ../src.orig/%.asm globals.txt
	../script/flat2fdpic.pl $< $@

# build static and shared LIBS

$(LIBG729AB): $(LIBG729AB_OBJS)
	@echo "Linking $(LIBG729AB) static lib"
	$(ARCHIVER) r $(LIBG729AB) $(LIBG729AB_OBJS)

$(LIBG729AB_SO): $(LIBG729AB_OBJS)
	@echo "Linking $(LIBG729AB) shared lib"

	# partially link into one object file
	bfin-linux-uclibc-ld -r -o partial.o $(LIBG729AB_OBJS)

	# now make most symbols local.  This ensures any calls
	# don't use the PLT method which is not compatable with
	# the G729 asm (the asm uses the same registers as the 
	# PLT code)
	bfin-linux-uclibc-objcopy \
	-G _G729AB_ENC_PROCESS \
	-G _G729AB_ENC_RESET \
	-G _G729AB_DEC_PROCESS \
	-G _G729AB_DEC_RESET \
	partial.o partial_local.o

	# finally, create the .so
	$(COMPILER) -shared -o $(LIBG729AB_SO) partial_local.o \
	-Wl,-sep-code -Wl,-code-in-l1 -Wl,-z,now -Wl,-data-in-l1


clean:
	rm -f *.o
	rm -f $(LIBG729AB) $(LIBG729AB_SO)
 




