
include ../../MCONFIG

OBJS    = error_message.o et_name.o init_et.o com_err.o
LIBRARY = ../libcom_err.a

all: $(LIBRARY) compile_et

compile_et: $(DEP_SUBSTITUTE) $(srcdir)/compile_et.sh.in
	$(SUBSTITUTE) $(srcdir)/compile_et.sh.in compile_et
	$(CHMOD) +x compile_et

$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@

clean:
	rm -f $(OBJS) $(LIBRARY) compile_et *.gdb

$(OBJS): ../../MCONFIG
