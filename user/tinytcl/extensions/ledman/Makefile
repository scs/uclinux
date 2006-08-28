CFLAGS += -I$(TCLDIR)

OBJS=ledman.o

ifndef CONFIG_LIB_TINYTCL_STATIC
CFLAGS += -fpic

ledman.so: $(OBJS)
	$(CC) -shared $(SH_LDFLAGS) -o $@ $(OBJS) $(SH_LDLIBS)

else
all: $(OBJS)
	cp $(OBJS) ..
endif

clean:
	rm -f *.o *.so

romfs:
	@-mkdir -p $(ROMFSDIR)/lib/tcl
	$(ROMFSINST) /lib/tcl/ledman.so
