
OBJS = main.o magic.o fsm.o lcp.o ipcp.o auth.o options.o sys-linux.o
	# upap.o chap.o ccp.o

DEFS = -DUSE_MS_DNS=1 -D_linux_=1 -DNO_SYSLOG -DHAVE_PATHS_H -DXDEBUGALL
CFLAGS += $(INCNET) $(DEFS)
#CFLAGS := -I. -I../usr.include.net -I.. $(CFLAGS) $(INCNET) $(DEFS)
#LDLIBS = $(LIBNET)


all: pppd

pppd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/pppd

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

