
EXEC = dhcpcd
OBJS = arp.o buildmsg.o client.o dhcpcd.o peekfd.o signals.o udpipgen.o

ifeq ($(findstring 2.0,$(LINUXDIR)),2.0)
CFLAGS += -DOLD_LINUX_VERSION=1
endif

CFLAGS += -D_BSD_SOURCE=1

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

