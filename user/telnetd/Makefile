
EXEC = telnetd
OBJS = telnetd.o state.o termstat.o slc.o sys_term.o \
	utility.o global.o authenc.o logwtmp.o logout.o

FLTFLAGS += -s 6144

CFLAGS += -DPARANOID_TTYS -DUSE_TERMIO -DKLUDGELINEMODE -D_GNU_SOURCE -Wall

ifdef CONFIG_DEFAULTS_LIBC_UCLIBC
LDLIBS := -lutil $(LDLIBS)
endif

ifdef CONFIG_USER_TELNETD_DOES_NOT_USE_OPENPTY
CFLAGS += -DCONFIG_USER_TELNETD_DOES_NOT_USE_OPENPTY
endif


all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lutil $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) -e CONFIG_USER_TELNETD_TELNETD \
		-a "telnet  stream tcp nowait root /bin/telnetd" /etc/inetd.conf

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): defs.h ext.h pathnames.h telnetd.h logwtmp.h logout.h

