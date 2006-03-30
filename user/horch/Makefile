# Make some example applications using can4linux device driver
# (c) 2003 port GmbH oe@port.de
#

EXEC = horch
OBJS = horch.o linux.o filter.o version.o socklib.o

VPATH=filter:socklib

# Used release tag for this software version
VERSION=2
REL=6
RELEASE=HORCH_$(VERSION)_$(REL)

CFLAGS += -I. -I ../../linux-2.6.x/drivers/char/can4linux
CFLAGS += -Wall -DTARGET_LINUX_BF -DLINUX_BF

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS-$(@)))
	exit


clean:
	rm -f $(EXEC) *.elf *.gdb *.o 

romfs:
	$(ROMFSINST) /bin/horch

version.c:	Makefile
	@echo "/* version file for horch, created by make */"   > $@
	@echo "char const horch_revision[] = \"$(VERSION).$(REL)$(PATCH)\";" >> $@
