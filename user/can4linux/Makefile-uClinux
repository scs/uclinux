# Make some example applications using can4linux device driver
# (c) 2003-2006 port GmbH oe@port.de
#
# this is used from within uClinuc user/can4linux

EXEC = ctest can_send receive receive-select \
	transmit transmit-select transmitblock \
	baud acceptance

CTEST_OBJS = ctest.o
CANSEND_OBJS = can_send.o
TRANSMITBLOCK_OBJS = transmitblock.o
TRANSMITSELECT_OBJS = transmit-select.o

CFLAGS += -I.
CFLAGS += -Wall

all: $(EXEC)

ctest: $(CTEST_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(CTEST_OBJS) $(LDLIBS$(LDLIBS-$(@)))

can_send: $(CANSEND_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(CANSEND_OBJS) $(LDLIBS$(LDLIBS-$(@)))

transmitblock: $(TRANSMITBLOCK_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(TRANSMITBLOCK_OBJS) $(LDLIBS$(LDLIBS-$(@)))

transmit-select: $(TRANSMITSELECT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(TRANSMITSELECT_OBJS) $(LDLIBS$(LDLIBS-$(@)))


receive: receive.o
	$(CC) $(LDFLAGS) -o $@ receive.o $(LDLIBS$(LDLIBS-$(@)))

receive-select: receive-select.o
	$(CC) $(LDFLAGS) -o $@ receive-select.o $(LDLIBS$(LDLIBS-$(@)))



clean:
	rm -f $(EXEC) *.elf *.gdb *.o

# place programs you like to have in the file system here
romfs:
	$(ROMFSINST) /bin/can_send
	$(ROMFSINST) /bin/receive

cp:
	cp $(EXEC) /z2
