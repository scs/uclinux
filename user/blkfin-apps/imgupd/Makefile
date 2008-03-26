
EXEC = imgupd
OBJS = imgupd.o

CFLAGS += -DSERVER_IP='$(CONFIG_USER_IMGUPD_SERVER_IP)' -ggdb3
#CFLAGS += -DSERVER_IP='192.168.1.3'

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

