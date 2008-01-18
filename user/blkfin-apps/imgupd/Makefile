
EXEC = imgupd
OBJS = imgupd.o

CFLAGS += -DSERVER_IP='$(CONFIG_USER_IMGUPD_SERVER_IP)'

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

