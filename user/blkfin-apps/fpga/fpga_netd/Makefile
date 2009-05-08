EXEC = fpga_netd
OBJS = fpga_netd.o

all: $(EXEC)

romfs:
	$(ROMFSINST) fpga_netd /bin/

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) -lpthread

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
