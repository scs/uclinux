EXEC = fpga_loader
OBJS = fpga_loader.o

CFLAGS += \
	  -DDEFAULT_SPIDEV=\"/dev/spidev0.1\" \
	  -DDEFAULT_PROG_B=\"/dev/gpio29\" \
	  -DDEFAULT_INT_B=\"/dev/gpio27\" \
	  -DDEFAULT_DONE=\"/dev/gpio28\"

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) -a "[ -e /home/firmware.bin ] && fpga_loader /home/firmware.bin" /etc/rc

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
 