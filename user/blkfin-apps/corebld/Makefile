
EXEC = corebld 
OBJS = corebld.o
NOLIB_FLAGS = -nostartfiles -nostdlib -nodefaultlibs

all: $(EXEC) coreb

coreb.o:
	$(CC) $(NOLIB_FLAGS) -c -I ../../../uClibc/include coreb.S -o coreb.o

coreb: coreb.o coreb.lds
	$(CC) $(NOLIB_FLAGS) -N -M -T coreb.lds coreb.o -o coreb > coreb.map

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBM) $(LDLIBS) $(LIBGCC)

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /etc/coreb

clean:
	-rm -f $(EXEC) coreb *.map *.elf *.gdb *.o
