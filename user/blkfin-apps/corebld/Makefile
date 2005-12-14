
EXEC = corebld 
OBJS = corebld.o

all: $(EXEC) coreb

coreb.o:
	$(CC) -c -I ../../../uClibc/include coreb.S -o coreb.o

coreb: coreb.o coreb.lds
	$(CC) -N -M -T coreb.lds coreb.o -o coreb > coreb.map

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBM) $(LDLIBS) $(LIBGCC)

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /etc/coreb

clean:
	-rm -f $(EXEC) coreb *.map *.elf *.gdb *.o
