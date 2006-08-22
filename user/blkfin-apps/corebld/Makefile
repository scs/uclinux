
EXEC = corebld
OBJS = corebld.o
NOLIB_FLAGS = -nostartfiles -nostdlib -nodefaultlibs

all: $(EXEC) coreb coreb_get_testarg

coreb.o:
	$(CC) $(NOLIB_FLAGS) -c -I ../../../uClibc/include coreb.S -o coreb.o

coreb_get_testarg.o:
	$(CC) $(NOLIB_FLAGS) -c -I ../../../uClibc/include coreb_get_testarg.S -o coreb_get_testarg.o

coreb: coreb.o coreb.lds
	$(LD) $(NOLIB_FLAGS) -N -M -T coreb.lds coreb.o -o coreb > coreb.map

coreb_get_testarg: coreb_get_testarg.o coreb.lds
	$(LD) $(NOLIB_FLAGS) -N -T coreb.lds coreb_get_testarg.o -o coreb_get_testarg

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBM) $(LDLIBS) $(LIBGCC)

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /etc/coreb
	$(ROMFSINST) /bin/coreb_get_testarg

clean:
	-rm -f $(EXEC) coreb *.map *.elf *.gdb *.o coreb_get_testarg
