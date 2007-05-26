CFLAGS += -Wall

EXEC = ndso
OBJS = ndso.o cgivars.o htmllib.o int_fft.o

#CFLAGS += -g

all: $(EXEC)

romfs:
	$(ROMFSINST) $(EXEC) /home/httpd/cgi-bin/ndso.cgi
	
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBM)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): cgivars.h htmllib.h template.h
