
EXEC = ndso
OBJS = ndso.o cgivars.o htmllib.o int_fft.o

#CFLAGS += -g

all: $(EXEC)

romfs:

	$(ROMFSINST) /home/httpd/cgi-bin/$(EXEC)
	mv $(ROMFSDIR)/home/httpd/cgi-bin/ndso $(ROMFSDIR)/home/httpd/cgi-bin/ndso.cgi 
	
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBM)
	
	

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
	

$(OBJS): cgivars.h htmllib.h template.h
