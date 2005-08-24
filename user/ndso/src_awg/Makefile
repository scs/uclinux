
EXEC = awg
OBJS = awg.o cgivars.o htmllib.o parse.o readsamples.o

#CFLAGS += -g

all: $(EXEC)

romfs:

	$(ROMFSINST) /home/httpd/cgi-bin/$(EXEC)
	mv $(ROMFSDIR)/home/httpd/cgi-bin/awg $(ROMFSDIR)/home/httpd/cgi-bin/awg.cgi 
	
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBM)
	
	

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
	

$(OBJS): cgivars.h htmllib.h 
