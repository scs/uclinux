
EXEC = fcd.cgi
OBJS = fcd.o cgivars.o htmllib.o i2c.o getSinglePic.o bayer-lcv.o
#CFLAGS += -g

all: $(EXEC)

romfs:
	mkdir -p $(ROMFSDIR)/home/httpd/cgi-bin/
	mkdir -p $(ROMFSDIR)/home/httpd/pics/	
	$(ROMFSINST) /home/httpd/cgi-bin/$(EXEC)
#	mv $(ROMFSDIR)/home/httpd/cgi-bin/fcd $(ROMFSDIR)/cgi-bin/fcd.cgi 

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBM)



clean:
	-rm -f $(EXEC) *.elf *.gdb *.o


$(OBJS): cgivars.h htmllib.h
