
EXEC = fcd.cgi
OBJS = fcd.o cgivars.o htmllib.o i2c.o

#CFLAGS += -g

all: $(EXEC)

romfs:
	mkdir -p $(ROMFSDIR)/cgi-bin/
	$(ROMFSINST) /cgi-bin/$(EXEC)
#	mv $(ROMFSDIR)/cgi-bin/fcd $(ROMFSDIR)/cgi-bin/fcd.cgi 
	
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBM)
	
	

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
	

$(OBJS): cgivars.h htmllib.h
