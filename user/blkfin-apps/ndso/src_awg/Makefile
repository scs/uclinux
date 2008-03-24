CFLAGS += -Wall

EXEC = awg
OBJS = awg.o cgivars.o htmllib.o parse.o readsamples.o

#CFLAGS += -g

all: $(EXEC)

romfs:
	$(ROMFSINST) $(EXEC) /home/httpd/cgi-bin/awg.cgi

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) -lm

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): cgivars.h htmllib.h 
