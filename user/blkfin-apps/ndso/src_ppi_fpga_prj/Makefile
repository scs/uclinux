CFLAGS += -Wall -ffast-math -lm 

EXEC = fpga
OBJS = cgivars.o htmllib.o ndso.o domath_fpga.o ppi.o FFT16x32rad4.o IFFT16x32rad4.o 

#CFLAGS += -g
FLTFLAGS = -s 0x2000 

all: $(EXEC)

romfs:
	$(ROMFSINST) fpga /home/httpd/cgi-bin/fpga.cgi
	
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) -lm -lbfdsp 

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): cgivars.h htmllib.h template.h
