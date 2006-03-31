TARGET = __ADSPBLACKFIN__
#PROCESSOR = __ADSPBF533__

#UCLINUX_OPTS = -D$(TARGET) -D__EDG_VERSION__=$(EDG_VERSION) -D$(PROCESSOR)
UCLINUX_OPTS = -D$(TARGET)

CC = bfin-uclinux-gcc

CFLAGS += -I ../../include  $(UCLINUX_OPTS) -g -fstack-limit-symbol=_stack_start
LDFLAGS += -Wl,-elf2flt
LIBS += ../../src/libbfdsp532.a

PROGS = fir 

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

fir: fir.o

clean:
	rm -f  *.o $(PROGS) *.gdb
						
