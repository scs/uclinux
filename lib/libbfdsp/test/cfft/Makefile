TARGET = __ADSPBLACKFIN__

# You may also try on other blackfin
PROCESSOR = __ADSPBF533__

# Enable Cycle count 
UCLINUX_OPTS = -D$(TARGET) -D$(PROCESSOR) -DDO_CYCLE_COUNTS

CC = bfin-uclinux-gcc

CFLAGS += -I ../../include  $(UCLINUX_OPTS) -g -fstack-limit-symbol=_stack_start
LDFLAGS += -Wl,-elf2flt
LIBS += ../../src/libbfdsp532.a

PROGS = cfft 

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

cfft: cfft.o

clean:
	rm -f  *.o $(PROGS) *.gdb
						
