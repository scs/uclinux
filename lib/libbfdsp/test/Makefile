TARGET = __ADSPBLACKFIN__

UCLINUX_OPTS = -Wall -D$(TARGET)

CC = bfin-uclinux-gcc

CFLAGS += -g -I ../include  $(UCLINUX_OPTS) 
LDFLAGS += -Wl,-elf2flt
LIBS += ../src/libbfdsp532.a

PROGS = math stats vector filter 

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

math: math.o
stats: stats.o
vector: vector.o
filter: filter.o

clean:
	rm -f  *.o $(PROGS) *.gdb
						
