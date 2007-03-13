TARGET = __ADSPBLACKFIN__

UCLINUX_OPTS = -Wall -D$(TARGET) -D_FLOAT16_NO_INLINE

CC = bfin-uclinux-gcc

CFLAGS += -O0 -I $(PWD)/../../include  $(UCLINUX_OPTS)
LDFLAGS += -Wl,-elf2flt 
LIBS += $(PWD)/../../libbfdsp.a -lm

PROGS = Verification

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

Verification: MatrixMulVec.o Verification.o 


clean:
	rm -f  *.o $(PROGS) *.gdb
TARGET = __ADSPBLACKFIN__

UCLINUX_OPTS = -Wall -D$(TARGET) -D_FLOAT16_NO_INLINE

CC = bfin-uclinux-gcc

CFLAGS += -O0 -I $(PWD)/../../include  $(UCLINUX_OPTS)
LDFLAGS += -Wl,-elf2flt 
LIBS += $(PWD)/../../libbfdsp.a -lm

PROGS = Verification

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

Verification: MatrixMulVec.o Verification.o 


clean:
	rm -f  *.o $(PROGS) *.gdb