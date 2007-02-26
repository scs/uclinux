TARGET = __ADSPBLACKFIN__

UCLINUX_OPTS = -Wall -D$(TARGET) -D_FLOAT16_NO_INLINE

CC = bfin-uclinux-gcc

CFLAGS += -O0 -I $(PWD)/../../include  $(UCLINUX_OPTS)
LDFLAGS += -Wl,-elf2flt 
LIBS += $(PWD)/../../libbfdsp.a -lm

PROGS = addfl16_test subfl16_test mulfl16_test divfl16_test

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

addfl16_test: addfl16_test.o
subfl16_test: subfl16_test.o
mulfl16_test: mulfl16_test.o
divfl16_test: divfl16_test.o

clean:
	rm -f  *.o $(PROGS) *.gdb


