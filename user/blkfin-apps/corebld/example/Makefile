CC = bfin-elf-gcc
CXX = bfin-elf-g++

# we have to clobber a bunch of flags as they are normally geared towards
# running under linux, not a bare metal environment like core b
CPPFLAGS =
CFLAGS  ?= -mcpu=bf561
CFLAGS  += -mmulticore -mcoreb
LDFLAGS  = $(CFLAGS)
ASFLAGS  = $(CFLAGS)

all: test_c test_cpp

test_c: test_c.o
	$(CC) -Wl,--verbose -Wl,-M $(LDFLAGS) $^ -o $@ > $@.map
	bfin-elf-objdump -x -D $@ > $@.dump

CXX_OBJS = test_cpp.o coreb_stub.o
test_cpp: $(CXX_OBJS) bf561.lds coreb.lds
	#bfin-elf-g++ -Wl,--verbose -Wl,-M -mcpu=bf561-0.3 -mmulticore -mcoreb $(CXX_OBJS) -o $@ > test_cpp.map
	$(CXX) -Wl,--verbose -Wl,-M -T coreb.lds $(LDFLAGS) $(CXX_OBJS) -o $@ > $@.map
	bfin-elf-objdump -x -D $@ > $@.dump

romfs:
	$(ROMFSINST) -d /usr/coreb/test_c
	$(ROMFSINST) -d /usr/coreb/test_cpp

clean:
	rm -f *.map *.dump *.elf *.gdb *.o test_c test_cpp 

.PHONY: all clean romfs
