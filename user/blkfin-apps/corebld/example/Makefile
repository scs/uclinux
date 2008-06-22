CC = bfin-elf-gcc
CXX = bfin-elf-g++

# we have to clobber a bunch of flags as they are normally geared towards
# running under linux, not a bare metal environment like core b
CPPFLAGS =
CFLAGS  += -mmulticore -mcoreb
LDFLAGS  = $(CFLAGS)
ASFLAGS  = $(CFLAGS)

all: test_c test_cpp

test_c: test_c.o
	$(CC) -Wl,--verbose -Wl,-M $(LDFLAGS) $^ -o $@ > $@.map
	bfin-elf-objdump -x -D $@ > $@.dump

test_cpp: test_cpp.o coreb_stub.o
	#bfin-elf-g++ -Wl,--verbose -Wl,-M -mcpu=bf561-0.3 -mmulticore -mcoreb test_cpp.o coreb_stub.o -o $@ > test_cpp.map
	$(CXX) -Wl,--verbose -Wl,-M -T coreb.lds $(LDFLAGS) $^ -o $@ > $@.map
	bfin-elf-objdump -x -D $@ > $@.dump

romfs:
	$(ROMFSINST) -d /usr/coreb/test_c
	$(ROMFSINST) -d /usr/coreb/test_cpp

clean:
	rm -f *.map *.dump *.elf *.gdb *.o test_c test_cpp 

.PHONY: all clean romfs
