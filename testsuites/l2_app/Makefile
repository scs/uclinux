
CCF:= bfin-uclinux-gcc
CC:= bfin-linux-uclibc-gcc
CPPC:= bfin-linux-uclibc-g++
CFLAGS:= -fno-jump-tables -mfdpic
LDFLAGS:= -Wl,-elf2flt
L2FLAGS:= -Wl,--sep-code -Wl,-z -Wl,now 

all: test_helloworld 

test_helloworld: libhelloworld
	$(CC)  -o $@ $@.c -lhelloworld -L./ $(CFLAGS)

libhelloworld:
	$(CC) -shared -o libhelloworld.so helloworld.c $(CFLAGS) $(L2FLAGS) 

clean:
	rm -rf *.o *.so *.gdb test_helloworld 
