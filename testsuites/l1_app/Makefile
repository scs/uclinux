
CCF:= bfin-uclinux-gcc
CC:= bfin-linux-uclibc-gcc
CPPC:= bfin-linux-uclibc-g++
CFLAGS:= -fno-jump-tables -mfdpic
LDFLAGS:= -Wl,-elf2flt
L1FLAGS:= -Wl,--sep-code -Wl,--code-in-l1 -Wl,-z -Wl,now -Wl,--data-in-l1

all: test_helloworld test_helloworldcpp

test_helloworld: libhelloworld
	$(CC) -pie -o $@ $@.c -lhelloworld -L./ $(CFLAGS)

libhelloworld:
	$(CC) -shared -o libhelloworld.so helloworld.c $(CFLAGS) $(L1FLAGS)

test_helloworldcpp: libhelloworldcpp
	$(CPPC) -o test_helloworldcpp test_helloworld.cpp -lhelloworldcpp -L./ $(CFLAGS)

libhelloworldcpp:
	$(CPPC) -shared -o libhelloworldcpp.so helloworld.cpp $(CFLAGS)

clean:
	rm -rf *.o *.so *.gdb test_helloworld test_helloworldcpp
