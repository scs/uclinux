# Makefile for dll test

all: libhelloworld.so test_dll

libhelloworld.so :
	bfin-linux-uclibc-gcc -o libhelloworld.so helloworld.c  -shared -mfdpic

test_dll :
	bfin-linux-uclibc-gcc -o test_dll test_dll.c -mfdpic -ldl

clean :
	rm -rf libhelloworld.so test_dll
