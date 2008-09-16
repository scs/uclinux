# Makefile for script testing
# David Rowe 9 Oct 2006

TARGETS =  test1 test1fdpic \
           test2 test2fdpic \
           test3simgot

all: $(TARGETS)

clean: 
	rm  -f $(TARGETS) *fdpic.s
	rm -f *.out
	rm -f *.gdb

# testX and testXfdpic should give the same answers

# Test 1 - basic test of .s to .s in fdpic

test1.s : test1.c
	bfin-uclinux-gcc -S test1.c

test1fdpic.s: test1.s
	./flat2fdpic.pl test1.s test1fdpic.s --usep3

test1fdpic: test1fdpic.s
	bfin-uclinux-gcc -mfdpic test1fdpic.s -o test1fdpic

test1: test1.s
	bfin-uclinux-gcc -Wl,-elf2flt test1.s -o test1

# Test 2 - added + 2 offset

test2fdpic.s: test2.s
	./flat2fdpic.pl test2.s test2fdpic.s --usep3

test2fdpic: test2fdpic.s
	bfin-uclinux-gcc -mfdpic test2fdpic.s -o test2fdpic

test2: test1.s
	bfin-uclinux-gcc -Wl,-elf2flt test2.s -o test2

# Test 3 - simulated GOT 

test3.s : test3.c
	bfin-uclinux-gcc -S test3.c

test3simgot.s: test3.s
	./flat2fdpic.pl test3.s test3simgot.s --simgot=simgot.c

test3simgot: test3simgot.s simgot.c
	bfin-uclinux-gcc -Wl,-elf2flt test3simgot.s simgot.c -o test3simgot


