# Makefile for g729ab/test
#
# Top level Makefile that builds all libraries and test programs
FDPIC_CC = bfin-linux-uclibc-gcc
FLAT_CC = bfin-uclinux-gcc

G729_CFLAGS += -I ../include/ -Wall -DG729_MULTI_INST
FLAT_LDFLAGS += -Wl,-elf2flt=-s100000
LDLIBS += -lpthread 

PROGS := g729ab_test g729ab_testsimgot g729ab_testfdpic g729ab_testfdpic_so 

all: $(PROGS)

../src.%:
	$(MAKE) -C $(patsubst %/libg729ab.a,%,$@)

# flat test program

g729ab_test.o: g729ab_test.c ../include/g729ab_codec.h
	$(FLAT_CC) $(G729_CFLAGS) -o g729ab_test.o -c $<

g729ab_test: g729ab_test.o ../src.orig/libg729ab.a
	$(FLAT_CC) $(FLAT_LDFLAGS) -o $@ $^ $(LDLIBS) ../src.orig/libg729ab.a 

# simulated GOT flat mode test program

simgot.o: ../src.simgot/simgot.c
	$(FLAT_CC) $(G729_CFLAGS) -c $<

g729ab_testsimgot.o: g729ab_test.c ../include/g729ab_codec.h
	$(FLAT_CC) $(G729_CFLAGS) -DSIMGOT -o g729ab_testsimgot.o -c $<

g729ab_testsimgot: g729ab_testsimgot.o simgot.o ../src.simgot/libg729ab.a 
	$(FLAT_CC) $(FLAT_LDFLAGS) -o $@ $^ $(LDLIBS) 

# FDPIC test program - static lib version

g729ab_testfdpic.o: g729ab_test.c ../include/g729ab_codec.h
	$(FDPIC_CC) $(G729_CFLAGS) -fno-jump-tables -DFDPIC \
        -o g729ab_testfdpic.o -c $<

g729ab_testfdpic: g729ab_testfdpic.o ../src.fdpic/libg729ab.a
	$(FDPIC_CC) -o $@ $^ $(LDLIBS) -Wl,-data-in-l1 -pie -Wl,-sep-code \
              -Wl,-code-in-l1 -Wl,-z -Wl,now

# FDPIC test program - dlopen-ed shared lib version

g729ab_testfdpic_so.o: g729ab_test.c ../include/g729ab_codec.h
	$(FDPIC_CC) $(G729_CFLAGS) -fno-jump-tables -DFDPIC -DDLOPEN \
        -o g729ab_testfdpic_so.o -c $<

g729ab_testfdpic_so: g729ab_testfdpic_so.o
	$(FDPIC_CC)  -o $@ g729ab_testfdpic_so.o $(LDLIBS) -ldl

clean:
	rm -f *.o $(PROGS) *.gdb

.PHONY: all clean $(LIBDIRS)
