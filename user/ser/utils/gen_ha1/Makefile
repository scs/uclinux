
all: gen_ha1

gen_ha1: gen_ha1.o calc.o ../../md5.o
	$(CC) $(LDFLAGS) $(LDLIBS) -o gen_ha1 gen_ha1.o calc.o ../../md5.o

gen_ha1.o: gen_ha1.c
	$(CC) $(CFLAGS) -c gen_ha1.c

calc.o: calc.c calc.h
	$(CC) $(CFLAGS) -c calc.c


clean:
	rm -f *~ *.o gen_ha1

