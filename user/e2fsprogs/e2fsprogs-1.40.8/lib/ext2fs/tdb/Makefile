all: tdbtool

tdb.c tdb.h tdbtool.c: 
	./build-tdb

tdbtool.o: tdbtool.c
	gcc -c tdbtool.c

tdbtool: tdb.o tdbtool.o
	gcc -o tdbtool tdb.o tdbtool.o

clean:
	rm -f tdb.c tdb.h tdb.o tdbtool tdbtool.c tdbtool.o .svninfo
	rm -rf .pc

