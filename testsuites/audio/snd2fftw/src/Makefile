snd2fftw: getopt.o main.o
	gcc -o snd2fftw main.c getopt.c -lm -lsndfile -lfftw3

CXXFLAGS=-I. -O -g -Wall

getopt.o: getopt.c getopt.h
main.o: main.c

install:
	cp snd2fftw /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/snd2fftw

clean:
	rm -f *.o snd2fftw
