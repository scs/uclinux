#include <stdio.h>
#include <ipod/ipod.h>
#include <ipod/ipod_io_file.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_string.h>
#include "ipod_atom.h"

char *inFileName = "sampledb/iPod_Control/iTunes/iTunesDB";
char *outFileName = "sampledb/iPod_Control/iTunes/iTunesDB.out";

ipod_atom readDatabase(char *fileName) {
	ipod_atom atom = NULL;
	FILE *f = fopen(fileName,"rb");
	if (f) {
		ipod_io io = ipod_io_file_new(f);
		atom = ipod_atom_read_next(io,0);
		fclose(f);
		ipod_io_file_free(io);
	} else {
		printf("%s: cannot open input file\n",inFileName);
	}
	return atom;
}

void writeDatabase(ipod_atom atom, char *fileName) {
	FILE *f = fopen(outFileName,"wb");
	if (f) {
		ipod_io io = ipod_io_file_new(f);
		ipod_atom_prepare_to_write(atom,atom,0);
		ipod_atom_write(atom,io,0);
		fclose(f);
		ipod_io_file_free(io);
	} else {
		printf("%s: cannot open output file\n",outFileName);
	}
}

void readWriteTest(void) {
	ipod_atom atom = readDatabase(inFileName);
	if (atom) {
		writeDatabase(atom,outFileName);
	}
	ipod_atom_free(atom);
}

int main(int argc, char **argv) {
	readWriteTest();
}
