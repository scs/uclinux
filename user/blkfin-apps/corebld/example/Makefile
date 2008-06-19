all: test_c test_cpp

coreb_stub.o: coreb_stub.S
	bfin-elf-gcc -mcpu=bf561-0.3 -mmulticore -mcoreb -c $< -o $@

test_c: test_c.o
	bfin-elf-gcc -Wl,--verbose -Wl,-M -mcpu=bf561-0.3 -mmulticore -mcoreb test_c.o -o $@ > test_c.map
	bfin-elf-objdump -x -D test_c > test_c.dump

test_c.o: test.c
	bfin-elf-gcc -mcpu=bf561-0.3 -mmulticore -mcoreb -c $< -o $@

test_cpp: test_cpp.o coreb_stub.o
	#bfin-elf-g++ -Wl,--verbose -Wl,-M -mcpu=bf561-0.3 -mmulticore -mcoreb test_cpp.o coreb_stub.o -o $@ > test_cpp.map
	bfin-elf-g++ -Wl,--verbose -Wl,-M -T coreb.lds -mcpu=bf561-0.3 -mmulticore -mcoreb test_cpp.o coreb_stub.o -o $@ > test_cpp.map
	bfin-elf-objdump -x -D test_cpp > test_cpp.dump

test_cpp.o: test.cpp
	bfin-elf-g++ -mcpu=bf561-0.3 -mmulticore -mcoreb -c $< -o $@

romfs:
	$(ROMFSINST) -d /usr/coreb/test_c
	$(ROMFSINST) -d /usr/coreb/test_cpp

clean:
	-rm -f *.map *.dump *.elf *.gdb *.o *.ko test_c test_cpp 
