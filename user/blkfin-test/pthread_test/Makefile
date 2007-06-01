LDFLAGS += -pthread

EXEC = ex1 ex2 ex3 ex4 ex5 ex6 ex7 ptest

all: $(EXEC)

ex1: ex1.c
	$(CC) $(LDFLAGS) -o $@ ex1.c

ex2: ex2.c
	$(CC) $(LDFLAGS) -o $@ ex2.c

ex3: ex3.c
	$(CC) $(LDFLAGS) -o $@ ex3.c

ex4: ex4.c
	$(CC) $(LDFLAGS) -o $@ ex4.c

ex5: ex5.c
	$(CC) $(LDFLAGS) -o $@ ex5.c

ex6: ex6.c
	$(CC) $(LDFLAGS) -o $@ ex6.c

ex7: ex7.c
	$(CC) $(LDFLAGS) -o $@ ex7.c

ptest: ptest.cpp
	$(CXX) -O $(LDFLAGS) -o $@ ptest.cpp

romfs:
	$(ROMFSINST) /bin/ex1
	$(ROMFSINST) /bin/ex2
	$(ROMFSINST) /bin/ex3
	$(ROMFSINST) /bin/ex4
	$(ROMFSINST) /bin/ex5
	$(ROMFSINST) /bin/ex6
	$(ROMFSINST) /bin/ex7
	$(ROMFSINST) /bin/ptest

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
