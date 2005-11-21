LDFLAGS += -pthread -Wl,-elf2flt 

EXEC = ex1 ex2 ex3 ex4 ex5 ex6 ex7
OBJS = ex1.o ex2.o ex3.o ex4.o ex5.o ex6.o ex7.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) 

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o