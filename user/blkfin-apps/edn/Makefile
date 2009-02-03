EXEC = edn
OBJS = edn.o linux.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm $(LDLIBS)

clean:
	rm -f *.o $(EXEC) *.gdb

