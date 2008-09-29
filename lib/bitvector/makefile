SRC = BitVector.c
OBJS = BitVector.o
LIB = libbitvector.so

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ -lc

romfs:
	$(ROMFSINST) /lib/libbitvector.so

clean:
	-rm -f $(LIB) *.o
