SRC = BitVector.c
OBJS = BitVector.o

ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
LIB = libbitvector.so
else
LIB = libbitvector.a
endif


all: $(LIB)

$(LIB): $(OBJS)
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(CC) -shared -Wl,-soname,$@ -o $@ $^ -lc
else
	$(AR) crv $@ $(OBJS)
endif

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF /lib/libbitvector.so

clean:
	-rm -f $(LIB) *.o
