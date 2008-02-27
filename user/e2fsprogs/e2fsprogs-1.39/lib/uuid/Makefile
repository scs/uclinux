
include ../../MCONFIG

LIBRARY = ../libuuid.a
OBJS =  clear.o \
		compare.o \
		copy.o \
		gen_uuid.o \
		isnull.o \
		pack.o \
		parse.o \
		unpack.o \
		unparse.o \
		uuid_time.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@

clean:
	rm -f $(OBJS) $(LIBRARY) *.gdb

$(OBJS): ../../MCONFIG
