
include ../../MCONFIG

OBJS=   feature.o fgetflags.o fsetflags.o fgetversion.o fsetversion.o \
		getflags.o getversion.o iod.o ls.o pe.o pf.o ps.o \
		setflags.o setversion.o uuid.o
LIBRARY = ../libe2p.a

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@

clean:
	rm -f $(OBJS) $(LIBRARY) *.gdb

$(OBJS): ../../MCONFIG
