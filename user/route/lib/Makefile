
LIB = libroute.a
OBJS = activate.o ether.o inet6.o irda.o proc.o tunnel.o af.o fddi.o \
	inet6_gr.o loopback.o rose.o unix.o arcnet.o frame.o inet6_sr.o \
	masq_info.o rose_gr.o util-ank.o ash.o getargs.o inet_gr.o \
	netrom.o setroute.o util.o ax25.o getroute.o inet_sr.o netrom_gr.o \
	sit.o ax25_gr.o hdlclapb.o interface.o netrom_sr.o slip.o ddp.o \
	hippi.o ipx.o nstrcmp.o slip_ac.o ddp_gr.o hw.o ipx_gr.o ppp.o \
	sockets.o econet.o inet.o ipx_sr.o ppp_ac.o tr.o

CFLAGS += -D_GNU_SOURCE -D__USE_BSD -Ilib -I../ -I../include -I../../pppd/pppd
CFLAGS += $(INCNET)


all: $(LIB) $(EXEC)

$(LIB): $(OBJS)
	rm -f $(LIB)
	$(AR) crv $(LIB) $(OBJS)
	$(RANLIB) $(LIB)

clean:
	rm -f $(LIB) *.o

