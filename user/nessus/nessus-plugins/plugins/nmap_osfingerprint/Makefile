include ../../nessus.tmpl

PLUGNAME=nmap_osfingerprint
OBJS = main.o \
	nmap.o \
	targets.o \
	tcpip.o \
	nmap_error.o \
	utils.o \
	osscan.o \
	output.o \
	timing.o \
	portlist.o 

LO_OBJS = main.lo \
	nmap.lo \
	targets.lo \
	tcpip.lo \
	nmap_error.lo \
	utils.lo \
	osscan.lo \
	output.lo \
	timing.lo \
	portlist.lo 	

NMAP_STUFF=-DNMAP_VERSION=\"3.00\" -DLOCALSTATEDIR=\"$(localstatedir)\"

all : $(PLUGNAME).nes


.c.o:
	$(LIBTOOL) $(CC) $(DEFS) $(NMAP_STUFF) $(include) -c $<
     


$(PLUGNAME).nes : $(OBJS)
	$(LIBTOOL) $(CC) $(DEFS) -o lib$(PLUGNAME).la $(LO_OBJS) $(LIBS) -lm $(LIBUTIL) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
