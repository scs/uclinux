include ../../nessus.tmpl

PLUGNAME=3com_hub

all : $(PLUGNAME).nes
	
$(PLUGNAME).nes : $(PLUGNAME).c
	$(LIBTOOL) $(CC) $(DEFS) $(include)  -I/usr/local/include `libnet-config --defines --cflags` -c  $(PLUGNAME).c
	$(LIBTOOL) $(CC) $(DEFS) -o lib$(PLUGNAME).la $(PLUGNAME).lo `libnet-config --defines --libs` -L/usr/local/lib $(LIBS) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o
