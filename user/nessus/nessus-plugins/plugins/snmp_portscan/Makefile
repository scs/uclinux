include ../../nessus.tmpl

PLUGNAME=snmp_portscan

all : $(PLUGNAME).nes
$(PLUGNAME).nes : $(PLUGNAME).c
	$(LIBTOOL) $(CC) $(DEFS) $(include) -c  $(PLUGNAME).c
	$(LIBTOOL) $(CC) $(DEFS) -o lib$(PLUGNAME).la $(PLUGNAME).lo $(LIBS) \
	$(LIBUTIL) \
	-rpath $(rootdir)/bin/plugins
	../install_plug $(PLUGNAME) $(rootdir)
clean :
	@rm -fr *.lo *.nes *.la .libs
	@rm -fr *.o 
