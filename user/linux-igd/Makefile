
LIBS= $(LIBUPNP) $(LIBIXML) $(LIBTHREADUTIL) -lpthread 

CFLAGS += -Wall

all: upnpd

upnpd: main.o gatedevice.o pmlist.o util.o config.o 
	$(CC)  $(CFLAGS) $(LDFLAGS) main.o gatedevice.o pmlist.o util.o config.o $(LIBS) -o  $@ $(LDLIBS)
ifndef CONFIG_USER_LINUXIGD_DEFAULT
	cat etc/gatedesc.snapgear.in | sed -e 's/DEVICENAME\.IN/$(CONFIG_PRODUCT)/' > etc/gatedesc.snapgear
endif

clean:
	rm -f *.o upnpd
	rm -f etc/gatedesc.snapgear

install: upnpd
	@install -d /etc/linuxigd
	@install etc/gatedesc.xml /etc/linuxigd
	@install etc/gateconnSCPD.xml  /etc/linuxigd
	@install etc/gateicfgSCPD.xml /etc/linuxigd
	@install etc/dummy.xml /etc/linuxigd
	@install upnpd /usr/sbin
	@install etc/upnpd.conf /etc

romfs:
ifdef CONFIG_USER_LINUXIGD_LINUXIGD
	$(ROMFSINST) upnpd /bin/upnpd
	@if [ ! -d $(ROMFSDIR)/etc/linuxigd ]; then mkdir $(ROMFSDIR)/etc/linuxigd; fi
	$(ROMFSINST) etc/gateconnSCPD.xml /etc/linuxigd/gateconnSCPD.xml
	$(ROMFSINST) etc/gateicfgSCPD.xml /etc/linuxigd/gateicfgSCPD.xml
	$(ROMFSINST) etc/ligd.gif /etc/linuxigd/ligd.gif
	$(ROMFSINST) etc/dummy.xml /etc/linuxigd/dummy.xml
ifndef CONFIG_USER_LINUXIGD_DEFAULT
	$(ROMFSINST) etc/gatedesc.snapgear /etc/linuxigd/gatedesc.xml
else
	$(ROMFSINST) etc/gatedesc.xml /etc/linuxigd/gatedevice.xml
endif
endif
