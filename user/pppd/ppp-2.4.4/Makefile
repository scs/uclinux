
.EXPORT_ALL_VARIABLES:

DIRS = pppd pppd/plugins

all:
	for i in $(DIRS) ; do make -C $$i || exit $? ; done

romfs:
	for i in $(DIRS) ; do make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -d etc.ppp /etc/ppp

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done


