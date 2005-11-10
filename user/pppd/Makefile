
.EXPORT_ALL_VARIABLES:

DIRS = pppd

all:
	for i in $(DIRS) ; do make -C $$i || exit $? ; done

romfs:
	for i in $(DIRS) ; do make -C $$i romfs || exit $? ; done
	mkdir -p ${ROMFSDIR}/etc/ppp
	$(ROMFSINST) etc.ppp/options /etc/ppp/
	$(ROMFSINST) etc.ppp/pap-secrets /etc/ppp/
	$(ROMFSINST) etc.ppp/chap-secrets /etc/ppp/

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done


