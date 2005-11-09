
.EXPORT_ALL_VARIABLES:

DIRS = pppd

all:
	for i in $(DIRS) ; do make -C $$i || exit $? ; done

romfs:
	for i in $(DIRS) ; do make -C $$i romfs || exit $? ; done
	mkdir -p ${ROMFSDIR}/etc/ppp
	cp etc.ppp/options ${ROMFSDIR}/etc/ppp/
	cp etc.ppp/pap-secrets etc.ppp/chap-secrets ${ROMFSDIR}/etc/ppp/

clean:
	-for i in $(DIRS) ; do make -C $$i clean ; done


