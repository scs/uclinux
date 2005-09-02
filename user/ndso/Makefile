
dir_y =
dir_y += thttpd
dir_y += gnuplot
dir_$(CONFIG_USER_NDSO) += src_ndso
dir_$(CONFIG_USER_AWG)  += src_awg

ifdef CONFIG_USER_NDSO
WEBFOLDER := web_ndso
endif
ifdef CONFIG_USER_AWG
WEBFOLDER := web_awg
endif

all:
	for i in $(dir_y) ; do  make -C $$i || exit $? ; done

romfs:
	for i in $(dir_y) ; do  make -C $$i romfs || exit $? ; done
	cp -Rf ./$(WEBFOLDER)/* $(ROMFSDIR)/home/httpd
	chmod 666 $(ROMFSDIR)/home/httpd/*.htm

clean:
	for i in $(dir_y) ; do \
		[ ! -d $$i ] || make -C $$i clean; \
	done


