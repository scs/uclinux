dir_y =
dir_n =
dir_  =

dir_y += thttpd
dir_y += gnuplot
dir_$(CONFIG_USER_NDSO) += src_ndso
dir_$(CONFIG_USER_AWG)  += src_awg

all:
	for i in $(dir_y) ; do $(MAKE) -C $$i || exit $$? ; done

romfs:
	for i in $(dir_y) ; do $(MAKE) -C $$i $@ || exit $$? ; done

	$(ROMFSINST) -e CONFIG_USER_NDSO web_ndso /home/httpd/
	$(ROMFSINST) -e CONFIG_USER_NDSO -s index.htm /home/httpd/index.html

	$(ROMFSINST) -e CONFIG_USER_AWG web_awg /home/httpd/
	$(ROMFSINST) -e CONFIG_USER_AWG -s index.htm /home/httpd/index.html

clean:
	for i in $(dir_y) $(dir_n) $(dir_) ; do $(MAKE) -C $$i $@ || exit $$? ; done
