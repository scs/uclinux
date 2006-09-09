ALSA_VER = 1.0.12

dir_y = 
dir_$(CONFIG_LIB_ALSA_LIB)                       += alsa-lib-$(ALSA_VER)
dir_$(CONFIG_LIB_ALSA_LIB_FORCE)                 += alsa-lib-$(ALSA_VER)
dir_$(CONFIG_USER_ALSA_UTILS)                    += alsa-utils-$(ALSA_VER)

all %::
	for i in $(sort $(dir_y)) ; do make -C $$i $@ || exit $$? ; done

romfs:
	if [ "$(CONFIG_LIB_ALSA_LIB)" = "y" ] || [ "$(CONFIG_LIB_ALSA_LIB_FORCE)" = "y" ] ; then \
		install_dir="alsa-lib-$(ALSA_VER)/DESTDIR" ; \
		for conf in `cd $$install_dir ; find usr/share/alsa -type f` ; do \
			$(ROMFSINST) -d $$install_dir/$$conf /$$conf || exit $$? ; \
		done ; \
	fi

	install_dir="alsa-utils-$(ALSA_VER)/DESTDIR" ; \
	for bin in `cd $$install_dir ; ls usr/bin/* usr/sbin/*` ; do \
		$(ROMFSINST) -d -e CONFIG_USER_ALSA_UTILS $$install_dir/$$bin /$$bin || exit $$? ; \
	done
