DIRS = $(dir $(wildcard */configure))

DIRS_makefiles = $(patsubst %,build-%/Makefile,$(DIRS))

all: $(DIRS_makefiles)
	for d in $(DIRS) ; do $(MAKE) -C build-$$d || exit $$? ; done

%/Makefile:
	set -e ; \
	VER=$(patsubst build-%/Makefile,%,$@) ; \
	find $${VER} -type f -print0 | xargs -0 touch -r $${VER}/configure ; \
	rm -rf build-$${VER} ; \
	mkdir build-$${VER} ; \
	cd build-$${VER} ; \
	FONT=/usr/share/directfb-examples/decker.ttf \
	../$${VER}/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build-*

romfs:
	for i in df_andi df_bltload df_drivertest df_cpuload df_databuffer df_dok df_fire \
		df_flip df_fonts df_input df_joystick df_layer df_matrix df_netload \
		df_dioload df_palette df_particle df_porter df_video df_video_particle \
		df_stress df_texture df_window pss; \
	do \
		$(ROMFSINST) -d build-DirectFB-examples-1.0.1/src/$$i /usr/bin/$$i; \
	done
	$(ROMFSINST) -d build-DirectFB-examples-1.0.1/src/df_knuckles/df_knuckles /usr/bin/df_knuckles
	$(ROMFSINST) -d build-DirectFB-examples-1.0.1/src/spacedream/spacedream /usr/bin/spacedream
	$(ROMFSINST) -d build-DirectFB-examples-1.0.1/src/df_neo/df_neo /usr/bin/df_neo
	$(ROMFSINST) -d DirectFB-examples-1.0.1/data /usr/share/directfb-examples
	mkdir -p ${ROMFSDIR}/usr/share/directfb-examples/fonts
	mv ${ROMFSDIR}/usr/share/directfb-examples/decker.ttf ${ROMFSDIR}/usr/share/directfb-examples/fonts/decker.ttf
	mv ${ROMFSDIR}/usr/share/directfb-examples/df_neo/* ${ROMFSDIR}/usr/share/directfb-examples/
	rm -rf ${ROMFSDIR}/usr/share/directfb-examples/df_neo

.PHONY: all clean romfs
