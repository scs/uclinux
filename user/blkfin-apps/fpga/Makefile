dir_y = hs_conv_driver fpga-test fpga_netd fpga_loader
dir_n =
dir_  =
dir_all = $(dir_y) $(dir_n) $(dir_)

all romfs:
	for i in $(dir_y)   ; do $(MAKE) -C $$i $@ || exit $$? ; done
	$(ROMFSINST) fpga_firmware /home/

clean:
	for i in $(dir_all) ; do $(MAKE) -C $$i $@ || exit $$? ; done

.PHONY: all clean romfs
