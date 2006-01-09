all clean:
	$(MAKE) -C utils $@ || exit 1
romfs:
	$(MAKE) -C utils -f ../Makefile real_romfs || exit 1
real_romfs:
	$(ROMFSINST) -e CONFIG_USER_YAFFS_UTILS /bin/mkyaffs
