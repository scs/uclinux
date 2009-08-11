VER = mpc-0.11.1

all: $(VER)/Makefile
	$(MAKE) -C $(VER)
clean:
	$(MAKE) -C $(VER) clean
romfs:
	$(MAKE) -C $(VER) romfs
	$(ROMFSINST) $(VER)/src/mpc /usr/bin/mpc
.PHONY: all clean romfs
