UGLY_FILES := *.ko *.o *.mod.c *~
INSTALL_DIR := $(KDIR)/drivers/mmc/

obj-$(CONFIG_SPI_MMC) += spi_mmc.o

spi_mmc-objs := spi_mmc_core.o \
		mmc_spi_mode.o \

default:
	
transfer: clean copy

clean:
	rm -rf $(UGLY_FILES)

copy:
	rm -rf $(INSTALL_DIR)/spi_mmc
	cp -a ../spi_mmc $(INSTALL_DIR)
	rm -rf $(INSTALL_DIR)/spi_mmc/CVS

