dir_y = libinetutils
dir_$(CONFIG_USER_INETUTILS_RCP)   += rcp
dir_$(CONFIG_USER_INETUTILS_RSH)   += rsh
dir_$(CONFIG_USER_INETUTILS_RSHD)  += rshd

all %::
	for i in $(dir_y) ; do make -C $$i $@ || exit $$? ; done
