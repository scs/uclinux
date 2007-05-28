ifndef ROOTDIR
	ROOTDIR = $(shell pwd)/../..

	-include hostbuild.import

ifndef UCLINUX_BUILD_LIB
	UCLINUX_BUILD_USER=1
endif
	UCLINUX_BUILD_LIB=1
endif
