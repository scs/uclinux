ifndef ROOTDIR
	ROOTDIR = $(PWD)/../..

	-include hostbuild.import

	UCLINUX_BUILD_USER=1
	UCLINUX_BUILD_LIB=1
endif
