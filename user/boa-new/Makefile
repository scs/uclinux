
.EXPORT_ALL_VARIABLES:
CFLAGS += -g
DIRS = src 

all romfs:
	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done

clean:
	for i in $(DIRS) ; do make -C $$i clean ; done

