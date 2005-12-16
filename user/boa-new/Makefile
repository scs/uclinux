
.EXPORT_ALL_VARIABLES:
CFLAGS += -g
DIRS = src examples

all romfs:
	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done

clean:
	for i in $(DIRS) ; do make -C $$i clean ; done

