SUBDIRS=sharedlib helloworld constructor exceptions iostream

BUILD_SUBS=for i in $(SUBDIRS); do \
		make -C $$i $@; done

all:
%:
	$(BUILD_SUBS)

#romfs:
#	$(BUILD_SUBS)

#clean:
#	$(BUILD_SUBS)
