
.EXPORT_ALL_VARIABLES:

DIRS = Tremor
EXEC = oggplay
OBJS = oggplay.o
XLIB = Tremor/libvorbisidec.a

EXEC2 = oggenc
OBJS2 = oggenc.o

.PHONY: clean romfs all $(DIRS)

all: $(DIRS) $(EXEC) $(EXEC2)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(XLIB) $(LDLIBS$(LDLIBS_$@))

oggplay.o: oggplay.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(DIRS) -Wall -Werror

$(EXEC2): $(OBJS2)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS$(LDLIBS_$@))

oggenc.o: oggenc.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(DIRS) -Wall -Werror

$(DIRS):
	make -C $@

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /bin/$(EXEC2)
#	for i in $(DIRS) ; do make -C $$i $@ || exit $?; done

clean:
	-rm -f $(EXEC) $(EXEC2) *.elf *.gdb *.o
	for i in $(DIRS) ; do make -C $$i clean ; done
