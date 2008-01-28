
THDM_TARGET=thdm
MTDM_TARGET=mtdm
BCDM_TARGET=bcdm

THDM_OBJS=thdm.o
MTDM_OBJS=mtdm.o
BCDM_OBJS=bcdm.o

TARGETS=$(THDM_TARGET) $(MTDM_TARGET) $(BCDM_TARGET)

# .c.o:
# 	$(CC) $(CFLAGS) -o $@ -c $<

all:	$(TARGETS)

$(THDM_TARGET): $(THDM_OBJS) 
	$(CC) $(LDFLAGS) -o $@ $< -lpthread $(LDLIBS)

$(MTDM_TARGET): $(MTDM_OBJS) 
	$(CC) $(LDFLAGS) -o $@ $< -lpthread $(LDLIBS)

$(BCDM_TARGET): $(BCDM_OBJS) 
	$(CC) $(LDFLAGS) -o $@ $< -lpthread $(LDLIBS)

clean:
	rm -f $(TARGETS) *.gdb *.elf *.elf2flt *.o *~ core

romfs:
	$(ROMFSINST) /bin/$(MTDM_TARGET)
	$(ROMFSINST) /bin/$(THDM_TARGET)
	$(ROMFSINST) /bin/$(BCDM_TARGET)
	
