
EXEC = dhrystone
OBJS = dhry_1.o dhry_2.o

CFLAGS += -DNO_PROTOTYPES=1

ifndef IP
IP=10.64.204.74
endif

ifndef ITT
ITT=10000000
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): dhry.h

results:
	cpu=`rsh -l root $(IP) 'grep "cpu MHz" /proc/cpuinfo' | awk -F ":" '{print $$2}' | awk -F "/" '{print $$1}' | sed 's/^[ \t]*//;s/[ \t]*$$//'` ;\
	echo "^ Flags ((standard ''CFLAGS'' include ''$(CFLAGS)''))  ^  size (bytes)  ^  Loops  ^  Dhrystones per Second ((Based on $(CC))) ^  Dhrystone MIPS ((DMIPS is obtained when the Dhrystone score is divided by 1,757 (the number of Dhrystones per second obtained on the VAX 11/780, nominally a 1 MIPS machine))  ^  DMIPS/MHz  ^";\
	( for level in -O{s,0,1,2,3}{" "," -fomit-frame-pointer"}{" "," -static"} ; do \
	    echo -n "| ''$${level}'' " | sed 's/ [ ]*/ /g' | sed "s/ '' /''/" ; \
	    touch dhry.h;\
	    $(MAKE) -s all CFLAGS="$(CFLAGS) $${level} -w" ;\
	    ls -l $(EXEC) | awk '{ORS = ""; print "  | " $$5 "  | $(ITT)  |  "}' ; \
	    rcp $(EXEC) root@$(IP):/var/$(EXEC) ; \
	    tmp=`rsh -l root $(IP) /var/$(EXEC) $(ITT)` ;\
	    echo $$cpu $$tmp | awk '{print $$NF "  |  " $$NF/1757 "  |  " $$NF/(1757*$$1) "  |" }' ; \
	  done; \
	)

