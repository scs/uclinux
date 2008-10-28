
EXEC = whetstone
OBJS = whetstone.o

ifndef ITT
ITT = 30000
endif

ifndef IP
IP=bfin
endif

CFLAGS += -DNO_PROTOTYPES=1

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

results:
	echo "^ Flags  ^  size  ^  Loops  ^  Duration (seconds) ^  Double Precision Whetstones MIPS  ^";\
	( for level in -O{s,0,1,2,3}{" "," -fomit-frame-pointer"}{" "," -ffast-math"}{" "," -mfast-fp"} ; do \
		echo -n "| ''$${level}'' " | sed 's/ [ ]*/ /g' | sed "s/ '' /''/" ; \
		$(CC) $(CFLAGS) $(LDFLAGS) $${level} whetstone.c -o $(EXEC) -lm $(LDLIBS); \
		ls -l $(EXEC) | awk '{ORS = ""; print "  | " $$5 "  | $(ITT)  |  "}' ; \
		rcp $(EXEC) root@$(IP):/var/. ; \
		tmp=`rsh -l root $(IP) /var/whetstone $(ITT)` ;\
		echo $$tmp | awk '{print $$6 "  |  " $$13 "  |"}'; \
	done; \
	)
