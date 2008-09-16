XENO_CONFIG := xeno-config
prefix := $(shell $(XENO_CONFIG) --prefix)

ifeq ($(prefix),)
$(error Please add <xenomai-install-path>/bin to your PATH variable)
endif

STD_CFLAGS  := $(shell $(XENO_CONFIG) --xeno-cflags)
STD_LDFLAGS := $(shell $(XENO_CONFIG) --xeno-ldflags) -lvxworks
STD_TARGETS := satch

GCIC := $(prefix)/bin/gcic
SIM_CFLAGS  := -g
SIM_LDFLAGS := -lvxworks_sim
SIM_TARGETS := satch_sim

# "std" makes all demos running natively in user-space.
# "sim" makes all demos running over the simulator.
# "all" makes, well... all.

std: $(STD_TARGETS)

sim: $(SIM_TARGETS)

all: std sim

satch: satch.c
	$(CC) -o $@ $< $(STD_CFLAGS) $(STD_LDFLAGS)

satch_sim: satch_sim.o
	$(GCIC) -o $@ $< $(SIM_LDFLAGS)

%_sim.o: %.c
	$(GCIC) -o $@ -c $< $(SIM_CFLAGS)

clean:
	$(RM) -f *.o *_sim.o $(STD_TARGETS) $(SIM_TARGETS)
