include ../MCONFIG

PROGS =	subst

all: $(PROGS)

subst: subst.c
	$(BUILD_CC) -o subst subst.c

clean:
	$(RM) -f $(PROGS) \#* *.s *.gdb *.o *.a *~ core

$(PROGS): ../MCONFIG
