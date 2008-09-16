TCOBJ=tc.o tc_qdisc.o tc_class.o tc_filter.o tc_util.o m_police.o m_estimator.o

include ../Config

SCH=atm cbq csz dsmark gred hfsc htb ingress prio red sfq tbf wrr
CLS=fw route rsvp tcindex u32

SCH_OPT = $(call TEST_CONFIG,$(call upper,$(SCH)),NET_SCH)
CLS_OPT = $(call TEST_CONFIG,$(call upper,$(CLS)),NET_CLS)

TEST_OBJ=$(foreach i,$(call lower,$(1)),$(2)_$(i).o)
TEST_CFLAGS=$(foreach i,$(1),-DTC_CONFIG_$(2)_$(i))

TCMODULES :=
TCMODULES += q_fifo.o
TCMODULES +=$(call TEST_OBJ,$(SCH_OPT),q) $(call TEST_OBJ,$(CLS_OPT),f)
CFLAGS += $(call TEST_CFLAGS,$(SCH_OPT),SCH) $(call TEST_CFLAGS,$(CLS_OPT),CLS)

ifneq ($(filter atm,$(SCH_OPT)),)
  LDLIBS += -latm
endif

TCOBJ += $(TCMODULES)

TCLIB := tc_core.o
TCLIB += tc_red.o
TCLIB += tc_cbq.o
TCLIB += tc_estimator.o

LDLIBS := -L. -ltc -lm $(LDLIBS)
# LDFLAGS += -Wl,-export-dynamic

all: libtc.a tc

tc: $(TCOBJ) $(LIBNETLINK) $(TCLIB)
	$(CC) $(LDFLAGS) -o $@ $(TCOBJ) $(LIBNETLINK) $(TCLIB) $(LDLIBS$(LDLIBS_$@))

tc.o: qdisc.c filter.c

qdisc.c: $(KERNEL_DIR)/.config Makefile
	@printf "$(foreach i,$(call lower,pfifo bfifo $(SCH_OPT)),extern struct qdisc_util $(i)_util;\n)" > qdisc.c
	@printf "static struct qdisc_util *qdisc[] = {\n" >> qdisc.c
	@printf "$(foreach i,$(call lower,pfifo bfifo $(SCH_OPT)),\t&$(i)_util,\n)" >> qdisc.c
	@printf "\tNULL\n};\n" >> qdisc.c

filter.c: $(KERNEL_DIR)/.config Makefile
	@printf "$(foreach i,$(call lower,$(CLS_OPT)),extern struct filter_util $(i)_util;\n)" > filter.c
	@printf "static struct filter_util *filter[] = {\n" >> filter.c
	@printf "$(foreach i,$(call lower,$(CLS_OPT)),\t&$(i)_util,\n)" >> filter.c
	@printf "\tNULL\n};\n" >> filter.c

libtc.a: $(TCLIB)
	$(CROSS)ar rcs $@ $(TCLIB)

romfs:
	$(ROMFSINST) -e CONFIG_USER_IPROUTE2_TC_TC /bin/tc

clean:
	rm -f *.o libtc.a tc *.gdb

