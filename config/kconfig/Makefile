#
# Local Makefile for the configurator programs
#

CC = cc

# lxdialog peices needed locally
check-lxdialog := lxdialog/check-lxdialog.sh
CFLAGS += $(shell $(CONFIG_SHELL) $(check-lxdialog) -ccflags)
LDLIBS += $(shell $(CONFIG_SHELL) $(check-lxdialog) -ldflags $(CC))

conf-objs := conf.o zconf.tab.o
mconf-objs := mconf.o zconf.tab.o
qconfig-objs := conf.o kconfig_load.o kxgettext.o zconf.tab.o qconf.o
lxdialog-objs := lxdialog/checklist.o lxdialog/inputbox.o lxdialog/menubox.o \
	lxdialog/textbox.o lxdialog/util.o lxdialog/yesno.o

all: conf mconf

conf: $(conf-objs)

mconf: $(mconf-objs) $(lxdialog-objs)

zconf.tab.o: zconf.tab.c zconf.hash.c lex.zconf.c

%.c: %.c_shipped
	cp $< $@

clean:
	rm -f conf mconf *.o .*.o.cmd lxdialog/*.o

