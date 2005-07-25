
LIBNAME=parse

VPATH=	../../lib$(LIBNAME)

# config.h
CFLAGS += -DHAVE_CONFIG_H -I../include

# ntp headers
CFLAGS += -I../../include

SRCS=	parse.c \
	parse_conf.c \
	clk_meinberg.c \
	clk_schmid.c \
	clk_rawdcf.c \
	clk_trimtsip.c \
	clk_dcf7000.c \
	clk_trimtaip.c \
	clk_rcc8000.c \
	clk_hopf6021.c \
	clk_computime.c \
	clk_wharton.c \
	clk_varitext.c \
	data_mbg.c \
	info_trimble.c \
	trim_info.c

OBJS=$(SRCS:.c=.o)

LIB=	lib$(LIBNAME).a

$(LIB): $(OBJS)
	-rm -f $@
	$(AR) cru $@ $(OBJS)
	$(RANLIB) $@

all: $(LIB)

romfs:

clean:
	rm -f $(LIB) $(OBJS)
