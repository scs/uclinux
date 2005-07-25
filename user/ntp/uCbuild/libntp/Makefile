
LIBNAME=ntp

VPATH=	../../lib$(LIBNAME)

# config.h
CFLAGS += -DHAVE_CONFIG_H -I../include

# ntp headers
CFLAGS += -I../../include

SRCS=	a_md5encrypt.c adjtime.c atoint.c atolfp.c atouint.c \
	authencrypt.c authkeys.c authparity.c authreadkeys.c authusekey.c \
	buftvtots.c caljulian.c calleapwhen.c caltontp.c calyearstart.c \
	clocktime.c clocktypes.c decodenetnum.c dofptoa.c dolfptoa.c \
	emalloc.c findconfig.c fptoa.c fptoms.c getopt.c hextoint.c \
	hextolfp.c humandate.c inttoa.c lib_strbuf.c machines.c md5c.c \
	memmove.c mfptoa.c mfptoms.c modetoa.c mstolfp.c msutotsf.c \
	msyslog.c netof.c numtoa.c numtohost.c octtoint.c prettydate.c \
	ranny.c refnumtoa.c statestr.c syssignal.c systime.c tsftomsu.c \
	tstotv.c tvtoa.c tvtots.c uglydate.c uinttoa.c utvtoa.c ymd2yd.c \
	mfp_mul.c binio.c ieee754io.c gpstolfp.c recvbuff.c iosignal.c \
	icom.c audio.c

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
