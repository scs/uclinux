.ifdef __ALPHA__
SUFFIX = _ALPHA
.endif
.ifdef __VAX__
XFER_VECTOR = ftplib_vector.obj
GETOPT = getopt.obj
.endif

TARGETS = ftplib$(SUFFIX).exe qftp$(SUFFIX).exe
CFLAGS = $(CFLAGS)/prefix=all/define=(NEED_STRDUP,NEED_MEMCCPY)
SHLINKFLAGS = /SHARE=$(MMS$TARGET)/NOMAP

* : $(TARGETS)
	continue

ftplib$(SUFFIX).obj : ftplib.c ftplib.h

ftplib$(SUFFIX).exe : ftplib$(SUFFIX).obj $(XFER_VECTOR)
	$(LINK) $(SHLINKFLAGS) ftplib$(SUFFIX).opt/options

qftp$(SUFFIX).exe : qftp$(SUFFIX).obj $(GETOPT)
	$(LINK) $(LINKFLAGS) qftp$(SUFFIX).opt/options

qftp$(SUFFIX).obj : qftp.c ftplib.h
