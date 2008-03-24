uCldist := /uClinux-dist

EXEC = gnuplot

OBJS   = bitmap.o command.o contour.o eval.o graphics.o graph3d.o \
         hidden3d.o util3d.o help.o internal.o misc.o parse.o \
         plot.o readline.o scanner.o set.o show.o specfun.o \
         standard.o stdfn.o term.o util.o version.o binary.o fit.o \
         matrix.o alloc.o datafile.o plot2d.o plot3d.o interpol.o time.o

CORETERM = term/aed.trm term/ai.trm term/amiga.trm term/apollo.trm \
           term/atariaes.trm term/atarivdi.trm term/be.trm term/cgi.trm \
           term/cgm.trm term/compact.c term/corel.trm term/debug.trm \
           term/djsvga.trm term/driver.h term/dumb.trm term/dxf.trm term/dxy.trm \
           term/eepic.trm term//emf.trm term/emxvga.trm term/epslatex.trm \
           term/epson.trm term/excl.trm term/fg.trm term/fig.trm term/ggi.trm \
           term/gif.trm term/gnugraph.trm term/gpic.trm term/gpr.trm \
           term/grass.trm term/hp26.trm term/hp2648.trm term/hp500c.trm \
           term/hpgl.trm term/hpljii.trm term/hppj.trm term/imagen.trm \
           term/impcodes.h term/iris4d.trm term/kyo.trm term/latex.trm \
           term/linux.trm term/mac.trm term/metafont.trm term/metapost.trm \
           term/mgr.trm term/mif.trm term/multitos.trm term/next.trm term/object.h \
           term/openstep.trm term/pbm.trm term//pdf.trm term/pc.trm term/pm.trm \
           term/png.trm term/post.trm term/pslatex.trm term/pstricks.trm \
           term/qms.trm term/regis.trm term/rgip.trm term/sun.trm term/svg.trm \
           term/t410x.trm term/table.trm \
           term/tek.trm term/texdraw.trm term/tgif.trm term/tkcanvas.trm \
           term/tpic.trm term/unixpc.trm term/unixplot.trm term/v384.trm \
           term/vws.trm term/win.trm term/x11.trm term/xlib.trm


CFLAGS := $(subst -Wall,,$(CFLAGS))
CFLAGS := -I. -DSHORT_TERMLIST -DHAVE_GETCWD -DHELPFILE=\"/usr/local/share/gnuplot.gih\" -DGNUPLOT_BINDIR=\"/bin\" -DCONTACT=\"bug-gnuplot@dartmouth.edu\"  $(CFLAGS)
LDLIBS := $(LIBPNG) $(LDLIBS) -L$(ROOTDIR)/lib/libpng -lpng -L$(ROOTDIR)/lib/zlib -lz -lm
CFLAGS := $(subst -g,, $(CFLAGS))
CFLAGS := $(subst -O2,-Os, $(CFLAGS))

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

all: build

#build: 
#	make -C $(uCldist) UCLINUX_BUILD_USER=1 $(PWD)_only


romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) $(OBJS) *.elf *.gdb

term.o: term.c term.h $(CORETERM)
	$(CC) $(CFLAGS) -I./term -I$(ROOTDIR)/lib/libpng -I$(ROOTDIR)/lib/zlib -c $<

#set.o: set.c
#	$(CC) $(subst -O0,, $(CFLAGS)) -c $<


