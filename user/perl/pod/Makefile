# pod/Makefile
# This file is derived from pod/Makefile.SH.  Any changes made here will
# be lost the next time you run Configure.

POD = perl5004delta.pod perl5005delta.pod perlapio.pod perlapi.pod perlbook.pod perlboot.pod perlbot.pod perlcall.pod perlclib.pod perlcompile.pod perldata.pod perldbmfilter.pod perldebguts.pod perldebtut.pod perldebug.pod perldelta.pod perldiag.pod perldsc.pod perlebcdic.pod perlembed.pod perlfaq1.pod perlfaq2.pod perlfaq3.pod perlfaq4.pod perlfaq5.pod perlfaq6.pod perlfaq7.pod perlfaq8.pod perlfaq9.pod perlfaq.pod perlfilter.pod perlfork.pod perlform.pod perlfunc.pod perlguts.pod perlhack.pod perlhist.pod perlintern.pod perlipc.pod perllexwarn.pod perllocale.pod perllol.pod perlmodinstall.pod perlmodlib.pod perlmod.pod perlnewmod.pod perlnumber.pod perlobj.pod perlopentut.pod perlop.pod perl.pod perlpod.pod perlport.pod perlref.pod perlreftut.pod perlre.pod perlrequick.pod perlretut.pod perlrun.pod perlsec.pod perlstyle.pod perlsub.pod perlsyn.pod perlthrtut.pod perltie.pod perltoc.pod perltodo.pod perltootc.pod perltoot.pod perltrap.pod perlunicode.pod perlutil.pod perlvar.pod perlxs.pod perlxstut.pod

MAN = perl5004delta.man perl5005delta.man perlapio.man perlapi.man perlbook.man perlboot.man perlbot.man perlcall.man perlclib.man perlcompile.man perldata.man perldbmfilter.man perldebguts.man perldebtut.man perldebug.man perldelta.man perldiag.man perldsc.man perlebcdic.man perlembed.man perlfaq1.man perlfaq2.man perlfaq3.man perlfaq4.man perlfaq5.man perlfaq6.man perlfaq7.man perlfaq8.man perlfaq9.man perlfaq.man perlfilter.man perlfork.man perlform.man perlfunc.man perlguts.man perlhack.man perlhist.man perlintern.man perlipc.man perllexwarn.man perllocale.man perllol.man perlmodinstall.man perlmodlib.man perlmod.man perlnewmod.man perlnumber.man perlobj.man perlopentut.man perlop.man perl.man perlpod.man perlport.man perlref.man perlreftut.man perlre.man perlrequick.man perlretut.man perlrun.man perlsec.man perlstyle.man perlsub.man perlsyn.man perlthrtut.man perltie.man perltoc.man perltodo.man perltootc.man perltoot.man perltrap.man perlunicode.man perlutil.man perlvar.man perlxs.man perlxstut.man

# no perltoc.html
HTML = perl5004delta.html perl5005delta.html perlapio.html perlapi.html perlbook.html perlboot.html perlbot.html perlcall.html perlclib.html perlcompile.html perldata.html perldbmfilter.html perldebguts.html perldebtut.html perldebug.html perldelta.html perldiag.html perldsc.html perlebcdic.html perlembed.html perlfaq1.html perlfaq2.html perlfaq3.html perlfaq4.html perlfaq5.html perlfaq6.html perlfaq7.html perlfaq8.html perlfaq9.html perlfaq.html perlfilter.html perlfork.html perlform.html perlfunc.html perlguts.html perlhack.html perlhist.html perlintern.html perlipc.html perllexwarn.html perllocale.html perllol.html perlmodinstall.html perlmodlib.html perlmod.html perlnewmod.html perlnumber.html perlobj.html perlopentut.html perlop.html perl.html perlpod.html perlport.html perlref.html perlreftut.html perlre.html perlrequick.html perlretut.html perlrun.html perlsec.html perlstyle.html perlsub.html perlsyn.html perlthrtut.html perltie.html  perltodo.html perltootc.html perltoot.html perltrap.html perlunicode.html perlutil.html perlvar.html perlxs.html perlxstut.html

TEX  = perl5004delta.tex perl5005delta.tex perlapio.tex perlapi.tex perlbook.tex perlboot.tex perlbot.tex perlcall.tex perlclib.tex perlcompile.tex perldata.tex perldbmfilter.tex perldebguts.tex perldebtut.tex perldebug.tex perldelta.tex perldiag.tex perldsc.tex perlebcdic.tex perlembed.tex perlfaq1.tex perlfaq2.tex perlfaq3.tex perlfaq4.tex perlfaq5.tex perlfaq6.tex perlfaq7.tex perlfaq8.tex perlfaq9.tex perlfaq.tex perlfilter.tex perlfork.tex perlform.tex perlfunc.tex perlguts.tex perlhack.tex perlhist.tex perlintern.tex perlipc.tex perllexwarn.tex perllocale.tex perllol.tex perlmodinstall.tex perlmodlib.tex perlmod.tex perlnewmod.tex perlnumber.tex perlobj.tex perlopentut.tex perlop.tex perl.tex perlpod.tex perlport.tex perlref.tex perlreftut.tex perlre.tex perlrequick.tex perlretut.tex perlrun.tex perlsec.tex perlstyle.tex perlsub.tex perlsyn.tex perlthrtut.tex perltie.tex perltoc.tex perltodo.tex perltootc.tex perltoot.tex perltrap.tex perlunicode.tex perlutil.tex perlvar.tex perlxs.tex perlxstut.tex  


CONVERTERS = pod2html pod2latex pod2man pod2text checkpods \
		pod2usage podchecker podselect

HTMLROOT = /	# Change this to fix cross-references in HTML
POD2HTML = pod2html \
	    --htmlroot=$(HTMLROOT) \
	    --podroot=.. --podpath=pod:lib:ext:vms \
	    --libpods=perlfunc:perlguts:perlvar:perlrun:perlop

PERL = ../miniperl
PERLILIB = $(PERL) -I../lib
REALPERL = ../perl

all: $(CONVERTERS) man

converters: $(CONVERTERS)

regen_pods: perlmodlib.pod toc

buildtoc:	buildtoc.PL perl.pod ../MANIFEST
	$(PERLILIB) buildtoc.PL

perltoc.pod:	buildtoc

man:	pod2man $(MAN)

html:	pod2html $(HTML)

tex:	pod2latex $(TEX)

toc:	buildtoc
	$(PERLILIB) buildtoc

.SUFFIXES: .pm .pod

.SUFFIXES: .man

.pm.man:     pod2man
	$(PERL) -I../lib pod2man $*.pm >$*.man

.pod.man:     pod2man
	$(PERL) -I../lib pod2man $*.pod >$*.man

.SUFFIXES: .html

.pm.html:    pod2html
	$(PERL) -I../lib $(POD2HTML) --infile=$*.pm --outfile=$*.html

.pod.html:    pod2html
	$(PERL) -I../lib $(POD2HTML) --infile=$*.pod --outfile=$*.html

.SUFFIXES: .tex

.pm.tex: pod2latex
	$(PERL) -I../lib pod2latex $*.pm

.pod.tex: pod2latex
	$(PERL) -I../lib pod2latex $*.pod

clean:
	rm -f $(MAN)
	rm -f $(HTML)
	rm -f $(TEX)
	rm -f pod2html-*cache
	rm -f *.aux *.log *.exe

realclean:	clean
	rm -f $(CONVERTERS)

distclean:	realclean

veryclean:	distclean
	-rm -f *~ *.orig

check:	checkpods
	@echo "checking..."; \
	$(PERL) -I../lib checkpods $(POD)

# Dependencies.
pod2latex:	pod2latex.PL ../lib/Config.pm
	$(PERL) -I../lib pod2latex.PL

pod2html:	pod2html.PL ../lib/Config.pm
	$(PERL) -I ../lib pod2html.PL

pod2man:	pod2man.PL ../lib/Config.pm
	$(PERL) -I ../lib pod2man.PL

pod2text:	pod2text.PL ../lib/Config.pm
	$(PERL) -I ../lib pod2text.PL

checkpods:	checkpods.PL ../lib/Config.pm
	$(PERL) -I ../lib checkpods.PL

pod2usage:	pod2usage.PL ../lib/Config.pm
	$(PERL) -I ../lib pod2usage.PL

podchecker:	podchecker.PL ../lib/Config.pm
	$(PERL) -I ../lib podchecker.PL

podselect:	podselect.PL ../lib/Config.pm
	$(PERL) -I ../lib podselect.PL

perlmodlib.pod:	$(PERL) perlmodlib.PL ../mv-if-diff
	rm -f perlmodlib.tmp
	$(PERL) -I ../lib perlmodlib.PL
	sh ../mv-if-diff perlmodlib.tmp perlmodlib.pod

compile: all
	$(REALPERL) -I../lib ../utils/perlcc -o pod2latex.exe pod2latex -log ../compilelog
	$(REALPERL) -I../lib ../utils/perlcc -o pod2man.exe pod2man -log ../compilelog
	$(REALPERL) -I../lib ../utils/perlcc -o pod2text.exe pod2text -log ../compilelog
	$(REALPERL) -I../lib ../utils/perlcc -o checkpods.exe checkpods -log ../compilelog

