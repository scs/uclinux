all:
	@find . -mindepth 2 -name Makefile -execdir make \;

clean:
	@find . -depth -mindepth 2 -name Makefile -execdir make clean \; 2>/dev/null || true
