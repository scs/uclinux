BANNER="Welcome to Blackfin Linux!"
TOOLCHAIN = $(TOOLS)
VERSION = $(shell grep '^Version:' $(ROOTDIR)/release_notes | awk '{print $$NF}')
