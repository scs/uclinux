OBJECTS_xxd := xxd.o

PRODUCTS := $(patsubst OBJECTS_%, %, $(filter OBJECTS_%, $(.VARIABLES)))
SHELL := $(shell which bash)

#CC := gcc -c -DOSC_TARGET -std=gnu99 -O3
#LD := gcc

CC := bfin-uclinux-gcc -c -DOSC_TARGET -std=gnu99 -O3
LD := bfin-uclinux-gcc -elf2flt="-s 10240"

-include .config

.PHONY: all host target
all: $(PRODUCTS)

.SUFFIXES:
Makefile.deps: $(SOURCES) $(MAKEFILE_LIST)
	@ echo "DEPS     $?"
	@ for i in $(SOURCES); do cpp -MM $$i; done > $@
	@ echo "$@: $$(cut -d " " -f 2- < $@ | tr "\n" " ")" >> $@

%.o: %.c $(MAKEFILE_LIST)
	@ echo "GCC_BF   $*.c => $@"
	@ $(CC) -std=gnu99 -Wall -O3 -o $@ $*.c

.SECONDEXPANSION:
$(PRODUCTS): INPUTS = $(OBJECTS_$@)
$(PRODUCTS): $$(INPUTS) $(MAKEFILE_LIST)
	@ echo "LD_BF    $(INPUTS) => $@"
	@ $(LD) -lm -o $@ $(INPUTS)

CLEAN_FILES := *.o $(PRODUCTS) Makefile.deps* Makefile.cache
CLEAN_FILES := $(wildcard $(CLEAN_FILES))

.PHONY: clean
clean:
ifneq '$(CLEAN_FILES)' ''
	@ echo "CLEAN   " $(CLEAN_FILES)
	@ rm -f $(CLEAN_FILES)
endif
	@ make -C CGI clean

ifeq '$(filter-out clean, $(MAKECMDGOALS))' '$(MAKECMDGOALS)'
  -include Makefile.deps
endif
