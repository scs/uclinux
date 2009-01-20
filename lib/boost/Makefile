VER = boost_1_37_0
URL = http://downloads.sourceforge.net/sourceforge/boost/$(VER).tar.bz2

LIBS-a := $(wildcard $(VER)/libs/*/build)
LIBS-a := $(LIBS-a:$(VER)/libs/%/build=%)
LIBS-  :=
LIBS-n := $(BOOST_LIBS_DISABLE) program_options
LIBS-$(CONFIG_LIB_EXPAT)          += graph
LIBS-$(CONFIG_USER_PYTHON_PYTHON) += python
LIBS-n += $(LIBS-)
LIBS-y := $(filter-out $(LIBS-n),$(LIBS-a))

CONF_OPTS-y := \
	-j$(HOST_NCPU) \
	--toolset=gcc \
	--layout=system \
	--user-config=user-config.jam \
	--prefix=$(STAGEDIR)/usr \
	$(LIBS-n:%=--without-%) \
	threading=single,multi \
	link=shared,static \
	runtime-link=shared,static
CONF_OPTS-y += \
	-sNO_WCHAR=1 \
	-sNO_LONG_DOUBLE=1
CONF_OPTS-$(CONFIG_LIB_EXPAT) += \
	-sEXPAT_INCLUDE=$(STAGEDIR)/usr/include \
	-sEXPAT_LIBPATH=$(STAGEDIR)/usr/lib
ifneq ($(CONFIG_LIB_LIBBZ2),y)
CONF_OPTS-y += -sNO_BZIP2=1
endif
ifneq ($(CONFIG_LIB_ZLIB),y)
CONF_OPTS-y += -sNO_ZLIB=1
endif
CONF_OPTS = $(CONF_OPTS-y)

include $(ROOTDIR)/tools/download.mk

JAM = $(CURDIR)/$(VER)/tools/jam/src/build/bjam

all: $(JAM) $(VER)/user-config.jam
	cd $(VER) && $(JAM) $(CONF_OPTS) install

$(JAM): $(VER)/.unpacked
	cd $(VER)/tools/jam/src && env LOCATE_TARGET=build ./build.sh

CPPFLAGS += -DBOOST_NO_INTRINSIC_WCHAR_T
LDFLAGS += -Wl,-z,defs
$(VER)/user-config.jam: $(VER)/.unpacked
	echo 'using gcc : $(shell $(CC) -dumpversion) : $(CXX) : <cxxflags>"$(CXXFLAGS) $(CPPFLAGS)" <linkflags>"$(LDFLAGS)" ;' > $(VER)/user-config.jam

clean:
	cd $(VER) && \
		rm -rf \
			bin.* \
			user-config.jam* \
			tools/jam/src/bootstrap \
			tools/jam/src/build \
			tools/jam/src/config.log

romfs:

.PHONY: all clean romfs
