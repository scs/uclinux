##############################################################################
# Non-user-configurable settings
##############################################################################


##############################################################################
# CPU-dependent settings
##############################################################################
#note : -D__CPU_$(MY_CPU) is added automatically later on.
CFLAGS.i386       = -DLSB_FIRST -DX86_ASM
CFLAGS.i386_noasm = -DLSB_FIRST
CFLAGS.ia64       = -DLSB_FIRST -DALIGN_INTS -DALIGN_SHORTS -D__LP64__
CFLAGS.amd64      = -DLSB_FIRST -DALIGN_INTS -DALIGN_SHORTS -D__LP64__
CFLAGS.em64t      = -DLSB_FIRST -DALIGN_INTS -DALIGN_SHORTS -D__LP64__
CFLAGS.alpha      = -DLSB_FIRST -DALIGN_INTS -DALIGN_SHORTS -D__LP64__
CFLAGS.m68k       = 
CFLAGS.risc       = -DALIGN_INTS -DALIGN_SHORTS 
CFLAGS.risc_lsb   = -DALIGN_INTS -DALIGN_SHORTS -DLSB_FIRST
CFLAGS.mips       = -DALIGN_INTS -DALIGN_SHORTS -DSGI_FIX_MWA_NOP
CFLAGS.bfin       = -DLSB_FIRST -DALIGN_INTS -DALIGN_SHORTS

##############################################################################
# Architecture-dependent settings
##############################################################################
LIBS.solaris       = -lnsl -lsocket
LIBS.irix          = -laudio
LIBS.irix_al       = -laudio
LIBS.aix           = -lUMSobj
LIBS.next	   = -framework SoundKit
LIBS.macosx	   = -framework AudioUnit -framework CoreServices
#LIBS.openbsd       = -lossaudio
LIBS.nto	   = -lsocket -lasound
LIBS.beos          = `$(SDL_CONFIG) --libs`

##############################################################################
# Display-dependent settings
##############################################################################
#first calculate the X11 Joystick driver settings, this is done here since
#they are only valid for X11 based display methods
ifdef XINPUT_DEVICES
XINPUT_DEVICES_CFLAGS = -DUSE_XINPUT_DEVICES
XINPUT_DEVICES_LIBS = -lXi
endif

ifdef X11_XINERAMA
XINERAMA_CFLAGS = -DHAVE_XINERAMA
XINERAMA_LIBS = -lXinerama
endif

# svga and ggi also use $(X11LIB) since that's where zlib often is
LIBS.x11        = $(X11LIB) $(XINPUT_DEVICES_LIBS) $(XINERAMA_LIBS) -lX11 -lXext
LIBS.svgalib    = $(X11LIB) -lvga -lvgagl
LIBS.ggi        = $(X11LIB) -lggi
ifdef GLIDE2
LIBS.svgafx     = $(X11LIB) -lvga -lvgagl -lglide2x
else
LIBS.svgafx     = $(X11LIB) -lvga -lvgagl -lglide3
endif
LIBS.openstep	= -framework AppKit
LIBS.SDL	= $(X11LIB) `$(SDL_CONFIG) --libs`
LIBS.photon2	= -L/usr/lib -lph -lphrender

CFLAGS.x11      = $(X11INC) $(XINPUT_DEVICES_CFLAGS) $(XINERAMA_CFLAGS)
ifdef GLIDE2
CFLAGS.svgafx   = -I/usr/include/glide
else
CFLAGS.svgafx   = -I/usr/include/glide3
endif
CFLAGS.SDL      = $(X11INC) `$(SDL_CONFIG) --cflags` -D_REENTRANT
CFLAGS.photon2	=

INST.x11	= doinstall
INST.ggi        = doinstall
INST.svgalib    = doinstallsuid
INST.svgafx     = doinstallsuid
INST.SDL	= doinstall
INST.photon2	= doinstall

# handle X11 display method additonal settings, override INST if necessary
ifdef X11_MITSHM
CFLAGS.x11 += -DUSE_MITSHM
endif
ifdef X11_XV
CFLAGS.x11 += -DUSE_XV
LIBS.x11   += -lXv
endif
ifdef X11_GLIDE
ifdef GLIDE2
CFLAGS.x11 += -DUSE_GLIDE -I/usr/include/glide
LIBS.x11   += -lglide2x
else
CFLAGS.x11 += -DUSE_GLIDE -I/usr/include/glide3
LIBS.x11   += -lglide3
endif
INST.x11    = doinstallsuid
endif
ifdef X11_XIL
CFLAGS.x11 += -DUSE_XIL
LIBS.x11   += -lxil -lpthread
endif
ifdef X11_DGA
CFLAGS.x11 += -DUSE_DGA
LIBS.x11   += -lXxf86dga -lXxf86vm
INST.x11    = doinstallsuid
endif
# must be last since it does a += on INST.x11
ifdef X11_OPENGL
CFLAGS.x11 += -DUSE_OPENGL $(GLCFLAGS)
LIBS.x11   += $(GLLIBS) -ljpeg
INST.x11   += copycab
endif

ifndef HOST_CC
HOST_CC = $(CC)
endif


##############################################################################
# these are the object subdirectories that need to be created.
##############################################################################
OBJ     = $(NAME).obj

OBJDIR = $(OBJ)/unix.$(DISPLAY_METHOD)

OBJDIRS = $(OBJ) $(OBJ)/cpu $(OBJ)/sound $(OBJ)/drivers \
	  $(OBJ)/machine $(OBJ)/vidhrdw $(OBJ)/sndhrdw \
	  $(OBJ)/debug
ifeq ($(TARGET), mess)
OBJDIRS += $(OBJ)/mess $(OBJ)/mess/expat $(OBJ)/mess/cpu \
	   $(OBJ)/mess/devices $(OBJ)/mess/systems $(OBJ)/mess/machine \
	   $(OBJ)/mess/vidhrdw $(OBJ)/mess/sndhrdw $(OBJ)/mess/formats \
	   $(OBJ)/mess/tools $(OBJ)/mess/tools/dat2html \
	   $(OBJ)/mess/tools/mkhdimg $(OBJ)/mess/tools/messroms \
	   $(OBJ)/mess/tools/imgtool $(OBJ)/mess/tools/messdocs \
	   $(OBJ)/mess/tools/messtest $(OBJ)/mess/tools/mkimage \
	   $(OBJ)/mess/sound
endif

UNIX_OBJDIR = $(OBJ)/unix.$(DISPLAY_METHOD)

SYSDEP_DIR = $(UNIX_OBJDIR)/sysdep
DSP_DIR = $(UNIX_OBJDIR)/sysdep/dsp-drivers
MIXER_DIR = $(UNIX_OBJDIR)/sysdep/mixer-drivers
VID_DIR = $(UNIX_OBJDIR)/video-drivers
BLIT_DIR = $(UNIX_OBJDIR)/blit
JOY_DIR = $(UNIX_OBJDIR)/joystick-drivers
FRAMESKIP_DIR = $(UNIX_OBJDIR)/frameskip-drivers

OBJDIRS += $(UNIX_OBJDIR) $(SYSDEP_DIR) $(DSP_DIR) $(MIXER_DIR) $(VID_DIR) \
	$(JOY_DIR) $(FRAMESKIP_DIR) $(BLIT_DIR)

ifeq ($(TARGET), mess)
INCLUDE_PATH = -I. -Imess -Isrc -Isrc/includes -Isrc/debug -Isrc/unix -Isrc/unix/sysdep -I$(OBJ)/cpu/m68000 -Isrc/cpu/m68000
else
INCLUDE_PATH = -I. -Isrc -Isrc/includes -Isrc/debug -Isrc/unix -I$(OBJ)/cpu/m68000 -Isrc/cpu/m68000
endif

##############################################################################
# Define standard libraries for CPU and sounds
##############################################################################

CPULIB = $(OBJ)/libcpu.a

SOUNDLIB = $(OBJ)/libsound.a

##############################################################################
# "Calculate" the final CFLAGS, unix CONFIG, LIBS and OBJS
##############################################################################
ifdef SEPARATE_LIBM
LIBS += -lm
endif

ifeq ($(BUILD_EXPAT),1)
CFLAGS += -Isrc/expat
OBJDIRS += $(OBJ)/expat
EXPAT = $(OBJ)/libexpat.a
else
LIBS += -lexpat
EXPAT =
endif

ifeq ($(BUILD_ZLIB),1)
CFLAGS += -Isrc/zlib
OBJDIRS += $(OBJ)/zlib
ZLIB = $(OBJ)/libz.a
else
LIBS += -lz
ZLIB =
endif

ifdef NEW_DEBUGGER
CFLAGS += -DNEW_DEBUGGER
endif

ifdef X86_VOODOO_DRC
DEFS += -DVOODOO_DRC
endif

all: maketree $(NAME).$(DISPLAY_METHOD) extra

# CPU core include paths
VPATH = src $(wildcard src/cpu/*)

# Platform-dependent objects for imgtool
PLATFORM_TOOL_OBJS = $(OBJDIR)/dirio.o \
			$(OBJDIR)/fileio.o \
			$(OBJDIR)/sysdep/misc.o

include src/core.mak

ifeq ($(TARGET), mame)
include src/$(TARGET).mak
endif
ifeq ($(TARGET), mess)
include mess/$(TARGET).mak
endif
ifeq ($(TARGET), tiny)
include src/$(TARGET).mak
endif

include src/cpu/cpu.mak
include src/sound/sound.mak

ifeq ($(TARGET), mess)
include mess/cpu/cpu.mak
include mess/sound/sound.mak
endif

ifdef DEBUG
DBGDEFS = -DMAME_DEBUG
else
DBGDEFS =
DBGOBJS =
endif

# Perhaps one day original mame/mess sources will use POSIX strcasecmp and
# M_PI instead MS-DOS counterparts... (a long and sad history ...)
CFLAGS += $(IL) $(CFLAGS.$(MY_CPU)) \
	-D__ARCH_$(ARCH) -D__CPU_$(MY_CPU) -D$(DISPLAY_METHOD) \
	-DPI=M_PI -DXMAME -DUNIX -DSIGNED_SAMPLES -DCLIB_DECL= \
	-DHAVE_UNISTD_H=1 \
	$(COREDEFS) $(SOUNDDEFS) $(CPUDEFS) $(ASMDEFS) \
	$(INCLUDES) $(INCLUDE_PATH)

LIBS += $(LIBS.$(ARCH)) $(LIBS.$(DISPLAY_METHOD))

ifdef DEBUG
CFLAGS += -DMAME_DEBUG
endif

ifdef XMAME_NET
CFLAGS += -DXMAME_NET
endif

ifdef DISABLE_EFFECTS
CFLAGS += -DDISABLE_EFFECTS
endif

ifdef HAVE_MMAP
CFLAGS += -DHAVE_MMAP
endif

ifdef CRLF
CFLAGS += -DCRLF=$(CRLF)
endif

ifdef PAUSE_KEY_119
CFLAGS += -DPAUSE_KEY_119
endif

# The SDL target automatically includes the SDL joystick and audio drivers.
ifeq ($(DISPLAY_METHOD),SDL)
JOY_SDL = 1
SOUND_SDL = 1
endif

##############################################################################
# Object listings
##############################################################################

# common objs
COMMON_OBJS  =  \
	$(OBJDIR)/main.o $(OBJDIR)/sound.o $(OBJDIR)/devices.o \
	$(OBJDIR)/video.o $(OBJDIR)/mode.o $(OBJDIR)/fileio.o \
	$(OBJDIR)/dirio.o $(OBJDIR)/config.o $(OBJDIR)/fronthlp.o \
	$(OBJDIR)/ident.o $(OBJDIR)/network.o $(OBJDIR)/snprintf.o \
	$(OBJDIR)/nec765_dummy.o $(OBJDIR)/effect.o $(OBJDIR)/ticker.o \
	$(OBJDIR)/parallel.o $(BLIT_DIR)/blit_15_15.o \
	$(BLIT_DIR)/blit_16_15.o $(BLIT_DIR)/blit_16_16.o \
	$(BLIT_DIR)/blit_16_24.o $(BLIT_DIR)/blit_16_32.o \
	$(BLIT_DIR)/blit_32_15.o $(BLIT_DIR)/blit_32_16.o \
	$(BLIT_DIR)/blit_32_24.o $(BLIT_DIR)/blit_32_32.o \
	$(BLIT_DIR)/blit_16_yuy2.o $(BLIT_DIR)/blit_32_yuy2.o

ifdef MESS
COMMON_OBJS += $(OBJDIR)/xmess.o
TOOLS = dat2html chdman imgtool
endif
ifdef LIRC
CONFIG  += -I/usr/include/lirc
LIBS += -L/usr/lib -llirc_client
endif

OSTOOLOBJS = \
	$(OBJDIR)/osd_tool.o

# sysdep objs
SYSDEP_OBJS = $(SYSDEP_DIR)/rc.o $(SYSDEP_DIR)/misc.o \
   $(SYSDEP_DIR)/plugin_manager.o $(SYSDEP_DIR)/sysdep_sound_stream.o \
   $(SYSDEP_DIR)/sysdep_palette.o $(SYSDEP_DIR)/sysdep_dsp.o \
   $(SYSDEP_DIR)/sysdep_mixer.o $(SYSDEP_DIR)/sysdep_display.o \
   $(SYSDEP_DIR)/sysdep_cpu.o

# video driver objs per display method
VID_OBJS.x11    = $(VID_DIR)/xinput.o $(VID_DIR)/x11_window.o
ifdef X11_XV
VID_OBJS.x11   += $(VID_DIR)/xv.o
endif
ifdef X11_OPENGL
VID_OBJS.x11   += $(VID_DIR)/gltool.o $(VID_DIR)/glxtool.o $(VID_DIR)/glcaps.o \
		  $(VID_DIR)/glvec.o $(VID_DIR)/glgen.o $(VID_DIR)/glexport.o \
		  $(VID_DIR)/glcab.o $(VID_DIR)/gljpg.o $(VID_DIR)/xgl.o
endif
ifdef X11_GLIDE
VID_OBJS.x11   += $(VID_DIR)/fxgen.o $(VID_DIR)/xfx.o $(VID_DIR)/fxvec.o
endif
ifdef X11_XIL
VID_OBJS.x11   += $(VID_DIR)/xil.o
endif
ifdef X11_DGA
VID_OBJS.x11   += $(VID_DIR)/xf86_dga1.o $(VID_DIR)/xf86_dga2.o \
		  $(VID_DIR)/xf86_dga.o
endif
VID_OBJS.svgalib = $(VID_DIR)/svgainput.o
VID_OBJS.svgafx = $(VID_DIR)/svgainput.o $(VID_DIR)/fxgen.o $(VID_DIR)/fxvec.o
VID_OBJS.openstep = $(VID_DIR)/openstep_input.o
VID_OBJS.photon2 = $(VID_DIR)/photon2_input.o \
	$(VID_DIR)/photon2_window.o \
	$(VID_DIR)/photon2_overlay.o
VID_OBJS = $(VID_DIR)/$(DISPLAY_METHOD).o $(VID_OBJS.$(DISPLAY_METHOD))

# sound driver objs per arch
SOUND_OBJS.linux   = $(DSP_DIR)/oss.o $(MIXER_DIR)/oss.o
SOUND_OBJS.freebsd = $(DSP_DIR)/oss.o $(MIXER_DIR)/oss.o
SOUND_OBJS.netbsd  = $(DSP_DIR)/netbsd.o
#SOUND_OBJS.openbsd = $(DSP_DIR)/oss.o $(MIXER_DIR)/oss.o
SOUND_OBJS.openbsd = $(DSP_DIR)/netbsd.o 
SOUND_OBJS.solaris = $(DSP_DIR)/solaris.o $(MIXER_DIR)/solaris.o
SOUND_OBJS.next    = $(DSP_DIR)/soundkit.o
SOUND_OBJS.macosx  = $(DSP_DIR)/coreaudio.o
SOUND_OBJS.nto     = $(DSP_DIR)/io-audio.o
SOUND_OBJS.irix    = $(DSP_DIR)/irix.o
SOUND_OBJS.irix_al = $(DSP_DIR)/irix_al.o
SOUND_OBJS.beos    =
SOUND_OBJS.generic =
#these need to be converted to plugins first
#SOUND_OBJS.aix     = $(DSP_DIR)/aix.o
SOUND_OBJS = $(SOUND_OBJS.$(ARCH))

ifdef SOUND_ESOUND
SOUND_OBJS += $(DSP_DIR)/esound.o
endif

ifdef SOUND_ALSA
SOUND_OBJS += $(DSP_DIR)/alsa.o $(MIXER_DIR)/alsa.o
endif

ifdef SOUND_ARTS_TEIRA
SOUND_OBJS += $(DSP_DIR)/artssound.o
endif

ifdef SOUND_ARTS_SMOTEK
SOUND_OBJS += $(DSP_DIR)/arts.o
endif

ifdef SOUND_SDL
SOUND_OBJS += $(DSP_DIR)/sdl.o
endif

ifdef SOUND_WAVEOUT
SOUND_OBJS += $(DSP_DIR)/waveout.o
endif

# joystick objs
ifdef JOY_STANDARD
JOY_OBJS += $(JOY_DIR)/joy_standard.o
endif

ifdef JOY_PAD
JOY_OBJS += $(JOY_DIR)/joy_pad.o
endif

ifdef JOY_USB
JOY_OBJS += $(JOY_DIR)/joy_usb.o
endif

ifdef JOY_PS2
JOY_OBJS += $(JOY_DIR)/joy_ps2.o
endif

ifdef JOY_SDL
JOY_OBJS += $(JOY_DIR)/joy_SDL.o
endif

ifdef LIGHTGUN_ABS_EVENT
JOY_OBJS += $(JOY_DIR)/lightgun_abs_event.o
endif

# framskip objs
FRAMESKIP_OBJS = $(FRAMESKIP_DIR)/dos.o $(FRAMESKIP_DIR)/barath.o

# all objs
UNIX_OBJS = $(COMMON_OBJS) $(SYSDEP_OBJS) $(VID_OBJS) $(SOUND_OBJS) \
	    $(JOY_OBJS) $(FRAMESKIP_OBJS)

##############################################################################
# CFLAGS
##############################################################################

# per arch
CFLAGS.linux      = -DSYSDEP_DSP_OSS -DSYSDEP_MIXER_OSS -DHAVE_SNPRINTF -DHAVE_VSNPRINTF -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS.freebsd    = -DSYSDEP_DSP_OSS -DSYSDEP_MIXER_OSS -DHAVE_SNPRINTF -DHAVE_VSNPRINTF -DHAVE_STRLCAT
CFLAGS.netbsd     = -DSYSDEP_DSP_NETBSD -DHAVE_SNPRINTF -DHAVE_VSNPRINTF -DHAVE_STRLCAT
CFLAGS.openbsd    = -DSYSDEP_DSP_NETBSD -DHAVE_SNPRINTF -DHAVE_VSNPRINTF -DHAVE_STRLCAT
CFLAGS.solaris    = -DSYSDEP_DSP_SOLARIS -DSYSDEP_MIXER_SOLARIS -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS.next       = -DSYSDEP_DSP_SOUNDKIT -DBSD43
CFLAGS.macosx     = -DSYSDEP_DSP_COREAUDIO -DHAVE_SNPRINTF -DHAVE_VSNPRINTF
CFLAGS.nto        = -DSYSDEP_DSP_ALSA -DSYSDEP_MIXER_ALSA
CFLAGS.irix       = -DSYSDEP_DSP_IRIX -DHAVE_SNPRINTF
CFLAGS.irix_al    = -DSYSDEP_DSP_IRIX -DHAVE_SNPRINTF
CFLAGS.beos       = `sdl-config --cflags` -DSYSDEP_DSP_SDL
CFLAGS.generic    =
#these need to be converted to plugins first
#CFLAGS.aix        = -DSYSDEP_DSP_AIX -I/usr/include/UMS -I/usr/lpp/som/include

CFLAGS += $(CFLAGS.$(ARCH))

# CONFIG are the cflags used to build the unix tree, this is where most defines
# go
CONFIG = $(CFLAGS) $(CFLAGS.$(DISPLAY_METHOD)) -DNAME='"x$(TARGET)"' \
	-DDISPLAY_METHOD='"$(DISPLAY_METHOD)"' \
	-DXMAMEROOT='"$(XMAMEROOT)"' -DSYSCONFDIR='"$(SYSCONFDIR)"'

ifdef HAVE_GETTIMEOFDAY
CONFIG += -DHAVE_GETTIMEOFDAY
endif

# Sound drivers config
ifdef SOUND_ESOUND
CONFIG  += -DSYSDEP_DSP_ESOUND `esd-config --cflags`
LIBS += `esd-config --libs`
endif

ifdef SOUND_ALSA
CONFIG  += -DSYSDEP_DSP_ALSA -DSYSDEP_MIXER_ALSA
LIBS += -lasound
endif

ifdef SOUND_ARTS_TEIRA
CONFIG  += -DSYSDEP_DSP_ARTS_TEIRA `artsc-config --cflags`
LIBS += `artsc-config --libs`
endif

ifdef SOUND_ARTS_SMOTEK
CONFIG  += -DSYSDEP_DSP_ARTS_SMOTEK `artsc-config --cflags`
LIBS += `artsc-config --libs`
endif

ifdef SOUND_SDL
CONFIG  += -DSYSDEP_DSP_SDL `$(SDL_CONFIG) --cflags`
LIBS += `$(SDL_CONFIG) --libs`
endif

ifdef SOUND_WAVEOUT
CONFIG  += -DSYSDEP_DSP_WAVEOUT
endif

# Joystick drivers config
ifdef JOY_STANDARD
CONFIG += -DSTANDARD_JOYSTICK
endif
ifdef JOY_PAD
CONFIG += -DLIN_FM_TOWNS
endif
ifdef JOY_PS2
CONFIG += -DPS2_JOYSTICK
endif

ifdef JOY_USB
CONFIG += -DUSB_JOYSTICK
ifeq ($(shell test -f /usr/include/usbhid.h && echo have_usbhid), have_usbhid)
CONFIG += -DHAVE_USBHID_H
LIBS += -lusbhid
else
ifeq ($(shell test -f /usr/include/libusbhid.h && echo have_libusbhid), have_libusbhid)
CONFIG += -DHAVE_LIBUSBHID_H
LIBS += -lusbhid
else
LIBS += -lusb
endif
endif
endif

ifdef JOY_SDL
CONFIG  += -DSDL_JOYSTICK `$(SDL_CONFIG) --cflags`
LIBS += `$(SDL_CONFIG) --libs`
endif

# Happ UGCI config
ifdef UGCICOIN
CONFIG += -DUGCICOIN
LIBS += -lugci
endif

ifdef LIRC
CONFIG += -DLIRC
endif

ifdef LIGHTGUN_ABS_EVENT
CONFIG += -DUSE_LIGHTGUN_ABS_EVENT
endif

ifdef LIGHTGUN_DEFINE_INPUT_ABSINFO
CONFIG += -DLIGHTGUN_DEFINE_INPUT_ABSINFO
endif

ifdef EFENCE
LIBS += -lefence
endif

OBJS += $(COREOBJS) $(CPULIB) $(SOUNDLIB) $(DRVLIBS)

OSDEPEND = $(OBJDIR)/osdepend.a

# MMX assembly language effects
ifdef EFFECT_MMX_ASM
CONFIG += -DEFFECT_MMX_ASM
UNIX_OBJS += $(UNIX_OBJDIR)/effect_asm.o
endif

##############################################################################
# Start of the real makefile.
##############################################################################

$(NAME).$(DISPLAY_METHOD): $(EXPAT) $(ZLIB) $(OBJS) $(UNIX_OBJS) $(OSDEPEND)
	@echo 'Linking $@ ...'
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(EXPAT) $(ZLIB) $(UNIX_OBJS) $(OSDEPEND) $(LIBS)

maketree: $(sort $(OBJDIRS))

$(sort $(OBJDIRS)):
	-mkdir -p $@

extra: $(TOOLS)

xlistdev: src/unix/contrib/tools/xlistdev.c
	@echo 'Compiling $< ...'
	$(CC) $(X11INC) src/unix/contrib/tools/xlistdev.c -o xlistdev $(JSLIB) $(LIBS.$(ARCH)) $(LIBS.$(DISPLAY_METHOD)) -lXi -lm

romcmp: $(OBJ)/romcmp.o $(OBJ)/unzip.o $(ZLIB)
	@echo 'Linking $@...'
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

chdman: $(OBJ)/chdman.o $(OBJ)/chd.o $(OBJ)/chdcd.o $(OBJ)/cdrom.o $(OBJ)/md5.o $(OBJ)/sha1.o $(OBJ)/version.o $(ZLIB) $(OSTOOLOBJS)
	@echo 'Linking $@...'
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

xml2info: $(OBJ)/xml2info.o $(EXPAT)
	@echo 'Linking $@...'
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

jedutil: $(OBJ)/jedutil.o $(OBJ)/jedparse.o $(OSDBGOBJS)
	@echo 'Linking $@...'
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

dat2html: $(DAT2HTML_OBJS)
	@echo 'Compiling $@...'
	$(LD) $(LDFLAGS) $^ -o $@

imgtool: $(IMGTOOL_OBJS) $(OSTOOLOBJS) $(ZLIB) $(PLATFORM_TOOL_OBJS)
	@echo 'Compiling $@...'
	$(LD) $(LDFLAGS) $^ $(LIBS) -o $@

messtest: $(OBJS) $(MESSTEST_OBJS) \
	$(OBJDIR)/dirio.o \
	$(OBJDIR)/fileio.o \
	$(OBJDIR)/ticker.o \
	$(OBJDIR)/parallel.o \
	$(OBJDIR)/sysdep/misc.o \
	$(OBJDIR)/sysdep/rc.o \
	$(OBJDIR)/tststubs.o \
	$(OBJDIR)/osd_tool.o
	@echo 'Linking $@...'
	$(LD) $(LDFLAGS) $(LIBS) $^ -Wl,--allow-multiple-definition -o $@

$(OBJDIR)/tststubs.o: src/unix/tststubs.c
	$(CC) $(CFLAGS) -o $@ -c $<

# library targets and dependencies
$(CPULIB): $(CPUOBJS)

ifdef DEBUG
$(CPULIB): $(DBGOBJS)
endif

$(SOUNDLIB): $(SOUNDOBJS)

$(OBJ)/libexpat.a: $(OBJ)/expat/xmlparse.o $(OBJ)/expat/xmlrole.o \
	$(OBJ)/expat/xmltok.o

$(OBJ)/libz.a: $(OBJ)/zlib/adler32.o $(OBJ)/zlib/compress.o \
	$(OBJ)/zlib/crc32.o $(OBJ)/zlib/deflate.o $(OBJ)/zlib/gzio.o \
	$(OBJ)/zlib/inffast.o $(OBJ)/zlib/inflate.o $(OBJ)/zlib/infback.o \
	$(OBJ)/zlib/inftrees.o $(OBJ)/zlib/trees.o $(OBJ)/zlib/uncompr.o \
	$(OBJ)/zlib/zutil.o

ifdef MESS
$(OBJ)/mess/%.o: mess/%.c
	@echo '[MESS] Compiling $< ...'
	$(CC) $(CFLAGS) -o $@ -c $<
endif

$(OBJ)/%.o: src/%.c
	@echo 'Compiling $< ...'
	$(CC) $(CFLAGS) -o $@ -c $<

$(OBJ)/%.a:
	@echo 'Archiving $@ ...'
	$(AR) $(AR_OPTS) $@ $^
	$(RANLIB) $@

$(OSDEPEND): $(UNIX_OBJS)
	@echo '[OSDEPEND] Archiving $@ ...'
	$(AR) $(AR_OPTS) $@ $(UNIX_OBJS)
	$(RANLIB) $@

$(UNIX_OBJDIR)/%.o: src/unix/%.c src/unix/xmame.h
	@echo '[OSDEPEND] Compiling $< ...'
	$(CC) $(CONFIG) -o $@ -c $<

$(UNIX_OBJDIR)/%.o: %.m src/unix/xmame.h
	@echo '[OSDEPEND] Compiling $< ...'
	$(CC) $(CFLAGS) -o $@ -c $<

# MMX assembly language for effect filters
$(OBJ)/unix.$(DISPLAY_METHOD)/effect_asm.o: src/unix/effect_asm.asm
	@echo Assembling $<...
	$(ASM) $(ASM_FMT) -o $@ $<

doc: src/unix/doc/xmame-doc.txt src/unix/doc/x$(TARGET)rc.dist doc/gamelist.$(TARGET) src/unix/doc/x$(TARGET).6

src/unix/doc/x$(TARGET)rc.dist: all src/unix/xmamerc-keybinding-notes.txt
	./x$(TARGET).$(DISPLAY_METHOD) -noloadconfig -showconfig | \
	 grep -v loadconfig | tr "\033" \# > src/unix/doc/x$(TARGET)rc.dist
	cat src/unix/xmamerc-keybinding-notes.txt >> src/unix/doc/x$(TARGET)rc.dist

src/unix/doc/gamelist.$(TARGET): all
	./x$(TARGET).$(DISPLAY_METHOD) -listgamelistheader > src/unix/doc/gamelist.$(TARGET)
	./x$(TARGET).$(DISPLAY_METHOD) -listgamelist >> src/unix/doc/gamelist.$(TARGET)

src/unix/doc/x$(TARGET).6: all src/unix/xmame.6-1 src/unix/xmame.6-3
	cat src/unix/xmame.6-1 > src/unix/doc/x$(TARGET).6
	./x$(TARGET).$(DISPLAY_METHOD) -noloadconfig -manhelp | \
	 tr "\033" \# >> src/unix/doc/x$(TARGET).6
	cat src/unix/xmame.6-3 >> src/unix/doc/x$(TARGET).6

install: $(INST.$(DISPLAY_METHOD)) install-man
	@echo $(NAME) for $(ARCH)-$(MY_CPU) installation completed

install-man:
	@echo Installing manual pages under $(MANDIR) ...
	-$(INSTALL_MAN_DIR) $(MANDIR)
	$(INSTALL_MAN) src/unix/doc/x$(TARGET).6 $(MANDIR)/x$(TARGET).6

doinstall:
	@echo Installing binaries under $(BINDIR)...
	-$(INSTALL_PROGRAM_DIR) $(BINDIR)
	$(INSTALL_PROGRAM) $(NAME).$(DISPLAY_METHOD) $(BINDIR)
	$(INSTALL_PROGRAM) $(TOOLS) $(BINDIR)

doinstallsuid:
	@echo Installing binaries under $(BINDIR)...
	-$(INSTALL_PROGRAM_DIR) $(BINDIR)
	$(INSTALL_PROGRAM_SUID) $(NAME).$(DISPLAY_METHOD) $(BINDIR)
	$(INSTALL_PROGRAM) $(TOOLS) $(BINDIR)

copycab:
	@echo Installing cabinet files under $(XMAMEROOT)...
	@cd src/unix; \
	for i in cab/*; do \
	if test ! -d $(XMAMEROOT)/$$i; then \
	$(INSTALL_DATA_DIR) $(XMAMEROOT)/$$i; fi; \
	for j in $$i/*; do $(INSTALL_DATA) $$j $(XMAMEROOT)/$$i; done; done

clean: 
	@rm -fr $(OBJ) $(NAME).* xlistdev $(TOOLS)

clean68k:
	@echo Deleting 68k object files...
	@rm -f $(OBJ)/cpuintrf.o
	@rm -f $(OBJ)/drivers/cps2.o
	@rm -f $(OBJ)/libcpu.a
	@rm -rf $(OBJ)/cpu/m68000

cleanosd:
	@echo Deleting OSDEPEND object files...
	@rm -rf $(OBJDIR)

cleancore:
	@echo Deleting core object files...
	@if test -d $(OBJ); then \
	@rm -rf `find $(OBJ) -mindepth 1 -path '$(OBJDIR)' -prune -o -print`; fi
