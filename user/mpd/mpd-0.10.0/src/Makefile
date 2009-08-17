EXEC=mpd

srcdir = .
top_srcdir = ..
top_builddir = ..
MPD_CFLAGS = -Wall

MPD_LIBS = -lmad -lid3tag -lz -lFLAC -lfaad -lmp4ff -laudiofile -lvorbisidec -lm

mpd_inputPlugins = \
	inputPlugins/aac_plugin.c \
	inputPlugins/audiofile_plugin.c \
	inputPlugins/flac_plugin.c \
	inputPlugins/mod_plugin.c \
	inputPlugins/mp3_plugin.c \
	inputPlugins/mp4_plugin.c \
	inputPlugins/ogg_plugin.c

mpd_SOURCES = \
	$(mpd_inputPlugins) \
	audio.c \
	audio_oss.c \
	buffer2array.c \
	charConv.c \
	command.c \
	conf.c \
	dbUtils.c \
	decode.c \
	directory.c \
	file_buffer.c \
	inputPlugin.c \
	inputStream.c \
	inputStream_file.c \
	inputStream_http.c \
	interface.c \
	list.c \
	listen.c \
	log.c \
	ls.c \
	main.c \
	metadataChunk.c \
	mpm_clone.c \
	myfprintf.c \
	outputBuffer.c \
	path.c \
	pcm_utils.c \
	permission.c \
	player.c \
	playerData.c \
	playlist.c \
	replayGain.c \
	sig_handlers.c \
	signal_check.c \
	song.c \
	stats.c \
	tag.c \
	tagTracker.c \
	utils.c \
	volume.c \
	utf8.c

CSRC = $(mpd_SOURCES)
DEFS = -DHAVE_CONFIG_H

#DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir) -I$(ROOTDIR)/uClibc/flac/include -I$(ROOTDIR)/uClibc/faad2/include -I$(ROOTDIR)/uClibc/libaudio/libaudiofile -I$(ROOTDIR)/uClibc/tremor -I$(ROOTDIR)/uClibc/libid3tag  -I$(ROOTDIR)/uClibc/libmad -I/usr/lib/local/include  -I$(ROOTDIR)/uClibc/libao-0.8.6 -I$(ROOTDIR)/uClibc/libao-0.8.6/include -I$(ROOTDIR)/glibc/debug

DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir) -I$(STAGEDIR)/usr/include/tremor

OBJS=$(patsubst %.c,%.o, $(CSRC))


EXTRALIBS = $(MPD_LIBS)


CFLAGS += $(MPD_CFLAGS)

FLTFLAGS += -s 0x1C000

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(EXTRALIBS)

$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@

romfs:
	echo "instaling mpd"
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.elf2flt *.o
	rm -f inputPlugins/*.o

