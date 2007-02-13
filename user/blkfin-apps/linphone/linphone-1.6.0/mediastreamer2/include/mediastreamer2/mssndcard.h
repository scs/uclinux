/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef sndcard_h
#define sndcard_h

#include "mscommon.h"

struct _MSSndCardManager{
	MSList *cards;
};

typedef struct _MSSndCardManager MSSndCardManager;

enum _MSSndCardMixerElem{
	MS_SND_CARD_MASTER,
	MS_SND_CARD_PLAYBACK,
	MS_SND_CARD_CAPTURE
};
typedef enum _MSSndCardMixerElem MSSndCardMixerElem;

enum _MSSndCardCapture {
	MS_SND_CARD_MIC,
	MS_SND_CARD_LINE
};
typedef enum _MSSndCardCapture MSSndCardCapture;

struct _MSSndCard;

typedef void (*MSSndCardDetectFunc)(MSSndCardManager *obj);
typedef void (*MSSndCardInitFunc)(struct _MSSndCard *obj);
typedef void (*MSSndCardUninitFunc)(struct _MSSndCard *obj);
typedef void (*MSSndCardSetLevelFunc)(struct _MSSndCard *obj, MSSndCardMixerElem e, int percent);
typedef void (*MSSndCardSetCaptureFunc)(struct _MSSndCard *obj, MSSndCardCapture e);
typedef int (*MSSndCardGetLevelFunc)(struct _MSSndCard *obj, MSSndCardMixerElem e);
typedef struct _MSFilter * (*MSSndCardCreateReaderFunc)(struct _MSSndCard *obj);
typedef struct _MSFilter * (*MSSndCardCreateWriterFunc)(struct _MSSndCard *obj);
typedef struct _MSSndCard * (*MSSndCardDuplicateFunc)(struct _MSSndCard *obj);

struct _MSSndCardDesc{
	const char *driver_type;
	MSSndCardDetectFunc detect;
	MSSndCardInitFunc init;
	MSSndCardSetLevelFunc set_level;
	MSSndCardGetLevelFunc get_level;
	MSSndCardSetCaptureFunc set_capture;
	MSSndCardCreateReaderFunc create_reader;
	MSSndCardCreateWriterFunc create_writer;
	MSSndCardUninitFunc uninit;
	MSSndCardDuplicateFunc duplicate;

};

typedef struct _MSSndCardDesc MSSndCardDesc;

struct _MSSndCard{
	MSSndCardDesc *desc;
	char *name;
	char *id;
	void *data;
};

typedef struct _MSSndCard MSSndCard;

#ifdef __cplusplus
extern "C"{
#endif

MSSndCardManager * ms_snd_card_manager_get(void);
void ms_snd_card_manager_destroy(void);
MSSndCard * ms_snd_card_manager_get_card(MSSndCardManager *m, const char *id);
MSSndCard * ms_snd_card_manager_get_default_card(MSSndCardManager *m);
const MSList * ms_snd_card_manager_get_list(MSSndCardManager *m);
void ms_snd_card_manager_add_card(MSSndCardManager *m, MSSndCard *c);
void ms_snd_card_manager_register_desc(MSSndCardManager *m, MSSndCardDesc *desc);


MSSndCard * ms_snd_card_new(MSSndCardDesc *desc);
MSSndCard * ms_snd_card_dup(MSSndCard *card);
const char *ms_snd_card_get_driver_type(const MSSndCard *obj);
const char *ms_snd_card_get_name(const MSSndCard *obj);
/*returns driver_type: name, should be unique */ 
const char *ms_snd_card_get_string_id(MSSndCard *obj);
void ms_snd_card_set_level(MSSndCard *obj, MSSndCardMixerElem e, int percent);
int ms_snd_card_get_level(MSSndCard *obj, MSSndCardMixerElem e);
void ms_snd_card_set_capture(MSSndCard *obj, MSSndCardCapture c);
struct _MSFilter * ms_snd_card_create_reader(MSSndCard *obj);
struct _MSFilter * ms_snd_card_create_writer(MSSndCard *obj);
void ms_snd_card_destroy(MSSndCard *obj);


#ifdef __cplusplus
}
#endif

#endif
