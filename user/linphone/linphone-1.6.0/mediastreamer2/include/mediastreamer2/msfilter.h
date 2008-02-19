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

#ifndef msfilter_h
#define msfilter_h

#include "mscommon.h"
#include "msqueue.h"
#include "allfilters.h"

typedef void (*MSFilterFunc)(struct _MSFilter *f);
typedef int (*MSFilterMethodFunc)(struct _MSFilter *f, void *arg);
typedef void (*MSFilterNotifyFunc)(void *userdata , unsigned int id, void *arg);

struct _MSFilterMethod{
	int id;
	MSFilterMethodFunc method;
};

typedef struct _MSFilterMethod MSFilterMethod;

enum _MSFilterCategory{
	MS_FILTER_OTHER,
	MS_FILTER_ENCODER,
	MS_FILTER_DECODER
};

typedef enum _MSFilterCategory MSFilterCategory;

struct _MSFilterDesc{
	MSFilterId id;	/* the id declared in allfilters.h */
	const char *name; /* filter name */
	const char *text; /*some descriptive text*/
	MSFilterCategory category;
	const char *enc_fmt; /* must be set if MS_FILTER_ENCODER/MS_FILTER_DECODER */
	int ninputs; /*number of inputs */
	int noutputs; /*number of outputs */
	MSFilterFunc init;
	MSFilterFunc preprocess;	/* called once before processing */
	MSFilterFunc process;		/* called every tick to do the filter's job*/
	MSFilterFunc postprocess;	/*called once after processing */
	MSFilterFunc uninit;
	MSFilterMethod *methods;
};

typedef struct _MSFilterDesc MSFilterDesc;

struct _MSFilter{
	MSFilterDesc *desc;
	/*protected attributes */
	ms_mutex_t lock;
	MSQueue **inputs;
	MSQueue **outputs;
	MSFilterNotifyFunc notify;
	void *notify_ud;
	void *data;
	struct _MSTicker *ticker;
	/*private attributes */
	uint32_t last_tick;
	bool_t seen;
};

typedef struct _MSFilter MSFilter;

#ifdef __cplusplus
extern "C"{
#endif

/* useful for plugins only */
void ms_filter_register(MSFilterDesc *desc);
/* functions to retrieve encoders/decoders according to codec name */
MSFilterDesc * ms_filter_get_encoder(const char *mime);
MSFilterDesc * ms_filter_get_decoder(const char *mime);
MSFilter * ms_filter_create_encoder(const char *mime);
MSFilter * ms_filter_create_decoder(const char *mime);
bool_t ms_filter_codec_supported(const char *mime);

MSFilter *ms_filter_new(MSFilterId id);
MSFilter *ms_filter_new_from_name(const char *name);
int ms_filter_link(MSFilter *f1, int pin1, MSFilter *f2, int pin2);
int ms_filter_unlink(MSFilter *f1, int pin1, MSFilter *f2, int pin2);
int ms_filter_call_method(MSFilter *f, unsigned int id, void *arg);
int ms_filter_call_method_noarg(MSFilter *f, unsigned int id);
void ms_filter_set_notify_callback(MSFilter *f, MSFilterNotifyFunc fn, void *userdata);
MSFilterId ms_filter_get_id(MSFilter *f);
void ms_filter_destroy(MSFilter *f);

#ifdef __cplusplus
}
#endif

/* I define the id taking the lower bits of the address of the MSFilterDesc object,
the method index (_cnt_) and the argument size */
/* I hope using this to avoid type mismatch (calling a method on the wrong filter)*/
#define MS_FILTER_METHOD_ID(_id_,_cnt_,_argsize_) \
	(  (((unsigned long)(_id_)) & 0xFFFF)<<16 | (_cnt_<<8) | (_argsize_ & 0xFF ))

#define MS_FILTER_METHOD(_id_,_count_,_argtype_) \
	MS_FILTER_METHOD_ID(_id_,_count_,sizeof(_argtype_))

#define MS_FILTER_METHOD_NO_ARG(_id_,_count_) \
	MS_FILTER_METHOD_ID(_id_,_count_,0)


#define MS_FILTER_BASE_METHOD(_count_,_argtype_) \
	MS_FILTER_METHOD_ID(MS_FILTER_BASE_ID,_count_,sizeof(_argtype_))

#define MS_FILTER_EVENT(_id_,_count_,_argtype_) \
	MS_FILTER_METHOD_ID(_id_,_count_,sizeof(_argtype_))

#define MS_FILTER_EVENT_NO_ARG(_id_,_count_)\
	MS_FILTER_METHOD_ID(_id_,_count_,0)

/* some MSFilter base methods:*/
#define MS_FILTER_SET_SAMPLE_RATE	MS_FILTER_BASE_METHOD(0,int)
#define MS_FILTER_GET_SAMPLE_RATE	MS_FILTER_BASE_METHOD(1,int)
#define MS_FILTER_SET_BITRATE		MS_FILTER_BASE_METHOD(2,int)
#define MS_FILTER_GET_BITRATE		MS_FILTER_BASE_METHOD(3,int)
#define MS_FILTER_SET_FMTP		MS_FILTER_BASE_METHOD(4,const char)
#define MS_FILTER_GET_NCHANNELS		MS_FILTER_BASE_METHOD(5,int)
#define MS_FILTER_SET_NCHANNELS		MS_FILTER_BASE_METHOD(6,int)
#define MS_FILTER_ADD_FMTP		MS_FILTER_BASE_METHOD(7,const char)
#define MS_FILTER_ADD_ATTR		MS_FILTER_BASE_METHOD(8,const char)
#define MS_FILTER_SET_MTU		MS_FILTER_BASE_METHOD(9,int)
#define MS_FILTER_GET_MTU		MS_FILTER_BASE_METHOD(10,int)
#define MS_FILTER_SET_FRAMESIZE MS_FILTER_BASE_METHOD(11,int)
#define MS_FILTER_SET_FILTERLENGTH MS_FILTER_BASE_METHOD(12,int)
#define MS_FILTER_SET_OUTPUT_SAMPLE_RATE MS_FILTER_BASE_METHOD(13,int)
#define MS_FILTER_ENABLE_DIRECTMODE MS_FILTER_BASE_METHOD(14,int)
#define MS_FILTER_ENABLE_VAD MS_FILTER_BASE_METHOD(15,int)
#define MS_FILTER_GET_STAT_DISCARDED MS_FILTER_BASE_METHOD(16,int)
#define MS_FILTER_GET_STAT_MISSED MS_FILTER_BASE_METHOD(17,int)
#define MS_FILTER_GET_STAT_INPUT MS_FILTER_BASE_METHOD(18,int)
#define MS_FILTER_GET_STAT_OUTPUT MS_FILTER_BASE_METHOD(19,int)

/*private methods*/
MSFilter *ms_filter_new_from_desc(MSFilterDesc *desc);
void ms_filter_process(MSFilter *f);
void ms_filter_preprocess(MSFilter *f, struct _MSTicker *t);
void ms_filter_postprocess(MSFilter *f);
bool_t ms_filter_inputs_have_data(MSFilter *f);
void ms_filter_notify(MSFilter *f, unsigned int id, void *arg);
void ms_filter_notify_no_arg(MSFilter *f, unsigned int id);
#define ms_filter_lock(f)	ms_mutex_lock(&(f)->lock)
#define ms_filter_unlock(f)	ms_mutex_unlock(&(f)->lock)
void ms_filter_unregister_all(void);

/* used by awk script in Makefile.am to generate alldescs.c */
#define MS_FILTER_DESC_EXPORT(desc)

#endif
