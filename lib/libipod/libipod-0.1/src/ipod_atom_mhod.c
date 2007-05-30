/*
 * ipod_atom_mhod.c
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <ipod/ipod_error.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_string.h>
#include <ipod/ipod_memory.h>
#include "ipod_atom.h"
#include "ipod_atom_mhod.h"
#include "ipod_atom_mhbd.h"
#include "ipod_atom_mhsd.h"
#include "ipod_atom_mhlt.h"
#include "ipod_atom_mhit.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_mhod(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		mhod->type = 0;
		mhod->unk1 = 0;
		mhod->unk2 = 0;
	}
}

static void ipod_atom_free_mhod_string(void *data) {
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	if (mhod->data.ipod_atom_mhod_string.string)
		ipod_memory_free(mhod->data.ipod_atom_mhod_string.string);
}

static void ipod_atom_free_mhod_url(void *data) {
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	if (mhod->data.ipod_atom_mhod_url.string)
		ipod_memory_free(mhod->data.ipod_atom_mhod_url.string);
}

static void ipod_atom_free_mhod_library_index(void *data) {
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	if (mhod->data.ipod_atom_mhod_library_index.indices)
		ipod_memory_free(mhod->data.ipod_atom_mhod_library_index.indices);
}

static void ipod_atom_free_mhod_raw(void *data) {
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	if (mhod->data.ipod_atom_mhod_raw.data)
		ipod_memory_free(mhod->data.ipod_atom_mhod_raw.data);
}

static void ipod_atom_free_mhod(void *data)
{
	if (data) {
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		if (mhod->type) {
			if (mhod->type==IPOD_ENCLOSUREURL || mhod->type==IPOD_RSSURL)
				ipod_atom_free_mhod_url(data);
			else if (mhod->type==IPOD_CHAPTER)
				ipod_atom_free_mhod_raw(data);
			else if (mhod->type<IPOD_SMARTPLAYLIST_PREF)
				ipod_atom_free_mhod_string(data);
			else if (mhod->type==IPOD_LIBRARYPLAYLIST_INDEX)
				ipod_atom_free_mhod_library_index(data);
			else
				ipod_atom_free_mhod_raw(data);
		}
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhod_string(ipod_io io,uint32_t version,void *data)
{
	size_t read;
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	mhod->data.ipod_atom_mhod_string.position = ipod_io_getul(io);
	mhod->data.ipod_atom_mhod_string.length = ipod_io_getul(io);
	mhod->data.ipod_atom_mhod_string.unk3 = ipod_io_getul(io);
	mhod->data.ipod_atom_mhod_string.unk4 = ipod_io_getul(io);
	mhod->data.ipod_atom_mhod_string.string = (char *)ipod_memory_alloc(mhod->data.ipod_atom_mhod_string.length);
	ipod_io_read(io,mhod->data.ipod_atom_mhod_string.string,mhod->data.ipod_atom_mhod_string.length,&read);
}

static void ipod_atom_read_mhod_url(ipod_io io,uint32_t version,void *data,size_t h2)
{
	size_t length,read;
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	mhod->data.ipod_atom_mhod_url.length = h2-ipod_io_tell(io);
	mhod->data.ipod_atom_mhod_url.string = (char *)ipod_memory_alloc(mhod->data.ipod_atom_mhod_url.length);
	ipod_io_read(io,mhod->data.ipod_atom_mhod_url.string,mhod->data.ipod_atom_mhod_url.length,&read);
}

static void ipod_atom_read_mhod_library_index(ipod_io io,uint32_t version,void *data)
{
	size_t count,i,read;
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	mhod->data.ipod_atom_mhod_library_index.sortIndex = ipod_io_getul(io);
	mhod->data.ipod_atom_mhod_library_index.count = ipod_io_getul(io);
	for (i=0;i<10;i++)
		(void) ipod_io_getul(io);
	mhod->data.ipod_atom_mhod_library_index.indices =
		(uint32_t*)ipod_memory_alloc(mhod->data.ipod_atom_mhod_library_index.count*sizeof(uint32_t));
	for (i=0;i<mhod->data.ipod_atom_mhod_library_index.count;i++)
		mhod->data.ipod_atom_mhod_library_index.indices[i] = ipod_io_getul(io);
}

static void ipod_atom_read_mhod_raw(ipod_io io,uint32_t version,void *data,size_t h2)
{
	size_t length,read;
	ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	mhod->data.ipod_atom_mhod_raw.length = h2-ipod_io_tell(io);
	mhod->data.ipod_atom_mhod_raw.data = (char *)ipod_memory_alloc(mhod->data.ipod_atom_mhod_raw.length);
	ipod_io_read(io,mhod->data.ipod_atom_mhod_raw.data,mhod->data.ipod_atom_mhod_raw.length,&read);
}

static void ipod_atom_read_mhod(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,h2;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		ipod_io_get_simple_header(io,&h1,&h2);
		mhod->type = ipod_io_getul(io);
		mhod->unk1 = ipod_io_getul(io);
		mhod->unk2 = ipod_io_getul(io);
		if (mhod->type) {
			if (mhod->type==IPOD_ENCLOSUREURL || mhod->type==IPOD_RSSURL)
				ipod_atom_read_mhod_url(io,version,data,h2);
			else if (mhod->type==IPOD_CHAPTER)
				ipod_atom_read_mhod_raw(io,version,data,h2);
			else if (mhod->type<IPOD_SMARTPLAYLIST_PREF)
				ipod_atom_read_mhod_string(io,version,data);
			else if (mhod->type==IPOD_LIBRARYPLAYLIST_INDEX)
				ipod_atom_read_mhod_library_index(io,version,data);
			else
				ipod_atom_read_mhod_raw(io,version,data,h2);
		}
		ipod_io_seek(io,h2);
	}		
}


typedef struct {
	uint32_t index;
	ipod_atom_mhod_string_struct *string;
} ipod_atom_mhod_library_index_sort;


int ipod_atom_mhod_library_index_compare(const void *a,const void *b)
{
	ipod_atom_mhod_library_index_sort *aa = (ipod_atom_mhod_library_index_sort *)a;
	ipod_atom_mhod_library_index_sort *bb = (ipod_atom_mhod_library_index_sort *)b;
	/*
	char *as,*bs;
	as = ipod_string_utf8_from_utf16(aa->string->string,aa->string->length/2);
	bs = ipod_string_utf8_from_utf16(bb->string->string,bb->string->length/2);
	ipod_memory_free(as); ipod_memory_free(bs);
	*/
	return ipod_string_compare_utf16(aa->string->string,aa->string->length/2,bb->string->string,bb->string->length/2);
}

static void ipod_atom_prepare_to_write_mhod_library_index(ipod_atom root, uint32_t version, ipod_atom_mhod mhod)
{
	ipod_atom mhsd, mhlt;
	ipod_atom_list mhits;
	static ipod_atom_mhod_string_struct nullString = { 0,0,0,10,"~\0~\0~\0~\0~\0"};
	
	mhsd = ipod_atom_mhbd_tracks(root);
	mhlt = ipod_atom_mhsd_tracks(mhsd);
	mhits = ipod_atom_mhlt_tracks(mhlt);
	if (mhits) {
		unsigned int i;
		unsigned int trackCount;
		ipod_atom_mhod_library_index_sort *s;
		trackCount = ipod_atom_list_length(mhits);
		s = (ipod_atom_mhod_library_index_sort *)ipod_memory_alloc(trackCount*sizeof(ipod_atom_mhod_library_index_sort));
		//printf("sorting by field %d\n",mhod->data.ipod_atom_mhod_library_index.sortIndex);
		for (i=0;i<trackCount;i++) {
			ipod_atom mhit_atom = ipod_atom_list_get(mhits,i);
			s[i].index = i;
			if (mhit_atom) {
				switch (mhod->data.ipod_atom_mhod_library_index.sortIndex) {
					case IPOD_SORT_ORDER_TITLE:
						s[i].string = ipod_atom_mhit_title_struct(mhit_atom); break;
					case IPOD_SORT_ORDER_ALBUM:
						s[i].string = ipod_atom_mhit_album_struct(mhit_atom); break;
					case IPOD_SORT_ORDER_ARTIST:
						s[i].string = ipod_atom_mhit_artist_struct(mhit_atom); break;
					case IPOD_SORT_ORDER_GENRE:
						s[i].string = ipod_atom_mhit_genre_struct(mhit_atom); break;
					case IPOD_SORT_ORDER_COMPOSER:
						s[i].string = ipod_atom_mhit_composer_struct(mhit_atom); break;
				}
			}
			if (s[i].string==NULL)
				s[i].string = &nullString;
		}
		qsort(s,trackCount,sizeof(ipod_atom_mhod_library_index_sort),ipod_atom_mhod_library_index_compare);
		mhod->data.ipod_atom_mhod_library_index.count = trackCount;
		mhod->data.ipod_atom_mhod_library_index.indices =
			(uint32_t *)ipod_memory_realloc(mhod->data.ipod_atom_mhod_library_index.indices,
			trackCount*sizeof(uint32_t));
		for (i=0;i<trackCount;i++)
			mhod->data.ipod_atom_mhod_library_index.indices[i] = s[i].index;
		//printf("done library sort\n");
		ipod_memory_free(s);
	}
}

static void ipod_atom_prepare_to_write_mhod(ipod_atom root,uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		if (mhod->type==IPOD_LIBRARYPLAYLIST_INDEX) {
			ipod_atom_prepare_to_write_mhod_library_index(root,version,mhod);
		}
	}
}

static void ipod_atom_write_mhod_string(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t dataWritten;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		ipod_io_putul(io,mhod->data.ipod_atom_mhod_string.position);
		ipod_io_putul(io,mhod->data.ipod_atom_mhod_string.length);
		ipod_io_putul(io,mhod->data.ipod_atom_mhod_string.unk3);
		ipod_io_putul(io,mhod->data.ipod_atom_mhod_string.unk4);
		ipod_io_write(io,mhod->data.ipod_atom_mhod_string.string,
			mhod->data.ipod_atom_mhod_string.length,&dataWritten);
	}
}

static void ipod_atom_write_mhod_url(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t dataWritten;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		ipod_io_write(io,mhod->data.ipod_atom_mhod_url.string,
			mhod->data.ipod_atom_mhod_url.length,&dataWritten);
	}
}

static void ipod_atom_write_mhod_library_index(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t dataWritten,i;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		ipod_io_putul(io,mhod->data.ipod_atom_mhod_library_index.sortIndex);
		ipod_io_putul(io,mhod->data.ipod_atom_mhod_library_index.count);
		ipod_io_put_zeros(io,10);
		for (i=0;i<mhod->data.ipod_atom_mhod_library_index.count;i++)
			ipod_io_putul(io,mhod->data.ipod_atom_mhod_library_index.indices[i]);
	}
}

static void ipod_atom_write_mhod_raw(ipod_io io, uint32_t version,void *data)
{
		size_t dataWritten;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		ipod_io_write(io,mhod->data.ipod_atom_mhod_raw.data,
			mhod->data.ipod_atom_mhod_raw.length,&dataWritten);
}

static void ipod_atom_write_mhod(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		int i;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
	
		mark = ipod_io_put_simple_header(io,IPOD_ATOM_MHOD,0x18);
		ipod_io_putul(io,mhod->type);
		ipod_io_putul(io,mhod->unk1);
		ipod_io_putul(io,mhod->unk2);
		if (mhod->type) {
			if (mhod->type==IPOD_ENCLOSUREURL || mhod->type==IPOD_RSSURL)
				ipod_atom_write_mhod_url(io,version,data);
			else if (mhod->type==IPOD_CHAPTER)
				ipod_atom_write_mhod_raw(io,version,data);
			else if (mhod->type<IPOD_SMARTPLAYLIST_PREF)
				ipod_atom_write_mhod_string(io,version,data);
			else if (mhod->type==IPOD_LIBRARYPLAYLIST_INDEX)
				ipod_atom_write_mhod_library_index(io,version,data);
			else
				ipod_atom_write_mhod_raw(io,version,data);
		}
		ipod_io_backpatch(io,mark);
	}
}

static void ipod_atom_copy_mhod_url(ipod_atom_mhod mhod, ipod_atom_mhod copy)
{
	size_t len = mhod->data.ipod_atom_mhod_url.length;
	copy->data.ipod_atom_mhod_url.length = len;
	copy->data.ipod_atom_mhod_url.string = (char *)ipod_memory_alloc(len);
	memcpy(copy->data.ipod_atom_mhod_url.string,mhod->data.ipod_atom_mhod_url.string,len);
}

static void ipod_atom_copy_mhod_raw(ipod_atom_mhod mhod, ipod_atom_mhod copy)
{
	size_t len = mhod->data.ipod_atom_mhod_raw.length;
	copy->data.ipod_atom_mhod_raw.length = len;
	copy->data.ipod_atom_mhod_raw.data = (char *)ipod_memory_alloc(len);
	memcpy(copy->data.ipod_atom_mhod_raw.data,mhod->data.ipod_atom_mhod_raw.data,len);
}

static void ipod_atom_copy_mhod_string(ipod_atom_mhod mhod, ipod_atom_mhod copy)
{
	size_t len = mhod->data.ipod_atom_mhod_string.length;
	copy->data.ipod_atom_mhod_string.position = mhod->data.ipod_atom_mhod_string.position;
	copy->data.ipod_atom_mhod_string.unk3 = mhod->data.ipod_atom_mhod_string.unk3;
	copy->data.ipod_atom_mhod_string.unk4 = mhod->data.ipod_atom_mhod_string.unk4;
	copy->data.ipod_atom_mhod_string.length = len;
	copy->data.ipod_atom_mhod_string.string = (char *)ipod_memory_alloc(len);
	memcpy(copy->data.ipod_atom_mhod_string.string,mhod->data.ipod_atom_mhod_string.string,len);
}

static void ipod_atom_copy_mhod_library_index(ipod_atom_mhod mhod, ipod_atom_mhod copy)
{
	size_t len = mhod->data.ipod_atom_mhod_library_index.count*4;
	copy->data.ipod_atom_mhod_library_index.sortIndex = mhod->data.ipod_atom_mhod_library_index.sortIndex;
	copy->data.ipod_atom_mhod_library_index.count = mhod->data.ipod_atom_mhod_library_index.count;
	copy->data.ipod_atom_mhod_library_index.indices = (uint32_t*)ipod_memory_alloc(len);
	memcpy(copy->data.ipod_atom_mhod_library_index.indices,mhod->data.ipod_atom_mhod_library_index.indices,len);
}

static void *ipod_atom_copy_mhod(void *data) {
	if (data) {
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		ipod_atom_mhod copy = (ipod_atom_mhod)ipod_memory_alloc(sizeof(ipod_atom_mhod_struct));
		copy->type = mhod->type;
		copy->unk1 = mhod->unk1;
		copy->unk2 = mhod->unk2;
		if (mhod->type) {
			if (mhod->type==IPOD_ENCLOSUREURL || mhod->type==IPOD_RSSURL)
				ipod_atom_copy_mhod_url(mhod,copy);
			else if (mhod->type==IPOD_CHAPTER)
				ipod_atom_copy_mhod_raw(mhod,copy);
			else if (mhod->type<IPOD_SMARTPLAYLIST_PREF)
				ipod_atom_copy_mhod_string(mhod,copy);
			else if (mhod->type==IPOD_LIBRARYPLAYLIST_INDEX)
				ipod_atom_copy_mhod_library_index(mhod,copy);
			else
				ipod_atom_copy_mhod_raw(mhod,copy);
		}
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
static ipod_atom_get_plist_mhod_string(plist_item *p,void *data)
{
	if (data) {
		char *s;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		s = ipod_string_utf8_from_utf16(mhod->data.ipod_atom_mhod_string.string,mhod->data.ipod_atom_mhod_string.length/2);
		plist_item_dict_at_key_put(p,"string",plist_item_from_string(s));
		ipod_memory_free(s);
		plist_item_dict_at_key_put(p,"position",plist_item_from_integer(mhod->data.ipod_atom_mhod_string.position));
		plist_item_dict_at_key_put(p,"unk3",plist_item_from_integer(mhod->data.ipod_atom_mhod_string.unk3));
		plist_item_dict_at_key_put(p,"unk4",plist_item_from_integer(mhod->data.ipod_atom_mhod_string.unk4));
	}
}

static ipod_atom_get_plist_mhod_url(plist_item *p,void *data)
{
	if (data) {
		char *s;
		size_t len;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		len = mhod->data.ipod_atom_mhod_url.length;
		s = (char *)ipod_memory_alloc(len+1);
		memmove(s,mhod->data.ipod_atom_mhod_url.string,len);
		s[len] = '\0';
		plist_item_dict_at_key_put(p,"string",plist_item_from_string(s));
		ipod_memory_free(s);
	}
}

static ipod_atom_get_plist_mhod_library_index(plist_item *p,void *data)
{
	if (data) {
		int i;
		plist_item *a;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		plist_item_dict_at_key_put(p,"sortIndex",plist_item_from_integer(mhod->data.ipod_atom_mhod_library_index.sortIndex));
		a = plist_item_new_array();
		plist_item_dict_at_key_put(p,"indices",a);
		for (i=0;i<mhod->data.ipod_atom_mhod_library_index.count;i++)
			plist_item_array_append(a,plist_item_from_integer(mhod->data.ipod_atom_mhod_library_index.indices[i]));
	}
}

static ipod_atom_get_plist_mhod_raw(plist_item *p,void *data)
{
	if (data) {
		char *s;
		size_t len;
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		len = mhod->data.ipod_atom_mhod_raw.length;
		s = (char *)ipod_memory_alloc(len+1);
		memmove(s,mhod->data.ipod_atom_mhod_raw.data,len);
		s[len] = '\0';
		plist_item_dict_at_key_put(p,"data",plist_item_from_string(s));
		ipod_memory_free(s);
	}
}

plist_item *ipod_atom_get_plist_mhod(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mhod mhod = (ipod_atom_mhod)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhod"));
		plist_item_dict_at_key_put(p,"type",plist_item_from_integer(mhod->type));
		plist_item_dict_at_key_put(p,"unk1",plist_item_from_integer(mhod->unk1));
		plist_item_dict_at_key_put(p,"unk2",plist_item_from_integer(mhod->unk2));
		if (mhod->type) {
			if (mhod->type==IPOD_ENCLOSUREURL || mhod->type==IPOD_RSSURL)
				ipod_atom_get_plist_mhod_url(p,data);
			else if (mhod->type==IPOD_CHAPTER)
				ipod_atom_get_plist_mhod_raw(p,data);
			else if (mhod->type<IPOD_SMARTPLAYLIST_PREF)
				ipod_atom_get_plist_mhod_string(p,data);
			else if (mhod->type==IPOD_LIBRARYPLAYLIST_INDEX)
				ipod_atom_get_plist_mhod_library_index(p,data);
			else
				ipod_atom_get_plist_mhod_raw(p,data);
		}
	}
	return p;
}

void ipod_atom_set_plist_mhod(plist_item *plist,void *data)
{
}
#endif

ipod_atom ipod_atom_new_mhod(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHOD;
		atom->init = ipod_atom_init_mhod;
		atom->free = ipod_atom_free_mhod;
		atom->read = ipod_atom_read_mhod;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhod;
		atom->write = ipod_atom_write_mhod;
		atom->copy = ipod_atom_copy_mhod;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhod;
		atom->set_plist = ipod_atom_set_plist_mhod;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhod_struct));
	}
	return atom;
}

ipod_atom ipod_atom_new_mhod_string(int tag,const char *s)
{
	ipod_atom_mhod mhod;
	ipod_atom_mhod_string_struct *ss;
	ipod_atom mhod_atom =  ipod_atom_new_mhod();
	ipod_atom_init(mhod_atom,IPOD_VERSION_ANY);
	mhod = (ipod_atom_mhod)mhod_atom->data;
	mhod->type = tag;
	ss = &mhod->data.ipod_atom_mhod_string;
	ss->position = 1;
	ss->unk3 = 0;
	ss->unk4 = 0;
	ss->length = 0;
	ss->string = ipod_memory_alloc(0);
	ipod_atom_mhod_string_set(mhod_atom,s);
	return mhod_atom;
}

char *ipod_atom_mhod_string_get(ipod_atom atom,char *s)
{
	ipod_atom_mhod_string_struct *ss;
	ipod_atom_mhod mhod = (ipod_atom_mhod)atom->data;
	if (s) s = ipod_string_zero(s);
	else s = ipod_string_new();
	if (atom) {
		ss = &mhod->data.ipod_atom_mhod_string;
		if (ss) {
			unsigned long len = ipod_string_utf16_to_utf8_length(ss->string,ss->length/2);
			s = ipod_string_realloc(s,len);
			ipod_string_utf16_to_utf8(ss->string,ss->length/2,s,len+1);
		}
	}
	return s;
}

void ipod_atom_mhod_string_set(ipod_atom atom,const char *s)
{
	ipod_atom_mhod mhod = (ipod_atom_mhod)atom->data;
	if (s) {
		ipod_atom_mhod_string_struct *ss = &mhod->data.ipod_atom_mhod_string;
		ss->length = ipod_string_utf8_to_utf16_length(s)*2;
		ss->string = ipod_memory_realloc(ss->string,ss->length);
		ipod_string_utf8_to_utf16(s,ss->string,ss->length);
	}
}

ipod_atom ipod_atom_new_mhod_url(int tag,const char *s)
{
	ipod_error("ipod_atom_new_mhod_url(): Not yet implemented\n");
	return NULL;
}

char *ipod_atom_mhod_url_get(ipod_atom atom,char *s)
{
	ipod_error("ipod_atom_mhod_url_get(): Not yet implemented\n");
	return s;
}

void ipod_atom_mhod_url_set(ipod_atom atom,const char *s)
{
	ipod_error("ipod_atom_mhod_url_set(): Not yet implemented\n");
}

ipod_atom ipod_atom_new_mhod_library_index(int key)
{
	ipod_atom mhod_atom;
	ipod_atom_mhod mhod;
	
	mhod_atom = ipod_atom_new_mhod();
	ipod_atom_init(mhod_atom,IPOD_VERSION_ANY);
	mhod = (ipod_atom_mhod)mhod_atom->data;
	mhod->data.ipod_atom_mhod_library_index.sortIndex = key;
	mhod->data.ipod_atom_mhod_library_index.count = 0;
	mhod->data.ipod_atom_mhod_library_index.indices =
		(uint32_t *)ipod_memory_alloc(0);
	return mhod_atom;
}

