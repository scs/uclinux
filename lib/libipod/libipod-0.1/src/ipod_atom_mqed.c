/*
 * ipod_atom_mqed.c
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
#include <ipod/ipod_memory.h>
#include "ipod_atom_mqed.h"
#include "ipod_atom_pqed.h"
#include "ipod_private_constants.h"

typedef struct ipod_eq_preset_value {
	char *name;
	int32_t preamp;
	int32_t bands0[10];
	int32_t bands1[5];
} ipod_eq_preset_value;

//
// default presets
//
struct ipod_eq_preset_value ipod_eq_defaults[] = {
  {"Acoustic", 0,{ 500 , 490 , 395 , 105 , 215 , 175 , 350 , 410 , 355 , 215 },{ 400 , 100 , 100 , 300 , 300 }} ,
  {"Bass Booster", 0,{ 550 , 425 , 350 , 250 , 125 , 0 , 0 , 0 , 0 , 0 },{ 400 , 100 , 0 , 0 , 0 }} ,
  {"Bass Reducer", 0,{ -550 , -425 , -350 , -250 , -125 , 0 , 0 , 0 , 0 , 0 },{ -400 , -100 , 0 , 0 , 0 }} ,
  {"Classical", 0,{ 475 , 375 , 300 , 250 , -150 , -150 , 0 , 225 , 325 , 375 },{ 300 , 0 , -100 , 100 , 300 }} ,
  {"Dance", 0,{ 357 , 655 , 499 , 0 , 192 , 365 , 515 , 454 , 359 , 0 },{ 500 , 100 , 300 , 400 , 200 }} ,
  {"Deep", 0,{ 495 , 355 , 175 , 100 , 285 , 250 , 145 , -215 , -355 , -460 },{ 300 , 100 , 200 , 0 , -300 }} ,
  {"Electronic", 0,{ 425 , 380 , 120 , 0 , -215 , 225 , 85 , 125 , 395 , 480 },{ 300 , -100 , 200 , 100 , 400 }} ,
  {"Flat", 0,{ 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },{ 0 , 0 , 0 , 0 , 0 }} ,
  {"Hip-Hop", 0,{ 500 , 425 , 150 , 300 , -100 , -100 , 150 , -50 , 200 , 300 },{ 300 , 100 , -100 , 0 , 200 }} ,
  {"Jazz", 0,{ 400 , 300 , 150 , 225 , -150 , -150 , 0 , 150 , 300 , 375 },{ 200 , 0 , -100 , 0 , 300 }} ,
  {"Latin", 0,{ 450 , 300 , 0 , 0 , -150 , -150 , -150 , 0 , 300 , 450 },{ 200 , 0 , -100 , 0 , 300 }} ,
  {"Loudness", 0,{ 600 , 400 , 0 , 0 , -200 , 0 , -100 , -500 , 500 , 100 },{ 300 , 0 , 0 , -200 , 300 }} ,
  {"Lounge", 0,{ -300 , -150 , -50 , 150 , 400 , 250 , 0 , -150 , 200 , 100 },{ -100 , 200 , 200 , 0 , 100 }} ,
  {"Piano", 0,{ 300 , 200 , 0 , 250 , 300 , 150 , 350 , 450 , 300 , 350 },{ 100 , 200 , 100 , 400 , 300 }} ,
  {"Pop", 0,{ -150 , -100 , 0 , 200 , 400 , 400 , 200 , 0 , -100 , -150 },{ 0 , 300 , 400 , 100 , -100 }} ,
  {"R&B", 0,{ 262 , 692 , 565 , 133 , -219 , -150 , 232 , 265 , 300 , 375 },{ 500 , 0 , -100 , 200 , 300 }} ,
  {"Rock", 0,{ 500 , 400 , 300 , 150 , -50 , -100 , 50 , 250 , 350 , 450 },{ 400 , 0 , -100 , 100 , 300 }} ,
  {"Small Speakers", 0,{ 550 , 425 , 350 , 250 , 125 , 0 , -125 , -250 , -350 , -425 },{ 400 , 100 , 0 , -100 , -300 }} ,
  {"Spoken Word", 0,{ -346 , -47 , 0 , 69 , 346 , 461 , 484 , 428 , 254 , 0 },{ -100 , 200 , 400 , 400 , 100 }} ,
  {"Treble Booster", 0,{ 0 , 0 , 0 , 0 , 0 , 125 , 250 , 350 , 425 , 550 },{ 0 , 0 , 100 , 300 , 400 }} ,
  {"Treble Reducer", 0,{ 0 , 0 , 0 , 0 , 0 , -125 , -250 , -350 , -425 , -550 },{ 0 , 0 , -100 , -200 , -400 }} ,
  {"Vocal Booster", 0,{ -150 , -300 , -300 , 150 , 375 , 375 , 300 , 150 , 0 , -150 },{ -200 , 200 , 300 , 200 , 0 }},
  {NULL,0,{0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0}}
};

//
// initialize with default presets
//
static void ipod_atom_mqed_build_defaults(ipod_atom_mqed mqed)
{
	struct ipod_eq_preset_value *v = ipod_eq_defaults;
	while (v->name) {
		int i;
		ipod_atom a = ipod_atom_new_pqed();
		ipod_atom_init(a,IPOD_VERSION_ANY);
		ipod_atom_pqed_set_text_utf8(a,IPOD_TITLE,v->name);
		ipod_atom_pqed_set_attribute(a,IPOD_EQ_PRESET_PREAMP,v->preamp);
		for (i=0;i<10;i++)
			ipod_atom_pqed_set_attribute(a,IPOD_EQ_PRESET_BAND_A_BASE+i,v->bands0[i]);
		for (i=0;i<5;i++)
			ipod_atom_pqed_set_attribute(a,IPOD_EQ_PRESET_BAND_B_BASE+i,v->bands1[i]);
		ipod_atom_list_append(mqed->children,a);
		v++;
	}
}

static void ipod_atom_init_mqed(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)data;
		mqed->unk1 = 0;
		mqed->unk2 = 0;
		mqed->children = ipod_atom_list_new();
		ipod_atom_mqed_build_defaults(mqed);
	}
}

static void ipod_atom_free_mqed(void *data)
{
	if (data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)data;
		ipod_atom_list_remove_and_free_all(mqed->children);
		ipod_atom_list_free(mqed->children);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mqed(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,count,childSize;
		ipod_atom_mqed mqed = (ipod_atom_mqed)data;
		h1 = ipod_io_get_list_header(io);
		mqed->unk1 = ipod_io_getul(io);
		mqed->unk2 = ipod_io_getul(io);
		count = ipod_io_getul(io);
		childSize = ipod_io_getul(io);
		if (childSize!=588)
			ipod_error("ipod_atom_read_mqed(): unexpected child size (%d)\n",childSize);
		ipod_io_seek(io,h1);
		ipod_atom_list_remove_and_free_all(mqed->children);
		ipod_atom_list_read(mqed->children,count,io,version);
	}
}

static void ipod_atom_prepare_to_write_mqed(ipod_atom root,uint32_t version,void *data)
{
}

static void ipod_atom_write_mqed(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		ipod_atom_mqed mqed = (ipod_atom_mqed)data;
	
		mark = ipod_io_put_list_header(io,IPOD_ATOM_MQED,0x68);
		ipod_io_putul(io,mqed->unk1);
		ipod_io_putul(io,mqed->unk2);
		ipod_io_putul(io,ipod_atom_list_length(mqed->children));
		ipod_io_putul(io,588);
		ipod_io_put_pad(io,mark,0x68);
		ipod_atom_list_write(mqed->children,io,version);
	}
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_mqed(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mqed"));
		plist_item_dict_at_key_put(p,"unk1",plist_item_from_integer(mqed->unk1));
		plist_item_dict_at_key_put(p,"unk2",plist_item_from_integer(mqed->unk2));
		plist_item_dict_at_key_put(p,"children",ipod_atom_list_get_plist(mqed->children));
	}
	return p;
}

void ipod_atom_set_plist_mqed(plist_item *plist,void *data)
{
}
#endif

ipod_atom ipod_atom_new_mqed(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MQED;
		atom->init = ipod_atom_init_mqed;
		atom->free = ipod_atom_free_mqed;
		atom->read = ipod_atom_read_mqed;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mqed;
		atom->write = ipod_atom_write_mqed;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mqed;
		atom->set_plist = ipod_atom_set_plist_mqed;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mqed_struct));
	}
	return atom;
}

unsigned long ipod_atom_mqed_preset_count(ipod_atom atom)
{
	if (atom && atom->data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)atom->data;
		return ipod_atom_list_length(mqed->children);
	} else {
		ipod_error("ipod_atom_mqed_preset_count(): Invalid eq atom\n");
	}
	return 0;
}

ipod_atom ipod_atom_mqed_get_preset_by_index(ipod_atom atom,unsigned long index)
{
	if (atom && atom->data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)atom->data;
		if (index>=0 && index<ipod_atom_list_length(mqed->children)) {
			return ipod_atom_list_get(mqed->children,index);
		} else {
			ipod_error("ipod_atom_mqed_get_preset_by_index(): Index %d out of range\n",index);
		}
	} else {
		ipod_error("ipod_atom_mqed_get_preset_by_index(): Invalid eq atom\n");
	}
	return NULL;
}

ipod_atom ipod_atom_mqed_new_preset(ipod_atom atom)
{
	if (atom && atom->data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)atom->data;
		ipod_atom a = ipod_atom_new_pqed();
		ipod_atom_init(a,IPOD_VERSION_ANY);
		ipod_atom_list_append(mqed->children,a);
		return a;
	} else {
		ipod_error("ipod_atom_mqed_new_preset(): Invalid eq atom\n");
	}
	return NULL;	
}

void ipod_atom_mqed_remove_preset(ipod_atom atom, ipod_atom item)
{
	if (atom && atom->data) {
		ipod_atom_mqed mqed = (ipod_atom_mqed)atom->data;
		ipod_atom_list_remove(mqed->children,item);
	} else {
		ipod_error("ipod_atom_mqed_remove_preset(): Invalid eq atom\n");
	}
}

