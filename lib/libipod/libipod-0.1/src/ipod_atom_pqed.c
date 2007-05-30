/*
 * ipod_atom_pqed.c
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
#include <ipod/ipod_string.h>
#include "ipod_atom_pqed.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_pqed(uint32_t version,void *data)
{
	if (data) {
		int i;
		ipod_atom_pqed pqed = (ipod_atom_pqed)data;
		pqed->name = ipod_string_new();
		pqed->preamp = 0;
		for (i=0;i<10;i++)
			pqed->bands0[i] = 0;
		for (i=0;i<5;i++)
			pqed->bands1[i] = 0;
	}
}

static void ipod_atom_free_pqed(void *data)
{
	if (data) {
		ipod_atom_pqed pqed = (ipod_atom_pqed)data;
		ipod_string_free(pqed->name);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_pqed(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		unsigned int i,len;
		size_t mark,dataRead;
		char *name;
		ipod_atom_pqed pqed = (ipod_atom_pqed)data;
		len = ipod_io_getuw(io); // length of name in characters
		mark = ipod_io_tell(io);
		name = (char *)ipod_memory_alloc(len*2);
		ipod_io_read(io,name,len*2,&dataRead);
		pqed->name = ipod_string_utf8_from_utf16(name,len);
		//ipod_error("ipod_atom_read_pqed(): got preset name %s\n",pqed->name);
		ipod_memory_free(name);
		ipod_io_seek(io,mark+510); // fixed length for name block
		pqed->preamp = ipod_io_getul(io);
		len = ipod_io_getul(io);
		if (len!=10)
			ipod_error("ipod_atom_read_pqed(): bad count for band0 (%d, 0x%x)\n",len,len);
		for (i=0;i<10;i++)
			pqed->bands0[i] = ipod_io_getul(io);
		len = ipod_io_getul(io);
		if (len!=5)
			ipod_error("ipod_atom_read_pqed(): bad count for band1 (%d, 0x%x)\n",len,len);
		for (i=0;i<5;i++)
			pqed->bands1[i] = ipod_io_getul(io);
	}
}

static void ipod_atom_prepare_to_write_pqed(ipod_atom root,uint32_t version,void *data)
{
}

static void ipod_atom_write_pqed(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		int i;
		ipod_atom_pqed pqed = (ipod_atom_pqed)data;
	}
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_pqed(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_pqed pqed = (ipod_atom_pqed)data;
	}
	return p;
}

void ipod_atom_set_plist_pqed(plist_item *plist,void *data)
{
}
#endif

char *ipod_atom_pqed_get_text_utf8(ipod_atom atom, int tag, char *s)
{
	s = ipod_string_zero(s);
	if (atom && atom->data) {
		ipod_atom_pqed pqed = (ipod_atom_pqed)atom->data;
		if (tag==IPOD_TITLE) {
			if (s) ipod_string_free(s);
			s = ipod_string_new_from(pqed->name);
		} else
			ipod_error("ipod_atom_pqed_get_text_utf8(): Non-string type %d\n",tag);
	}
	return s;
}

void ipod_atom_pqed_set_text_utf8(ipod_atom atom, int tag, const char *s)
{
	if (atom && atom->data) {
		ipod_atom_pqed pqed = (ipod_atom_pqed)atom->data;
		if (tag==IPOD_TITLE) {
			ipod_string_free(pqed->name);
			pqed->name = ipod_string_new_from(s);
		} else
			ipod_error("ipod_atom_pqed_get_text_utf8(): Non-string type %d\n",tag);
	}
}

int ipod_atom_pqed_has_text(ipod_atom atom, int tag)
{
	return tag==IPOD_TITLE;
}

int32_t ipod_atom_pqed_get_attribute(ipod_atom atom, int tag)
{
	if (atom && atom->data) {
		ipod_atom_pqed pqed = (ipod_atom_pqed)atom->data;
		if (tag==IPOD_EQ_PRESET_PREAMP)
			return pqed->preamp;
		else if (tag>=IPOD_EQ_PRESET_BAND_A_BASE && tag<IPOD_EQ_PRESET_BAND_A_BASE+10)
			return pqed->bands0[tag-IPOD_EQ_PRESET_BAND_A_BASE];
		else if (tag>=IPOD_EQ_PRESET_BAND_B_BASE && tag<IPOD_EQ_PRESET_BAND_B_BASE+5)
			return pqed->bands1[tag-IPOD_EQ_PRESET_BAND_B_BASE];
		else
			ipod_error("ipod_atom_pqed_get_attribute(): Invalid tag %d\n",tag);
	} else {
		ipod_error("ipod_atom_pqed_get_attribute(): Invalid preset atom\n");
	}
	return 0;
}

void ipod_atom_pqed_set_attribute(ipod_atom atom, int tag, int32_t value)
{
	if (atom && atom->data) {
		ipod_atom_pqed pqed = (ipod_atom_pqed)atom->data;
		if (tag==IPOD_EQ_PRESET_PREAMP)
			pqed->preamp = value;
		else if (tag>=IPOD_EQ_PRESET_BAND_A_BASE && tag<IPOD_EQ_PRESET_BAND_A_BASE+10)
			pqed->bands0[tag-IPOD_EQ_PRESET_BAND_A_BASE] = value;
		else if (tag>=IPOD_EQ_PRESET_BAND_B_BASE && tag<IPOD_EQ_PRESET_BAND_B_BASE+5)
			pqed->bands1[tag-IPOD_EQ_PRESET_BAND_B_BASE] = value;
		else
			ipod_error("ipod_atom_pqed_set_attribute(): Invalid tag %d\n",tag);
	} else {
		ipod_error("ipod_atom_pqed_set_attribute(): Invalid preset atom\n");
	}
}

ipod_atom ipod_atom_new_pqed(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_PQED;
		atom->init = ipod_atom_init_pqed;
		atom->free = ipod_atom_free_pqed;
		atom->read = ipod_atom_read_pqed;
		atom->prepare_to_write = ipod_atom_prepare_to_write_pqed;
		atom->write = ipod_atom_write_pqed;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_pqed;
		atom->set_plist = ipod_atom_set_plist_pqed;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_pqed_struct));
	}
	return atom;
}
