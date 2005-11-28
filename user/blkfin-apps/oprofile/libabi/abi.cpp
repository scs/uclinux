/**
 * @file abi.cpp
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Graydon Hoare
 * @author John Levon
 */

#include "abi.h"
#include "odb.h"
#include "op_sample_file.h"

#include <iostream>
#include <cassert>

using namespace std;

typedef map<string, int> abi_map;
typedef map<string, int>::const_iterator abi_iter;

#define byte_addr(x) (reinterpret_cast<unsigned char *>(&(x)))
#define field_offset(s, f) (byte_addr(s.f) - byte_addr(s))

abi_exception::abi_exception(string const d) : desc(d) {}


abi::abi()
{
	odb_node_t node;
	odb_descr_t descr;
	struct opd_header header;
	
	slots["sizeof_double"] = sizeof(double);
	slots["sizeof_time_t"] = sizeof(time_t);
	slots["sizeof_u8"] = sizeof(u8);
	slots["sizeof_u32"] = sizeof(u32);
	slots["sizeof_int"] = sizeof(int);
	slots["sizeof_unsigned_int"] = sizeof(unsigned int);
	slots["sizeof_odb_key_t"] = sizeof(odb_key_t);
	slots["sizeof_odb_index_t"] = sizeof(odb_index_t);
	slots["sizeof_odb_value_t"] = sizeof(odb_value_t);
	slots["sizeof_odb_node_nr_t"] = sizeof(odb_node_nr_t);
	slots["sizeof_odb_descr_t"] = sizeof(odb_descr_t);
	slots["sizeof_odb_node_t"] = sizeof(odb_node_t);
	slots["sizeof_struct_opd_header"] = sizeof(struct opd_header);		
	
	slots["offsetof_node_key"] = field_offset(node, key);
	slots["offsetof_node_value"] = field_offset(node, value);
	slots["offsetof_node_next"] = field_offset(node, next);
	
	slots["offsetof_descr_size"] = field_offset(descr, size);
	slots["offsetof_descr_current_size"] = field_offset(descr, current_size);
	
	slots["offsetof_header_magic"] = field_offset(header, magic);
	slots["offsetof_header_version"] = field_offset(header, version);
	slots["offsetof_header_cpu_type"] = field_offset(header, cpu_type);
	slots["offsetof_header_ctr_event"] = field_offset(header, ctr_event);
	slots["offsetof_header_ctr_um"] = field_offset(header, ctr_um);
	slots["offsetof_header_ctr_count"] = field_offset(header, ctr_count);
	slots["offsetof_header_is_kernel"] = field_offset(header, is_kernel);
	slots["offsetof_header_cpu_speed"] = field_offset(header, cpu_speed);
	slots["offsetof_header_mtime"] = field_offset(header, mtime);
	slots["offsetof_header_cg_to_is_kernel"] = field_offset(header,
		cg_to_is_kernel);
	slots["offsetof_header_anon_start"] = field_offset(header, anon_start);
	slots["offsetof_header_cg_to_anon_start"] = field_offset(header,
		cg_to_anon_start);

	// determine endianness

	unsigned int probe = 0xff;
	size_t sz = sizeof(unsigned int);
	unsigned char * probe_byte = reinterpret_cast<unsigned char *>(&probe);

	assert(probe_byte[0] == 0xff || probe_byte[sz - 1] == 0xff);

	if (probe_byte[0] == 0xff)
		slots["little_endian"] = 1;
	else
		slots["little_endian"] = 0;
}


abi::abi(abi const & other)
{
	slots.clear();
	slots.insert(other.slots.begin(), other.slots.end());
}


int abi::need(string const key) const throw (abi_exception)
{
	if (slots.find(key) != slots.end())
		return slots.find(key)->second;
	else
		throw abi_exception(string("missing ABI key: ") + key);
}


bool abi::operator==(abi const & other) const
{
	abi_iter i = slots.begin();
	abi_iter e = slots.end();
	abi_map const & theirs = other.slots;

	for (; i != e; ++i) {
		if (theirs.find(i->first) == theirs.end() ||
		    theirs.find(i->first)->second != i->second)
			return false;
	}

	return true;		
}


ostream & operator<<(ostream & o, abi const & abi)
{
	abi_iter i = abi.slots.begin();
	abi_iter e = abi.slots.end();

	for (; i != e; ++i) {
		o << i->first << " " << i->second << endl;
	}

	return o;
}


istream & operator>>(istream & i, abi & abi)
{
	string key;
	int val;
	abi.slots.clear();

	while(i >> key >> val) {
		abi.slots[key] = val;
	}

	return i;
}
