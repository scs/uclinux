/*
 * plist.h
 *
 * Duane Maxwell
 * (c) Linspire, Inc 2005
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

#ifndef __PLIST_H_
#define __PLIST_H_

#ifdef PLIST

#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern 'C' {
#endif

enum {
	PLIST_ITEM_TYPE_UNKNOWN,
	PLIST_ITEM_TYPE_INTEGER,
	PLIST_ITEM_TYPE_REAL,
	PLIST_ITEM_TYPE_STRING,
	PLIST_ITEM_TYPE_TRUE, // true and false actually use boolean type
	PLIST_ITEM_TYPE_FALSE,
	PLIST_ITEM_TYPE_DATE, // in ISO 8601 format
	PLIST_ITEM_TYPE_DATA, // Base-64 encoded data
	PLIST_ITEM_TYPE_ARRAY,
	PLIST_ITEM_TYPE_DICT,
	PLIST_ITEM_TYPE_PLIST,
	
	PLIST_ITEM_TYPE_KEY, // fake entry of interest to parser
	PLIST_ITEM_TYPE_BOOLEAN // used to store true and false values
};

//
// internal structures - should not need to use them
//
typedef struct plist_array_type {
	size_t p_array_length;
	struct plist_item **p_array_items;
} plist_array_type;

typedef struct plist_dict_element {
	char *p_key;
	struct plist_item *p_value;
} plist_dict_element;

typedef struct plist_dict_type {
	size_t p_dict_length;
	plist_dict_element *p_dict_items;
} plist_dict_type;

typedef struct plist_data_type {
	size_t p_data_length;
	void *p_data;
} plist_data_type;

typedef struct plist_item {
	int p_type;
	struct plist_item *p_parent; // used by parser
	union {
		int p_integer; // integer
		double p_real;  // real
		char *p_string; // string
		int p_boolean; // true, false
		time_t p_date; // date
		plist_data_type p_data; // data
		plist_array_type p_array; // array
		plist_dict_type p_dict; // dict
		struct plist_item *p_child; // plist
	} u;
} plist_item;

//
// check type of element
//
int plist_item_type(plist_item *p);
int plist_item_is_type(plist_item *p,int type);

//
// create elements of each type
//
plist_item *plist_item_from_integer(int i);
plist_item *plist_item_from_real(double f);
plist_item *plist_item_from_string(char *s); // makes copy of s
plist_item *plist_item_from_boolean(int b);
plist_item *plist_item_from_date(time_t t);
plist_item *plist_item_from_data(void *bytes,size_t len); // makes copy of bytes
plist_item *plist_item_new_array(void);
plist_item *plist_item_new_dict(void);
plist_item *plist_item_new_plist(void);

//
// dispose of element (includes memebers of array and dict)
//
void plist_item_free(plist_item *p);

//
// get atomic values
//
int plist_item_integer_value(plist_item *p);
double plist_item_real_value(plist_item *p);
char *plist_item_string_value(plist_item *p); // returns internal
int plist_item_boolean_value(plist_item *p);
time_t plist_item_date_value(plist_item *p);
void *plist_item_data_value(plist_item *p,size_t *len); // returns internal data

//
// handle arrays
//
size_t plist_item_array_length(plist_item *array);
plist_item *plist_item_array_at_index(plist_item *array,int i);
plist_item *plist_item_array_at_index_put(plist_item *array,int i,plist_item *value); // keeps value
plist_item *plist_item_array_append(plist_item *array,plist_item *value); // keeps value

//
// handle dicts
//
size_t plist_item_dict_length(plist_item *dict);
char *plist_item_dict_key_at_index(plist_item *dict,int i);
int plist_item_dict_has_key(plist_item *dict,char *key); // makes copy of key
plist_item *plist_item_dict_at_key(plist_item *dict,char *key);
plist_item *plist_item_dict_at_key_put(plist_item *dict,char *key,plist_item *value); // keeps value

//
// handle plists
//
plist_item *plist_item_plist_value(plist_item *plist); // returns internal
plist_item *plist_item_plist_set_value(plist_item *plist,plist_item *value); // keeps value

//
// parse from a file
//
plist_item *plist_item_from_file(char *fileName);

//
// dump xml-ish representation to stdout for debugging purposes
// currently does not encode standard entities
//
void plist_dump(plist_item *p);

//helper functions for returning tag values
char * plist_string_item(plist_item *p,char* key,char* if_missing);
int  plist_integer_item(plist_item *p,char* key,int if_missing);
time_t plist_date_item(plist_item *p,char *key,time_t if_missing);
int plist_bool_item(plist_item *p,char *key,int if_missing);

#ifdef __cplusplus
}
#endif
#endif
#endif
