/**
 * @file db_insert.c
 * Inserting a key-value pair into a DB
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "odb.h"

int odb_insert(odb_t * odb, odb_key_t key, odb_value_t value)
{
	odb_index_t index;
	odb_index_t new_node;
	odb_node_t * node;
	odb_data_t * data;

	data = odb->data;
	index = data->hash_base[odb_do_hash(data, key)];
	while (index) {
		if (index <= 0 || index >= data->descr->current_size) {
			return EINVAL;
		}
		node = &data->node_base[index];
		if (node->key == key) {
			if (node->value + value >= node->value) {
				node->value += value;
			} else {
				/* post profile tools must handle overflow */
				node->value = ~(odb_value_t)0;
			}
			return 0;
		}

		index = node->next;
	}

	/* no locking is necessary: iteration interface retrieve data through
	 * the node_base array, odb_hash_add_node() increase current_size but
	 * odb_travel just ignore node with a zero key so on setting the key
	 * atomically update the node */
	new_node = odb_hash_add_node(odb);
	if (new_node == ODB_NODE_NR_INVALID) {
		return EINVAL;
	}

	node = &data->node_base[new_node];
	node->value = value;
	node->key = key;

	/* we need to recalculate hash code, hash table has perhaps grown */
	index = odb_do_hash(data, key);
	node->next = data->hash_base[index];
	data->hash_base[index] = new_node;
	
	return 0;
}
