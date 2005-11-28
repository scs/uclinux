/**
 * @file op_abi.cpp
 * This file contains a simple C interface to the ABI-describing functionality,
 * the majority of which is implemented in C++. this is the file which is 
 * intended for use in files outside the /libabi directory.
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Graydon Hoare
 */

#include "op_abi.h"
#include "abi.h"

#include <fstream>

using namespace std;

int op_write_abi_to_file(char const * abi_file)
{
	ofstream file(abi_file);
	if (!file) 
		return 0;

	abi curr;
	file << curr;

	return 1;
}
