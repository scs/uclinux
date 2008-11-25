/**
 * @file op_abi.h
 * This file contains a simple C interface to the ABI-describing functionality,
 * the majority of which is implemented in C++. this is the file which is 
 * intended for use in files outside the /libabi directory.
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Graydon Hoare
 */

#ifndef OP_ABI_H
#define OP_ABI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Write current abi to file.
 * return 1 on success, 0 on failure
 */
int op_write_abi_to_file(char const * abi_file);

#ifdef __cplusplus
}
#endif

#endif // OP_ABI_H
