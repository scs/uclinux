/*
 * ipod_memory.h
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

#ifndef __IPOD_MEMORY_H__
#define __IPOD_MEMORY_H__

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_memory.h
 *  \brief Memory allocation functions
 */

/** \brief Callback to allocate memory
 *
 * \param size the number of bytes to allocate
 * \param userData implementation-specific data
 * \return a pointer to the allocated bytes
 */
typedef void *(*ipod_memory_alloc_func)(size_t size,void *userData);

/** \brief Callback to reallocate memory
 *
 * \param p the block of memory to be reallocated
 * \param size the number of bytes to allocate
 * \param userData implementation-specific data
 * \return a pointer to the reallocated bytes
 */
typedef void *(*ipod_memory_realloc_func)(void *p, size_t size,void *userData);

/** \brief Callback to free memory
 *
 * \param p the block of memory to free
 * \param userData implementation-specific data
 */
typedef void (*ipod_memory_free_func)(void *p,void *userData);

/** \brief Set the memory callback functions
 *
 * \param alloc_func callback to allocate memory
 * \param realloc_func callback to reallocate memory
 * \param free_func callback to free memory
 * \param userData implementation-specific data sent to the callbacks
 */
extern void ipod_memory_set_funcs(
		ipod_memory_alloc_func alloc_func,
		ipod_memory_realloc_func realloc_func,
		ipod_memory_free_func free_func,
		void *userData);

/** \brief Allocate memory
 *
 * \param size the number of bytes to allocate
 * \return a pointer to the allocated bytes
 */
extern void *ipod_memory_alloc(size_t size);

/** \brief Reallocate memory
 *
 * \param p the block of memory to be reallocated
 * \param size the number of bytes to allocate
 * \return a pointer to the reallocated bytes
 */
extern void *ipod_memory_realloc(void *p,size_t size);

/** \brief Free memory
 *
 * \param p the block of memory to free
 */
extern void ipod_memory_free(void *p);

/** \brief Print out some internal statistics
 */
extern void ipod_memory_report(void);

#ifdef __cplusplus
};
#endif

#endif
