/*
 * ipod_io_memory.h
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

#ifndef __IPOD_IO_MEMORY_H__
#define __IPOD_IO_MEMORY_H__

#include <ipod/ipod_io.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_io_memory.h
 *  \brief An implementation of an ipod_io device that reads and writes to a memory block
 */

/** \brief Read data from this device
 *
 * \param data pointer to buffer in which to store the data that has been read
 * \param maxDataLen the maximum amount of data to read
 * \param dataRead a pointer in which to store the actual amount of data read
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
extern int ipod_io_memory_read(void *data, size_t maxDataLen, size_t *dataRead,void *userData);

/** \brief Write data to this device
 *
 * \param data pointer to buffer from which to read the data to be written
 * \param dataLen the amount of data to write
 * \param dataWritten a pointer in which to store the actual amount of data written
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
extern int ipod_io_memory_write(void *data, size_t dataLen,size_t *dataWritten,void *userData);

/** \brief The current location of the device mark
 *
 * \param offset a pointer to a location in which to write the mark
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
extern int ipod_io_memory_tell(size_t *offset,void *userData);

/** \brief Seeks the device to the given location
 *
 * \param offset the offset into the device to which to seek
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
extern int ipod_io_memory_seek(size_t offset,void *userData);

/** \brief The total amount of data of the device
 *
 * \param offset a pointer to a loctio nin which to store the length of the data stream
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
extern int ipod_io_memory_length(size_t *offset,void *userData);

/** \brief Create a new device into memory, typically for writing
 *
 * \return a new ipod_io device
 */
extern ipod_io ipod_io_memory_new(void);

/** \brief Create a new device for an existing block of memory, typically for reading
 *
 * \param data a pointer to a block of memory
 * \param dataLen the total size of the block of memory
 * \return a new ipod_io device
 */
extern ipod_io ipod_io_memory_new_from_memory(char *data,size_t dataLen);

/** \brief Free the ipod_io device, and free the memory if created by ipod_io_memory_new()
 *
 * \param io the ipod_io device to free
 */
extern void ipod_io_memory_free(ipod_io io);

/** \brief The amount of memeory currently begin used for the device
 *
 * \param io the ipod_io device
 * \return the size of the memory block on this device
 */
extern size_t ipod_io_memory_size(ipod_io io);

/** \brief The memory block used by this device
 *
 * \param io the ipod_io device
 * \return a pointer to the block of memory
 */
extern char *ipod_io_memory_data(ipod_io io);

#ifdef __cplusplus
};
#endif

#endif
