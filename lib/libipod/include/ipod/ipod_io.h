/*
 * ipod_io.h
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

#ifndef __IPOD_IO_H__
#define __IPOD_IO_H__

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_io.h
 *  \brief I/O functions for reading and writing iPod data structures
 */

/** \brief Callback to implement reads for a device
 *
 * \param data pointer to buffer in which to store the data that has been read
 * \param maxDataLen the maximum amount of data to read
 * \param dataRead a pointer in which to store the actual amount of data read
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
typedef int (*ipod_io_read_func)(void *data, size_t maxDataLen, size_t *dataRead,void *userData);

/** \brief Callback to implement writes to a device
 *
 * \param data pointer to buffer from which to read the data to be written
 * \param dataLen the amount of data to write
 * \param dataWritten a pointer in which to store the actual amount of data written
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
typedef int (*ipod_io_write_func)(void *data, size_t dataLen,size_t *dataWritten,void *userData);

/** \brief The current location of the device mark
 *
 * \param offset a pointer to a location in which to write the mark
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
typedef int (*ipod_io_tell_func)(size_t *offset,void *userData);

/** \brief Seeks the device to the given location
 *
 * \param offset the offset into the device to which to seek
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
typedef int (*ipod_io_seek_func)(size_t offset,void *userData);

/** \brief The total amount of data on the device
 *
 * \param offset a pointer to a loctio nin which to store the length of the data stream
 * \param userData an opaque structure containing information about this device
 * \return 0 for success -1 for failure
 */
typedef int (*ipod_io_length_func)(size_t *offset,void *userData);

/** \brief the internal structure of an ipod_io device
 */
typedef struct {
	void *userData; /*!< \brief ipod_io type-specific data, sent to callback */
	ipod_io_read_func read; /*!< \brief Read callback */
	ipod_io_write_func write; /*!< \brief Write callback */
	ipod_io_tell_func tell; /*!< \brief Tell callback */
	ipod_io_seek_func seek; /*!< \brief Seek callback */
	ipod_io_length_func length; /*!< \brief Length callback */
} ipod_io_struct;

typedef ipod_io_struct *ipod_io; /*!< \brief opaque reference to the device */

/** \brief Reads data from a device
 *
 * \param io the ipod_io device
 * \param data pointer to buffer in which to store the data that has been read
 * \param maxDataLen the maximum amount of data to read
 * \param dataRead a pointer in which to store the actual amount of data read
 * \return 0 for success -1 for failure
 */
extern int ipod_io_read(ipod_io io,void *data, size_t maxDataLen, size_t *dataRead);

/** \brief Writes data to a device
 *
 * \param io the ipod_io device
 * \param data pointer to buffer from which to read the data to be written
 * \param dataLen the amount of data to write
 * \param dataWritten a pointer in which to store the actual amount of data written
 * \return 0 for success -1 for failure
 */
extern int ipod_io_write(ipod_io io,void *data, size_t dataLen, size_t *dataWritten);

/** \brief Read a signed byte from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern int8_t ipod_io_getb(ipod_io io);

/** \brief Write a signed byte to the device
 *
 * \param io the ipod_io device
 * \param b the value to write
 */
extern void ipod_io_putb(ipod_io io,int8_t b);

/** \brief Read an unsigned byte from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint8_t ipod_io_getub(ipod_io io);

/** \brief Write an unsigned byte to the device
 *
 * \param io the ipod_io device
 * \param b the value to write
 */
extern void ipod_io_putub(ipod_io io,uint8_t b);

/** \brief Read a little-endian signed word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern int16_t ipod_io_getw(ipod_io io);

/** \brief Write a little-endian signed word to the device
 *
 * \param io the ipod_io device
 * \param w the value to write
 */
extern void ipod_io_putw(ipod_io io,int16_t w);

/** \brief Read a little-endian unsigned word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint16_t ipod_io_getuw(ipod_io io);

/** \brief Write a little-endian unsigned word to the device
 *
 * \param io the ipod_io device
 * \param w the value to write
 */
extern void ipod_io_putuw(ipod_io io,uint16_t w);

/** \brief Read a big-endian signed word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern int16_t ipod_io_getw_be(ipod_io io);

/** \brief Write a big-endian signed word to the device
 *
 * \param io the ipod_io device
 * \param w the value to write
 */
extern void ipod_io_putw_be(ipod_io io,int16_t w);

/** \brief Read a big-endian unsigned word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint16_t ipod_io_getuw_be(ipod_io io);

/** \brief Write a big-endian unsigned word to the device
 *
 * \param io the ipod_io device
 * \param w the value to write
 */
extern void ipod_io_putuw_be(ipod_io io,uint16_t w);

/** \brief Read a little-endian signed long word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern int32_t ipod_io_getl(ipod_io io);

/** \brief Write a little-endian signed long word to the device
 *
 * \param io the ipod_io device
 * \param l the value to write
 */
extern void ipod_io_putl(ipod_io io,int32_t l);

/** \brief Read a little-endian unsigned long word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint32_t ipod_io_getul(ipod_io io);

/** \brief Write a little-endian unsigned long word to the device
 *
 * \param io the ipod_io device
 * \param l the value to write
 */
extern void ipod_io_putul(ipod_io io,uint32_t l);


/** \brief Read a big-endian signed long word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern int32_t ipod_io_getl_be(ipod_io io);

/** \brief Write a big-endian signed long word to the device
 *
 * \param io the ipod_io device
 * \param l the value to write
 */
extern void ipod_io_putl_be(ipod_io io,int32_t l);

/** \brief Read a big-endian unsigned long word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint32_t ipod_io_getul_be(ipod_io io);

/** \brief Write a big-endian unsigned long word to the device
 *
 * \param io the ipod_io device
 * \param l the value to write
 */
extern void ipod_io_putul_be(ipod_io io,uint32_t l);

/** \brief Read a little-endian single-precision float from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern float ipod_io_getf(ipod_io io);

/** \brief Write a little-endian single-precision float to the device
 *
 * \param io the ipod_io device
 * \param f the value to write
 */
extern void ipod_io_putf(ipod_io io,float f);

/** \brief Read a 4-character tag from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint32_t ipod_io_get4cc(ipod_io io);


/** \brief Write a 4-character tag to the device
 *
 * \param io the ipod_io device
 * \param l the value to write
 */
extern void ipod_io_put4cc(ipod_io io,uint32_t l);


/** \brief Read a 3-byte little-endian unsigned long word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint32_t ipod_io_getul3(ipod_io io);

/** \brief Write a 3-byte little-endian unsigned long word to the device
 *
 * \param io the ipod_io device
 * \param l the value to write
 */
extern void ipod_io_putul3(ipod_io io,uint32_t l);

/** \brief Read a synch-safe unsigned long word from the device
 *
 * \param io the ipod_io device
 * \return the value
 */
extern uint32_t ipod_io_getul_ss(ipod_io io); // synchsafe integers from MP3 files

/** \brief Seek the device
 *
 * \param io the ipod_io device
 * \param offset the location to which to seek
 */
extern void ipod_io_seek(ipod_io io,size_t offset);

/** \brief Return the current mark of the device
 *
 * \param io the ipod_io device
 * \return the offset of the current mark
 */
extern size_t ipod_io_tell(ipod_io io);

/** \brief Return the total length of the data in this device
 *
 * \param io the ipod_io device
 * \return the total lenght of the data
 */
 
extern size_t ipod_io_length(ipod_io io);

/** \brief Seek the device relative to the current mark
 *
 * \param io the ipod_io device
 * \param count the number of bytes to skip
 */
extern void ipod_io_skip(ipod_io io,size_t count);

/** \brief Backpatch a location in the file to offset to the current mark
 *
 * \param io the ipod_io device
 * \param mark the location to fill in with the offset to the current mark
 */
extern void ipod_io_backpatch(ipod_io io,size_t mark);

/** \brief Read a simple ipod data atom header
 *
 * \param io the ipod_io device
 * \param h1 pointer to location to store the atom header size
 * \param h2 pointer to location to store the atom full size
 */
extern void ipod_io_get_simple_header(ipod_io io,size_t *h1,size_t *h2);

/** \brief Write a simple ipod data atom header
 *
 * \param io the ipod_io device
 * \param tag the 4-character tag for the atom
 * \param size the size of the header
 */
extern size_t ipod_io_put_simple_header(ipod_io io,uint32_t tag,size_t size);

/** \brief Read an ipod list atom header
 *
 * \param io the ipod_io device
 * \return the size of the header
 */
extern size_t ipod_io_get_list_header(ipod_io io);

/** \brief Write an ipod list atom header
 *
 * \param io the ipod_io device
 * \param tag the 4-character tag for the atom
 * \param size the size of the header
 */
extern size_t ipod_io_put_list_header(ipod_io io,uint32_t tag,size_t size);

/** \brief Write a ficed number of null bytes
 *
 * \param io the ipod_io device
 * \param count the number of null bytes to write
 */
extern void ipod_io_put_zeros(ipod_io io,unsigned int count);

/** \brief Write out padding bytes to reach a particular offset from a particular mark
 *
 * \param io the ipod_io device
 * \param mark the base location of the padding
 * \param size the intended final size after padding with null bytes
 */
extern void ipod_io_put_pad(ipod_io io,size_t mark,size_t size);

#ifdef __cplusplus
};
#endif

#endif
