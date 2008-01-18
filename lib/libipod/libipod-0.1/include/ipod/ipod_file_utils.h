/*
 * ipod_file_utils.h
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

#ifndef __IPOD_FILE_UTILS_H__
#define __IPOD_FILE_UTILS_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_file_utils.h
 *  \brief File handling routines
 */

/** \brief Callback used during file transfers
 *
 * \param transferred the number of bytes transferred so far
 * \param total the total numb er of bytes to be transferred
 * \param userData application-specific data
 */
typedef void (*ipod_file_transfer_func)(uint64_t transferred, uint64_t total,void *userData);

/** \brief Test for the existence of a directory
 *
 * \param path a path to a directory
 * \return 1 if the directory exists, 0 otherwise
 */
extern int ipod_directory_exists(const char *path);

/** \brief Test for the existence of a file
 *
 * \param path a path to a file
 * \return 1 if the file exists, 0 otherwise
 */
extern int ipod_file_exists(const char *path);

/** \brief Delete a file
 *
 * \param path a path to a file to be deleted
 */
extern void ipod_delete_file(const char *path);

/** \brief Copy a file from one location to another
 *
 * \param srcFile the file to be copied
 * \param dstFile the location to which to copy the file
 * \param callback the function to call during the copy to report progess information
 * \param userData application-specific data to provide to the callback function
 * \return 0 if the copy succeeded, -1 if it failed
 */
extern int ipod_copy_file(const char *srcFile, const char *dstFile,ipod_file_transfer_func callback,void *userData);

/** \brief Returns a pointer to the extension of the file, including the dot
 *
 * \param path a file path
 * \param def a string to return if no extension can be found
 * \return a pointer to the extension
 *
 * \code
 * printf(ipod_extension_of("/home/jayne/hero_of_canton.mp3",".wav"));  -> ".mp3"
 * \endcode
 */
extern const char *ipod_extension_of(const char *path,const char *def);

/** \brief Locate the filename in a full file path
 *
 * \param path a full file path
 * \return a pointer to the filename portion of the path
 *
 * \code
 * printf(ipod_file_name_of("/home/jayne/hero_of_canton.mp3")); -> "hero_of_canton.mp3"
 * \endcode
 */
extern const char *ipod_file_name_of(const char *path);

#ifdef __cplusplus
};
#endif

#endif
