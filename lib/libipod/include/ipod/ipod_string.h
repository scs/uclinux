/*
 * ipod_string.h
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

#ifndef __IPOD_STRING_H__
#define __IPOD_STRING_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_string.h
 *  \brief String manipulation functions
 *
 * The iPod data structures store text in a variety of formats. The bulk
 * of the text items are stored in UTF-16LE, but some are in either ASCII or
 * UTF-8.  The libipod API normalizes all of them to UTF-8, although the C++
 * binding will also support ISO-8859-1.
 */

/** \brief Allocates a new zero-terminated string on the heap
 *
 * \return pointer to a single zero byte on the heap
 */
extern char *ipod_string_new(void);

/** \brief Allocates a new zero-terminated string on the heap copied from the given string
 *
 * \param s the string to copy
 * \return pointer to the new string
 */
extern char *ipod_string_new_from(const char *s);

/** \brief Allocates a new string on the heap created from an array of characters
 *
 * \param s a pointer to an array of characters
 * \param length the number of characters in the array
 * \return pointer to the new string
 */ 
extern char *ipod_string_new_from_array(const char *s, size_t length);

/** \brief Copy a string into an exising allocated string, resizing as necessary
 *
 * \param s the string to copy into
 * \param ss the string to copy from
 * \return the reallocated string
 */
extern char *ipod_string_set(char *s,const char *ss);

/** \brief Free the string back to the heap
 *
 * \param s the string to free
 */
extern void ipod_string_free(char *s);

/** \brief Resize an existing string to an empty string
 *
 * \param s the string to empty
 * \return the reallocated string
 */
extern char *ipod_string_zero(char *s);

/** \brief Reallocate an existing string to hold the given length, plus the terminating null
 *
 * \param src the string to resize
 * \param length the new lenght for the string
 * \return the reallocated string
 */
extern char *ipod_string_realloc(char *src, size_t length);

/** \brief Append a string to an existing string
 *
 * \param src the string to wich to append
 * \param a the string to append
 * \return the reallocated string
 */
extern char *ipod_string_append(char *src,const char *a);

/** \brief Destructively replace all instances of a with b in an existing string
 *
 * \param src the strin to modify
 * \param a the character to replace
 * \param b the character with which to replace
 */
extern void ipod_string_replace_char(char *src, const char a, const char b);

/** \brief Calculate the number of bytes necessary for a UTF-8 encoding of an array of UTF-16LE characters
 *
 * \param src pointer to the array of UTF-16LE characters
 * \param numChars the number of characters in the UTF-16BE array
 * \return the number of bytes needed to represent the array in UTF-8
 */
extern size_t ipod_string_utf16_to_utf8_length(const char *src, size_t numChars);

/** \brief Convert an array of UTF-16LE characters to UTF-8
 *
 * \param src pointer to the array of UTF-16LE characters
 * \param numChars the number of characters in the UTF-16BE array
 * \param dst pointer to the buffer to stored the converted characters
 * \param maxLen the maximum number of bytes to store in the destination buffer
 * \return the number of bytes stored in the destination buffer
 */
extern size_t ipod_string_utf16_to_utf8(const char *src, size_t numChars, char *dst, size_t maxLen);

/** \brief Calculate the number of UTF-16LE characters in a null terminated UTF-8 string
 *
 * \param s a pointer to a null-terminated UTF-8 string
 * \return the number of UTF-16LE characters needed to store the string
 */
extern size_t ipod_string_utf8_to_utf16_length(const char *s);

/** \brief Convert a string of UTF-8 characters into an array of UTF-16LE characters
 *
 * \param src pointer to string or UTF-8 characters
 * \param dst pointer to buffer in which to store the UTF-16LE characters
 * \param maxLen the maximum number of UTF-16LE characters to store
 * \return the number of UTF-16LE characters converted
 */
extern size_t ipod_string_utf8_to_utf16(const char *src, char *dst, size_t maxLen); // maxlen== number of characters

/** \brief Convert an array of UTF-16LE characters to a UTF-8 string allocated on the heap
 *
 * \param src pointer to an array of UTF-16LE characters
 * \param numChars the number of characters in the UTF-16LE array
 * \return a null-terminated string containing the UTF-8 characters
 */
extern char *ipod_string_utf8_from_utf16(const char *src,size_t numChars);

/** \brief Convert a UTF-8 encoded string to an array of UTF-16LE characters allocated on the heap
 *
 * \param src the null terminated string of UTF-8 characters
 * \param numChars a pointer to location to store the number of characters in the array of UTF-16LE characters
 * \return a pointer to the array of UTF-16LE characters on the heap
 */
extern char *ipod_string_utf16_from_utf8(const char *src,size_t *numChars);

/** \brief Convert an ISO-8859-1 encoded string to an array of UTF-16LE characters allocated on the heap
 *
 * \param src the null terminated string of ISO-8859-1 characters
 * \param numChars a pointer to location to store the number of characters in the array of UTF-16LE characters
 * \return a pointer to the array of UTF-16LE characters on the heap
 */
extern char *ipod_string_utf16_from_iso8859(const char *src,size_t *numChars);

/** \brief Convert an array of UTF-16LE characters to an ISO-8859-1 string allocated on the heap
 *
 * \param src pointer to an array of UTF-16LE characters
 * \param numChars the number of characters in the UTF-16LE array
 * \return a null-terminated string containing the ISO-8859-1 characters
 */
extern char *ipod_string_iso8859_from_utf16(const char *src,size_t numChars);

/** \brief Convert a string of ISO-8859-1 characters to UTF-8
 *
 * \param src a string of UTF-8 characters
 * \return a string of ISO-8859-1 characters allocated on the heap
 */
extern char *ipod_string_utf8_from_iso8859(const char *src);

/** \brief Convert a string of UTF-8 characters to ISO-8859-1
 *
 * \param src a string of UTF-8 characters
 * \return a string of ISO-8859-1 characters allocated on the heap
 */
extern char *ipod_string_iso8859_from_utf8(const char *src);

/** \brief Compare two arrays of UTF-16LE characters
 *
 * \param a a pointer to an array of UTF-16LE characters
 * \param numCharsA the number of characters in 'a'
 * \param b a pointer to an array of UTF-16LE characters
 * \param numCharsB the number of characters in 'b'
 * \return -1 if a &lt; b, 0 if a==b, 1 if a &gt; b
 */
extern int ipod_string_compare_utf16(const char *a, size_t numCharsA, const char *b, size_t numCharsB);

/** \brief Print out some internal statistics
 */
extern void ipod_string_report(void);

#ifdef __cplusplus
};
#endif

#endif
