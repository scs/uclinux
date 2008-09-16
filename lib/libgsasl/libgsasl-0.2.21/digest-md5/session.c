/* session.c --- Data integrity/privacy protection of DIGEST-MD5.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "session.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strdup, strlen. */
#include <string.h>

/* Get gc_hmac_md5. */
#include <gc.h>

#define MD5LEN 16
#define SASL_INTEGRITY_PREFIX_LENGTH 4
#define MAC_DATA_LEN 4
#define MAC_HMAC_LEN 10
#define MAC_MSG_TYPE "\x00\x01"
#define MAC_MSG_TYPE_LEN 2
#define MAC_SEQNUM_LEN 4

int
digest_md5_encode (const char *input, size_t input_len,
		   char **output, size_t * output_len,
		   digest_md5_qop qop,
		   unsigned long sendseqnum, char key[DIGEST_MD5_LENGTH])
{
  int res;

  if (qop & DIGEST_MD5_QOP_AUTH_CONF)
    {
      return -1;
    }
  else if (qop & DIGEST_MD5_QOP_AUTH_INT)
    {
      char *seqnumin;
      char hash[GC_MD5_DIGEST_SIZE];
      size_t len;

      seqnumin = malloc (MAC_SEQNUM_LEN + input_len);
      if (seqnumin == NULL)
	return -1;

      seqnumin[0] = (sendseqnum >> 24) & 0xFF;
      seqnumin[1] = (sendseqnum >> 16) & 0xFF;
      seqnumin[2] = (sendseqnum >> 8) & 0xFF;
      seqnumin[3] = sendseqnum & 0xFF;
      memcpy (seqnumin + MAC_SEQNUM_LEN, input, input_len);

      res = gc_hmac_md5 (key, MD5LEN,
			 seqnumin, MAC_SEQNUM_LEN + input_len, hash);
      free (seqnumin);
      if (res)
	return -1;

      *output_len = MAC_DATA_LEN + input_len + MAC_HMAC_LEN +
	MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;
      *output = malloc (*output_len);
      if (!*output)
	return -1;

      len = MAC_DATA_LEN;
      memcpy (*output + len, input, input_len);
      len += input_len;
      memcpy (*output + len, hash, MAC_HMAC_LEN);
      len += MAC_HMAC_LEN;
      memcpy (*output + len, MAC_MSG_TYPE, MAC_MSG_TYPE_LEN);
      len += MAC_MSG_TYPE_LEN;
      (*output + len)[0] = (sendseqnum >> 24) & 0xFF;
      (*output + len)[1] = (sendseqnum >> 16) & 0xFF;
      (*output + len)[2] = (sendseqnum >> 8) & 0xFF;
      (*output + len)[3] = sendseqnum & 0xFF;
      len += MAC_SEQNUM_LEN;
      (*output)[0] = ((len - MAC_DATA_LEN) >> 24) & 0xFF;
      (*output)[1] = ((len - MAC_DATA_LEN) >> 16) & 0xFF;
      (*output)[2] = ((len - MAC_DATA_LEN) >> 8) & 0xFF;
      (*output)[3] = (len - MAC_DATA_LEN) & 0xFF;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return -1;
      memcpy (*output, input, input_len);
    }

  return 0;
}

#define C2I(buf) ((buf[0] & 0xFF) |		\
		  ((buf[1] & 0xFF) << 8) |	\
		  ((buf[2] & 0xFF) << 16) |	\
		  ((buf[3] & 0xFF) << 24))

int
digest_md5_decode (const char *input, size_t input_len,
		   char **output, size_t * output_len,
		   digest_md5_qop qop,
		   unsigned long readseqnum, char key[DIGEST_MD5_LENGTH])
{
  if (qop & DIGEST_MD5_QOP_AUTH_CONF)
    {
      return -1;
    }
  else if (qop & DIGEST_MD5_QOP_AUTH_INT)
    {
      char *seqnumin;
      char hash[GC_MD5_DIGEST_SIZE];
      unsigned long len;
      char tmpbuf[SASL_INTEGRITY_PREFIX_LENGTH];
      int res;

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH)
	return -2;

      len = C2I (input);

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH + len)
	return -2;

      len -= MAC_HMAC_LEN + MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;

      seqnumin = malloc (SASL_INTEGRITY_PREFIX_LENGTH + len);
      if (seqnumin == NULL)
	return -1;

      tmpbuf[0] = (readseqnum >> 24) & 0xFF;
      tmpbuf[1] = (readseqnum >> 16) & 0xFF;
      tmpbuf[2] = (readseqnum >> 8) & 0xFF;
      tmpbuf[3] = readseqnum & 0xFF;

      memcpy (seqnumin, tmpbuf, SASL_INTEGRITY_PREFIX_LENGTH);
      memcpy (seqnumin + SASL_INTEGRITY_PREFIX_LENGTH,
	      input + MAC_DATA_LEN, len);

      res = gc_hmac_md5 (key, MD5LEN, seqnumin, MAC_SEQNUM_LEN + len, hash);
      free (seqnumin);
      if (res)
	return -1;

      if (memcmp
	  (hash,
	   input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN -
	   MAC_HMAC_LEN, MAC_HMAC_LEN) == 0
	  && memcmp (MAC_MSG_TYPE,
		     input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN,
		     MAC_MSG_TYPE_LEN) == 0
	  && memcmp (tmpbuf, input + input_len - MAC_SEQNUM_LEN,
		     MAC_SEQNUM_LEN) == 0)
	{
	  *output_len = len;
	  *output = malloc (*output_len);
	  if (!*output)
	    return -1;
	  memcpy (*output, input + MAC_DATA_LEN, len);
	}
      else
	return -1;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return -1;
      memcpy (*output, input, input_len);
    }

  return 0;
}
