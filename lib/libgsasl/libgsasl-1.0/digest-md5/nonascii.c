/* server.c --- DIGEST-MD5 mechanism from RFC 2831, server side.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "nonascii.h"

#include <stdlib.h>
#include <string.h>

/* C89 compliant way to cast 'char' to 'unsigned char'. */
static inline unsigned char
to_uchar (char ch)
{
  return ch;
}

char *
latin1toutf8 (const char *str)
{
  char *p = malloc (2 * strlen (str) + 1);
  if (p)
    {
      size_t i, j = 0;
      for (i = 0; str[i]; i++)
	{
	  if (to_uchar (str[i]) < 0x80)
	    p[j++] = str[i];
	  else if (to_uchar (str[i]) < 0xC0)
	    {
	      p[j++] = (unsigned char) 0xC2;
	      p[j++] = str[i];
	    }
	  else
	    {
	      p[j++] = (unsigned char) 0xC3;
	      p[j++] = str[i] - 64;
	    }
	}
      p[j] = 0x00;
    }

  return p;
}

char *
utf8tolatin1ifpossible (const char *passwd)
{
  char *p;
  size_t i;

  for (i = 0; passwd[i]; i++)
    {
      if (to_uchar (passwd[i]) > 0x7F)
	{
	  if (to_uchar (passwd[i]) < 0xC0 || to_uchar (passwd[i]) > 0xC3)
	    return strdup (passwd);
	  i++;
	  if (to_uchar (passwd[i]) < 0x80 || to_uchar (passwd[i]) > 0xBF)
	    return strdup (passwd);
	}
    }

  p = malloc (strlen (passwd) + 1);
  if (p)
    {
      size_t j = 0;
      for (i = 0; passwd[i]; i++)
	{
	  if (to_uchar (passwd[i]) > 0x7F)
	    {
	      /* p[i+1] can't be zero here */
	      p[j++] =
		((to_uchar (passwd[i]) & 0x3) << 6)
		| (to_uchar (passwd[i + 1]) & 0x3F);
	      i++;
	    }
	  else
	    p[j++] = passwd[i];
	}
      p[j] = 0x00;
    }
  return p;
}
