/* md5pwd.c --- Find passwords in UoW imapd MD5 type password files.
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
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"

/**
 * gsasl_simple_getpass:
 * @filename: filename of file containing passwords.
 * @username: username string.
 * @key: newly allocated output character array.
 *
 * Retrieve password for user from specified file.  The buffer @key
 * contain the password if this function is successful.  The caller is
 * responsible for deallocating it.
 *
 * The file should be on the UoW "MD5 Based Authentication" format,
 * which means it is in text format with comments denoted by # first
 * on the line, with user entries looking as "usernameTABpassword".
 * This function removes CR and LF at the end of lines before
 * processing.  TAB, CR, and LF denote ASCII values 9, 13, and 10,
 * respectively.
 *
 * Return value: Return %GSASL_OK if output buffer contains the
 *   password, %GSASL_AUTHENTICATION_ERROR if the user could not be
 *   found, or other error code.
 **/
int
gsasl_simple_getpass (const char *filename, const char *username, char **key)
{
  size_t userlen = strlen (username);
  char *line = NULL;
  size_t n = 0;
  FILE *fh;

  fh = fopen (filename, "r");
  if (fh)
    {
      while (!feof (fh))
	{
	  if (getline (&line, &n, fh) < 0)
	    break;

	  if (line[0] == '#')
	    continue;

	  if (line[strlen (line) - 1] == '\r')
	    line[strlen (line) - 1] = '\0';
	  if (line[strlen (line) - 1] == '\n')
	    line[strlen (line) - 1] = '\0';

	  if (strncmp (line, username, userlen) == 0 && line[userlen] == '\t')
	    {
	      *key = malloc (strlen (line) - userlen);
	      if (!*key)
		{
		  free (line);
		  return GSASL_MALLOC_ERROR;
		}

	      strcpy (*key, line + userlen + 1);

	      free (line);

	      fclose (fh);

	      return GSASL_OK;
	    }
	}

      fclose (fh);
    }

  if (line)
    free (line);

  return GSASL_AUTHENTICATION_ERROR;
}
