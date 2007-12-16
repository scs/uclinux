/* getsubopt.c --- Parse comma separate list into words, DIGEST-MD5 style.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 * Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
 * From the GNU C Library, under GNU LGPL version 2.1.
 * Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.
 * Modified for Libgsasl by Simon Josefsson <simon@josefsson.org>
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

/* Get prototypes. */
#include "parser.h"

/* Get memchr and memcmp. */
#include <string.h>

/* Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.

   This function is NOT identical to standard getsubopt! */
int
digest_md5_getsubopt (char **optionp,
		      const char *const *tokens, char **valuep)
{
  char *endp, *vstart;
  int cnt;
  int inside_quote = 0;

  if (**optionp == '\0')
    return -1;

  /* Find end of next token.  */
  endp = *optionp;
  while (*endp != '\0' && (inside_quote || (!inside_quote && *endp != ',')))
    {
      if (*endp == '"')
	inside_quote = !inside_quote;
      endp++;
    }

  /* Find start of value.  */
  vstart = memchr (*optionp, '=', endp - *optionp);
  if (vstart == NULL)
    vstart = endp;

  /* Try to match the characters between *OPTIONP and VSTART against
     one of the TOKENS.  */
  for (cnt = 0; tokens[cnt] != NULL; ++cnt)
    if (memcmp (*optionp, tokens[cnt], vstart - *optionp) == 0
	&& tokens[cnt][vstart - *optionp] == '\0')
      {
	/* We found the current option in TOKENS.  */
	*valuep = vstart != endp ? vstart + 1 : NULL;

	while (*valuep && (**valuep == ' ' ||
			   **valuep == '\t' ||
			   **valuep == '\r' ||
			   **valuep == '\n' || **valuep == '"'))
	  (*valuep)++;

	if (*endp != '\0')
	  {
	    *endp = '\0';
	    *optionp = endp + 1;
	  }
	else
	  *optionp = endp;
	endp--;
	while (*endp == ' ' ||
	       *endp == '\t' ||
	       *endp == '\r' || *endp == '\n' || *endp == '"')
	  *endp-- = '\0';
	while (**optionp == ' ' ||
	       **optionp == '\t' || **optionp == '\r' || **optionp == '\n')
	  (*optionp)++;

	return cnt;
      }

  /* The current suboption does not match any option.  */
  *valuep = *optionp;

  if (*endp != '\0')
    *endp++ = '\0';
  *optionp = endp;
  while (**optionp == ' ' ||
	 **optionp == '\t' || **optionp == '\r' || **optionp == '\n')
    (*optionp)++;

  return -1;
}
