/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison and Michel Arboi
 * give permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 */
#include <includes.h>

#ifndef HAVE_STRNDUP_ALREADY
char * strndup(char * str, int length)
{
 char * ret = emalloc(length + 1);
 bcopy(str, ret, length);
 return ret; 
}
#endif


int str_match(const char* string, const char* pattern, int icase)
{
  while (*pattern != '\0')
    {
      if (*pattern == '?')
	{
	  if (*string == '\0')
	    return 0;
	}
      else if (*pattern == '*')
	{
	  const char	*p = string;
	  do
	    if (str_match(p, pattern+1, icase))
	      return 1;
	  while (*p ++ != '\0');
	  return 0;
	}
      else if (icase && tolower(*pattern) != tolower(*string) ||
	       ! icase && *pattern != *string)
	return 0;
      pattern ++; string ++;
    }
  return *string == '\0';
}



#ifndef HAVE_MEMMEM
/*
 * Slow replacement for memmem()
 */
void * memmem(haystack, hl_len, needle, n_len)
 const void *  haystack;
 size_t hl_len;
 const void * needle;
 size_t n_len;
{
 char * hs = (char*)haystack;
 char * nd = (char*)needle;
 int i;

 for(i=0;i<=hl_len-n_len;i++)
 {
  if(hs[i] == nd[0])
  { 
   int flag = 1;
   int j;
   for(j = 1;j < n_len; j++)if(hs[i+j] != nd[j] ){ flag=0;break; }
   if(flag != 0)
   	return( hs + i );
  }
 }
 return(NULL);
}
#endif


