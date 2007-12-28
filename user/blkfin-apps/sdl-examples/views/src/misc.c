/* views - view images exclusive with SDM
* Copyright (C) cappa <cappa@referee.at>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "include/views.h"

char *char_alloc(void)
{
	return (char *) calloc(1, 1024);
}

void die(void)
{
        exit(EXIT_FAILURE);
}

void death(void)
{
	exit(EXIT_SUCCESS);
}

void is_file(const char *filename)
{

	FILE *fp;
	
	if((fp = fopen(filename, "r")) == NULL)
	{
		geterror("Can't open %s for read", filename);
		die();
	}
}

void geterror(const char *format, ...)
{
	char *error;
	va_list err;

        error = char_alloc();
	va_start(err, format);
	vsprintf(error, format, err);
	va_end(err);
	perror(error);
}

char *substring(char *name, int from, int to)
{
        char *ret;
        ret = char_alloc();

	name += from;
        strncpy(ret, name, to);
        return ret;
}

/*
char *basename(char *filename)
{
	char *name;
	for(name = filename;; ++name)
	{
		if(!*name)
		{
			if( name > filename)
			{
				putchar('/');
			}
			putchar('\n');
			exit(0);
		}
		if(*name != '/')
		{
			break;
		}
	}
	for(;*name; ++name)
	{
		continue;
	}
	
	while(*--name == '/')
	{
		continue;
	}
	*++name = '\0';

	while(--name >= filename)
	{
		if(*name == '/')
		{
			break;
		}
	}
	++name;
	return name;
}
*/
