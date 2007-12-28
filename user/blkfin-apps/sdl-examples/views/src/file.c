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

char *nextfile(char *filename)
{
	char *dirname;
	char *newfile;
	char *name;
	direct *dir;
	
	dirname = char_alloc();
	newfile = char_alloc();
	name = char_alloc();
	dir = (direct *) calloc(1, sizeof(direct));
	
	dirname = getdir(filename);
	dir = read_dir(dirname);
	
	while(dir)
	{
		if(!strcmp(dir->name, basename(filename)))
                {
			break;
		}
		dir = dir->next;
		name = dir->name;
	}
	dir = dir->next;
	if(dir == NULL)
	{
		dir = read_dir(dirname);	
		while(dir)
		{
			if(!strcmp(dir->name, ".."))
			{
				break;
			}
			dir = dir->next;
		}
		dir = dir->next;
	}
	snprintf(newfile, 1024, "%s%s", dirname, dir->name);
	return newfile;
}

char *lastfile(char *filename)
{
	char *dirname;
	char *newfile;
	char *name;
	direct *dir;
	
	dirname = char_alloc();
	newfile = char_alloc();
	name = char_alloc();
	dir = (direct *) calloc(1, sizeof(direct));
	
	dirname = getdir(filename);
	dir = read_dir(dirname);
	while(dir)
	{
		if(!strcmp(dir->name, basename(filename)))
                {
			break;
		}
		name = dir->name;
		dir = dir->next;
	}
	snprintf(newfile, 1024, "%s%s", dirname, name);

	return newfile;
}
