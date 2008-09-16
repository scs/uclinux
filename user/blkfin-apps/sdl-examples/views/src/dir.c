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

direct *add_name(direct *dir, char *name)
{
	if(dir == NULL)
	{	
		dir = (struct _directory *) calloc(1, sizeof(struct _directory));
		dir->name = strdup(name);
		dir->next = NULL;
	} else {
		dir->next = add_name(dir->next, name);
	}
	return dir;
}

void print_names(direct *dir)
{
	if(dir != NULL)
	{
		printf("%s\n", dir->name);
		print_names(dir->next);
	}
}

char *search(direct *dir, const char *name)
{
	while(dir)
	{
		if(!strcmp(dir->name, name))
		{
			return dir->name;
		}
		dir = dir->next;
	}
	return NULL;
}

direct *read_dir(char *dirname)
{
	DIR *cdir;
	struct dirent *dir;

	dir = (struct dirent *) calloc(1, sizeof(struct dirent));
	directory = (struct _directory *) calloc(1, sizeof(struct _directory));
	directory = NULL;
	
	if(strlen(dirname) == 0)
	{
		snprintf(dirname, strlen(get_current_dir_name())+2, "%s/", get_current_dir_name());
	}
	
	cdir = opendir(dirname);
	if(cdir == NULL)
	{
		geterror("Can't open directory (%s)", dirname);
		die();
	}

	while(cdir != NULL)
	{
		dir = readdir(cdir);
		if(dir != NULL)
		{
			directory = add_name(directory, dir->d_name);

		} else {
			break;
		}
	}
	closedir(cdir);
	return directory;
}

char *getdir(char *filename)
{
	char *dir;

	dir = char_alloc();
	dir = substring(filename, 0, strlen(filename)-strlen(basename(filename)));
	return dir;
}
