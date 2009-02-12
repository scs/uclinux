/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvmutils_toolshop_h
#define _mvmutils_toolshop_h

#include <sys/types.h>

#define TOSH_FILE_IMAGE  0x1
#define TOSH_FILE_SO     0x2
#define TOSH_SYM_TEXT    0x1
#define TOSH_SYM_DATA    0x2
#define TOSH_SYM_UNDEF   0x4

struct tosh_symbol {

	const char *name;
	unsigned long value;
	int type;
};

typedef struct tosh_syminfo {

	int filetype;
	struct tosh_symbol *symtab;
	unsigned symcnt;
	char *strtab;
	void *rawsyms;
	char *filename;
	int refcnt;
	struct tosh_syminfo *link;

} tosh_syminfo_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int tosh_spawn(const char *path,
	       char *const argv[]);

int tosh_spawnw(const char *path,
		char *const argv[]);

char *tosh_findpath(const char *argv0);

char *tosh_getselfpath(const char *argv0);

const char *tosh_getposixpath(const char *path);

const char *tosh_getcanonpath(const char *path);

tosh_syminfo_t *tosh_slurpsyms(const char *efile);

void tosh_freesyms(tosh_syminfo_t *syminfo);

const char *tosh_getrawsym(const char *name);

const char *tosh_getcanonsym(const char *name);

void *tosh_addrincore(struct tosh_symbol *symbol);

struct tosh_symbol *tosh_searchsymtab(tosh_syminfo_t *syminfo,
				      const char *name,
				      int type);

struct tosh_symbol *tosh_searchsymtab2(tosh_syminfo_t *syminfo,
				       const void *object,
				       int type);
char *tosh_mktemp(const char *tmpdir,
		  const char *prefix);

const char *tosh_tempdir(void);

u_long tosh_getfileid(const char *path);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* !_mvmutils_toolshop_h */
