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

#include <xeno_config.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_ELF_H
#include <elf.h>
#endif /* HAVE_ELF_H */
#ifdef HAVE_LIBELF_H
#include <libelf.h>
#endif /* HAVE_LIBELF_H */
#ifdef HAVE_LIBELF_LIBELF_H
#include <libelf/libelf.h>
#endif /* HAVE_LIBELF_LIBELF_H */
#include "vmutils/toolshop.h"

static tosh_syminfo_t *tosh_symtabs = NULL;

static int tosh_ldsymtab (int fd, Elf *elf, tosh_syminfo_t *syminfo)

{
    struct tosh_symbol *isym;
    Elf32_Sym *esym, *lesym;
    Elf_Scn *scn = NULL;
    int isymall = 128;
    Elf32_Shdr *shdr;
    Elf_Data *data;

    syminfo->symtab = (struct tosh_symbol *)malloc(sizeof(*isym) * isymall);
    syminfo->strtab = NULL; /* not used */
    /* Elf buffer must remain valid until tosh_freesyms()
       is called -- i.e. pointers to the ELF string table
       contents exist until symtab is disposed. */
    syminfo->rawsyms = elf;
    syminfo->symcnt = 0;

    while ((scn = elf_nextscn(elf,scn)) != NULL)
	{
	shdr = elf32_getshdr(scn);

	if (!shdr || shdr->sh_type != SHT_SYMTAB)
	    continue;

	/* canonicalize function and data symbols */

	data = NULL;

        while ((data = elf_getdata(scn,data)) != NULL)
	    {
	    if (data->d_type != ELF_T_SYM)
		continue;

	    esym = (Elf32_Sym *)data->d_buf;
	    lesym = (Elf32_Sym *)((char *)data->d_buf + data->d_size);

	    while (esym < lesym)
		{
		int type = ELF32_ST_TYPE(esym->st_info);

		if (type == STT_OBJECT || type == STT_FUNC)
		    {
		    if (++syminfo->symcnt > isymall)
			{
			isymall += 128;
			syminfo->symtab = realloc(syminfo->symtab,
						  sizeof(*isym) * isymall);
			}

		    /* where to put the current symbol, *after* the
		       potential reallocation */
		    isym = syminfo->symtab + syminfo->symcnt - 1;

		    isym->name = elf_strptr(elf,
					    (size_t)shdr->sh_link,
					    (size_t)esym->st_name);
		    isym->type = (type == STT_OBJECT ?
				  TOSH_SYM_DATA : TOSH_SYM_TEXT);
		    isym->value = esym->st_value;
		    }

		esym++;
		}
	    }
	}

    return 0;
}

tosh_syminfo_t *tosh_slurpsyms (const char *elfile)

{
    tosh_syminfo_t *syminfo;
    Elf32_Ehdr *ehdr;
    Elf_Kind kind;
    Elf *elf;
    int fd;

    /* search for a currently open symtab in the cache */

    for (syminfo = tosh_symtabs; syminfo; syminfo = syminfo->link)
	{
	if (!strcmp(elfile,syminfo->filename))
	    {
	    syminfo->refcnt++;
	    return syminfo;
	    }
	}

    /* not cached -- extract the symbol table from the file  */

    if (elf_version(EV_CURRENT) == EV_NONE)
	return NULL; /* oops! version level mismatches */

    fd = open(elfile,O_RDONLY);

    if (fd < 0)
	return NULL;

    elf = elf_begin(fd,ELF_C_READ,NULL);
    kind = elf_kind(elf);
    elf = elf_begin(fd,ELF_C_READ,elf);

    if ((kind != ELF_K_COFF && kind != ELF_K_ELF) || !elf)
	{
	/* can only process COFF and ELF image files */
	elf_end(elf);
	close(fd);
	return NULL;
	}

    ehdr = elf32_getehdr(elf);

    if (!ehdr ||
	(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
	{
	/* not a 32bit class and/or an image file */
	elf_end(elf);
	close(fd);
	return NULL;
	}

    syminfo = (tosh_syminfo_t *)malloc(sizeof(*syminfo));
    syminfo->filetype = (ehdr->e_type == ET_EXEC ?
			 TOSH_FILE_IMAGE : TOSH_FILE_SO);
    syminfo->filename = strdup(elfile);

    if (tosh_ldsymtab(fd,elf,syminfo) < 0)
	{
	close(fd);
	free(syminfo);
	return NULL;
	}

    close(fd);

    syminfo->refcnt = 1;
    syminfo->link = tosh_symtabs;
    tosh_symtabs = syminfo;

    return syminfo;
}

void tosh_freesyms (tosh_syminfo_t *syminfo)

{
    if (--syminfo->refcnt == 0)
	{
	tosh_syminfo_t **symptr;

	for (symptr = &tosh_symtabs; *symptr; symptr = &((*symptr)->link))
	    {
	    if (*symptr == syminfo)
		{
		*symptr = syminfo->link;
		elf_end((Elf *)syminfo->rawsyms);
		free(syminfo->symtab);
		free(syminfo->filename);
		free(syminfo);
		return;
		}
	    }
	}
}

const char *tosh_getrawsym (const char *name)

{ return name; }

const char *tosh_getcanonsym (const char *name)

{ return name; }

struct tosh_symbol *tosh_searchsymtab (tosh_syminfo_t *syminfo,
				       const char *name,
				       int type)
{
    int symno;

    for (symno = 0, name = tosh_getrawsym(name);
	 symno < syminfo->symcnt; symno++)
	{
	struct tosh_symbol *symbol = syminfo->symtab + symno;

	if (symbol->type == type &&
	    !strcmp(name,symbol->name))
	    return symbol;
	}

    return NULL;
}

struct tosh_symbol *tosh_searchsymtab2 (tosh_syminfo_t *syminfo,
					const void *object,
					int type)
{
    int symno;

    for (symno = 0; symno < syminfo->symcnt; symno++)
	{
	struct tosh_symbol *symbol = syminfo->symtab + symno;

	if (symbol->type == type &&
	    object == tosh_addrincore(symbol))
	    return symbol;
	}

    return NULL;
}

void *tosh_addrincore (struct tosh_symbol *symbol)

{ return (void *)symbol->value; }
