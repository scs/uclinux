/*
 * Copyright (C) 1996 Charles Blake
 * Copyright (C) 1998 Michael K. Johnson
 * kernel address -> symbol with next lower address.  Charles Blake, 1996.
 * Written to obviate the need for psdatabase initialization based upon kernel
 * binary formats, etc.
 *
 * The basic algorithm is an approximate (intervals split vaguely 50-50) binary
 * search taking advantage of the fact the System.map is already sorted in
 * ascending order by the kernel makefile.  It needs to assume an average symbol
 * record length to avoid scanning the entire symbol table, but in practice the
 * search time does not seem to be especially sensitive to this choice.
 *
 * The search could be an exact binary search if the lines of System.map were
 * padded with blanks to the right.  awk '{printf "%8s%2s %-21.21s\n",$1,$2,$3}'
 * would do the trick for this but either makes the file large or truncates
 * symbols.  The approximate method seems to be plenty fast enough, costing
 * only about as much as one extra fstat() or so per process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include "proc/psdata.h"
#include "proc/procps.h"
#include "proc/version.h"

#define MAX_ADDR_SZ 32
static char *sysmap, *sysmap_last, sysmap_fmt[10];
static int   sysmap_len, sysmap_mean = 32, sysmap_addrsz;

static int three_column = 0;

/*
 * '?' is a symbol type
 * '.' is part of a name (versioning?)
 * "\t[]" are for the module name in /proc/ksyms
 */
#define LEGAL_SYSMAP_CHARS "0123456789_ ?.\n\t[]" \
                     "abcdefghijklmnopqrstuvwxyz" \
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

/*******************************/

/* scan backward in a string no further than address beg looking for c */
static char *strchrrev(char *a, char *beg, char c) {
    if (a)
	while (--a > beg && *a != c) ;
    return a;
}

/* return ptr to the beg of approximately the i-th record */
static char *addr_str(int i) {
    char *guess = sysmap + sysmap_mean * i;
    if (!i) return sysmap;
    if (guess - sysmap > sysmap_len - 2) guess = sysmap + sysmap_len - 2;
    for ( ; *guess != '\n' && guess > sysmap; guess--)
	;
    return guess + 1;

}

/* return ptr to symbol string (\n terminated) given beg of record ptr */
static char *sym_put(char *buf, int len, char *addrptr) {
    char *s;
    while (*addrptr++ != ' ')   ;
    if(three_column) while (*addrptr++ != ' ')   ;
    strncpy(buf, addrptr, len);
    for (s = buf; s < buf + len; s++)
	if (*s == '\n')
	    *s = '\0';
    buf[len - 1] = '\0';
    return buf;
}

/****************************************/

/* Try to open and mmap a single symbol table file and initialize globals */
static int sysmap_mmap(const char *path, void (*message)(const char *, ...)) {
    int fd;
    struct stat sbuf;
    char *p;
    if (sysmap)		/* do nothing if already mapped */
	return 1;
    if ((fd = open(path, O_RDONLY)) < 0
	|| fstat(fd, &sbuf) < 0
	|| (sysmap = mmap(0, sbuf.st_size + 1,
			  PROT_READ, MAP_SHARED,
			  fd, 0)) == (caddr_t) -1)
    {
	close(fd);
	sysmap = NULL;
	return 0;
    }
    close(fd);
    sysmap_len = sbuf.st_size;
    sysmap_last = strchrrev(sysmap + sysmap_len - 2, sysmap, '\n') + 1;

    /* Now sanity check the System.map file */
    for (p = sysmap; *p != ' '
	     && ((*p >= '0' && *p <= '9') ||
		 (*p >= 'a' && *p <= 'f'))
	     && p < sysmap + MAX_ADDR_SZ;
	 p++) /* no-op */ ;
    three_column = (*(p+2) == ' ');
    sysmap_addrsz = p - sysmap;
    snprintf(sysmap_fmt, sizeof sysmap_fmt, "%%0%dlx", sysmap_addrsz);
    if( (*p != ' ') || (strspn(sysmap,LEGAL_SYSMAP_CHARS)!=strlen(sysmap)) ){
	message("Warning: %s not parseable as a System.map\n", path);
	munmap(sysmap, sysmap_len);
	sysmap = NULL;
	return 0;
    }
    /*
     * We should make sure this file matches the kernel. We can't get a build
     * number, but we do have a version code. The map file will contain
     * something like "001b407c D Version_131103\n".
     */
    do {
        char Version[32];
        sprintf(Version, " Version_%d\n", linux_version_code);
        if(strstr(sysmap, Version)) break;
	message("Warning: %s has an incorrect kernel version.\n", path);
	munmap(sysmap, sysmap_len);
	sysmap = NULL;
	return 0;
    } while(0);
    return 1;
}

/*******************************/

/* kernel address -> name resolver.
   returned value is only good until the next call to the function.
 */
static char *sysmap_symbol(unsigned long address) {
    static char rval[128], *pc, addr[MAX_ADDR_SZ];
    int i, p, n = sysmap_len / (double)sysmap_mean;

    sprintf(addr, sysmap_fmt, address);
    p = 0; pc = sysmap;
    while (n) {
	i = p + (n >> 1);
	if (strncmp(addr, pc = addr_str(i), sysmap_addrsz) > 0)
	    p = i + 1;
	n >>= 1;
    }
    if (pc == sysmap_last)		/* scan forward but not past end */
	return sym_put(rval, sizeof rval, pc);
    while (strncmp(addr, pc, sysmap_addrsz) > 0)
	pc = strchr(pc, '\n') + 1;
    if (pc == sysmap)			/* scan backward but not past beg */
	return sym_put(rval, sizeof rval, pc);
    while (strncmp(addr, pc, sysmap_addrsz) < 0)
	pc = strchrrev(pc - 1, sysmap, '\n') + 1;
    return sym_put(rval, sizeof rval, pc);
}

/*********************************/

#if 0
/* extern struct nlist *namelist; */
struct tbl_s vars, fncs;
struct psdb_hdr db_hdr;
int psdb = -1;
#endif

static void default_message(const char *format, ...) {
    va_list arg;

    va_start (arg, format);
    vfprintf (stderr, format, arg);
    va_end (arg);
}

int open_psdb_message(const char *override, void (*message)(const char *, ...)) {
    static char *sysmap_paths[] = {
	"/boot/System.map-%s",
	"/boot/System.map",
	"/lib/modules/%s/System.map",
	"/usr/src/linux/System.map",
	"/System.map",
	NULL
    };
#if 0
    static char *psdb_paths[] = {
	"/etc/psdatabase",
	"/boot/psdatabase-%s",
	"/boot/psdatabase",
	"/lib/modules/%s/psdatabase",
	NULL
    };
#endif
    char **fmt, *env, path[64];
    struct utsname uts;
    if(getuid()!=geteuid()){
      printf("The /proc library is not secure for setuid operation.");
      exit(1);
    }
    if(getgid()!=getegid()){
      printf("The /proc library is not secure for setgid operation.");
      exit(1);
    }
    uname(&uts);
    if(override){           /* ought to search some path */
      if(sysmap_mmap(override, message)) return 0;
      return -1;           /* ought to return "Namelist not found." */
      /* failure is better than ignoring the user & using bad data */
    }
    /* Arrrgh, the old man page and code did not match. */
    if ((env = getenv("PS_SYSMAP"))     && sysmap_mmap(env, message))	return 0;
    if ((env = getenv("PS_SYSTEM_MAP")) && sysmap_mmap(env, message))	return 0;
    for (fmt = sysmap_paths; *fmt; fmt++) {
	snprintf(path, sizeof path, *fmt, uts.release);
	if (sysmap_mmap(path, message)) return 0;
    }
#if 0
    for (fmt = psdb_paths; *fmt; fmt++) {
	snprintf(path, sizeof path, *fmt, uts.release);
	if ((psdb = open(path, O_RDONLY)) != -1 &&
	    read(psdb, (char*)&db_hdr, sizeof db_hdr) == sizeof db_hdr &&
	    strncmp(db_hdr.magic, procps_version, sizeof(db_hdr.magic)) == 0)
	    /* && version_cmp(kernel,psdatabase) */
	    return 0;
	if (psdb != -1)
	    message("psdatabase has magic no. %*s instead of %*s\n",
		    (int) sizeof db_hdr.magic, db_hdr.magic,
		    (int) sizeof db_hdr.magic, procps_version);
	close(psdb);
    }
#endif
    return -1;
}

int open_psdb(const char *override) {
    return open_psdb_message(override, default_message);
}

/***********************************/

void close_psdb(void) {
    if (sysmap)
	munmap(sysmap, sysmap_len);
#if 0
    else
        if (psdb != -1) close(psdb);
    psdb = -1;
#endif
    sysmap = NULL;
}

/*************************************/

#if 0
int read_tbl(struct dbtbl_s *dbtbl, struct tbl_s *tbl) {
    lseek(psdb, dbtbl->off, SEEK_SET);
    tbl->tbl = (struct sym_s *) xmalloc(dbtbl->size);
    if (read(psdb, (char *) tbl->tbl, dbtbl->size) != dbtbl->size) {
	perror(PSDATABASE);
	exit(1);
    }
    tbl->nsym = dbtbl->nsym;
    tbl->strings = (char *) (tbl->tbl + tbl->nsym);
    return 0;
}
#endif

/*************************************/

/* Can't cache this, since modules may be loaded while top runs. */
char* find_module_sym(unsigned long address) {
   FILE *fd;
   static char buf[512];
   unsigned long adr, best_adr = 0;
   char mod[32], nm[32]; char c;
   *mod = 1;
   *buf = '\0'; /* sprintf (buf, "%08x", address); */
   fd = fopen ("/proc/ksyms", "r");
   if (!fd) return ("(no proc)");   /* FIXME return the number as text */
   while (!feof (fd) && !(*mod == '\0')) {
      fscanf (fd, "%lx %s\n", &adr, nm);
      if ((c = fgetc (fd)) != '[') *mod = '\0'; 
      else { fscanf (fd, "%s", mod); };
      if (abs(address - adr) < abs(address - best_adr) /* && address >= adr */
         && abs(address - adr) < 0xa00) {  /* FIXME is 0xa00 a good test? */
        best_adr = adr; *buf = '[';
/* FIXME Why the 0x100 limitation? */
        if (address - adr > 0x100) strcpy (buf+1, mod); /* module name */
        else strcpy(buf, nm); /* name of function/variable */
      };
   };
   fclose (fd);
   return buf;
};

/*************************************/

char * find_func(unsigned long address)	{
#if 0
    int n;
    struct sym_s *p;
    char *s;
#endif
    if (sysmap)
	return sysmap_symbol(address);
#if 0
    if (psdb == -1)
	return "(no psdb)";
    if (fncs.tbl == NULL)
	read_tbl(&db_hdr.fncs, &fncs);
    p = fncs.tbl;
    n = fncs.nsym;
    if (address > p[n-1].addr) return find_module_sym(address);
    while (n) {
	int i = n / 2;
	if (p[i].addr < address) {
	    p = &p[i+1];
	    if (p->addr > address) {
		--p;
		break;
	    }
	    --n;
	}
	n /= 2;
    }
    s = p->name + fncs.strings;
    return *s=='_' ? s+1 : s;
#else
    return "ERROR";
#endif
}

/***************************************/

char * wchan(unsigned long address) {
    static char zero = 0;
    char *p;

    if (address) {
	p = find_func(address);
	if (strncmp(p, "sys_", 4) == 0)
	    p += 4;
	while (*p == '_' && *p)
	    ++p;
    } else /* 0 address means not in kernel space */
	p = &zero;
    return p;
}

#ifdef SYSMAP_TEST
int main(int ac, char** av) {
    if (ac < 3) {printf("%s System.map lines hexaddr ...\n",av[0]); return 1;}
    if (!sysmap_mmap(av[1], default_message)) return 1;
    if ((sysmap_mean = atoi(av[2])) <= 0) return 1;
    for (av += 3; *av; av++)
	printf("%s %s\n", *av, sysmap_symbol(strtoul(*av, NULL, 16)));
    return 0;
}
#endif
