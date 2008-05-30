/*
 * psdata.h
 *
 * Jeffrey A. Uphoff <juphoff@nrao.edu>, 1995, 1996.
 * Michael K. Johnson.
 * Bruno Lankester.
 * (And others I'm sure...)
 *
 */

/*
 * Capabilities are for reading system images and producing maps for
 * WCHAN output.
 *
 * AOUT_CAPABLE and ELF_CAPABLE may have 32-bit word size limitations
 * and have only been tested by the maintainer on Intel systems.  They
 * are retained in the source tree in case they are useful; they are
 * intended to be generally deprecated.
 *
 * BFD_CAPABLE should work on any system with BFD.
 *
 * Set the capabilities in the top-level Makefile.
 */

#if defined(ELF_CAPABLE)
# define ELF_OBJECT 1
# define ELF_FUNC 2
#endif

#include <sys/types.h>
#include <linux/utsname.h>

#define        PSDATABASE      "/etc/psdatabase"

struct dbtbl_s {
  off_t off;			/* offset in psdatabase */
  int nsym;			/* # symbols */
  int size;			/* size of array + strings */
};

/*
 * header of psdatabase
 */
struct psdb_hdr {
  /* Current procps package version goes here.  kmemps doesn't like this. */
  char magic[32];
  /* 
   * These are not functional--they only reside in the database for
   * informational purposes (i.e. if you want to look at the raw
   * database and see what kernel it's for).
   */
  char uts_release[__NEW_UTS_LEN];
  char uts_version[__NEW_UTS_LEN];
  /* 
   * Again, this is not functional, it's just there for information: it
   * shows the path to the uncompressed kernel image that was used to
   * generate this database.
   */
  char sys_path[128];
  /* List of all functions. */
  struct dbtbl_s fncs;
  /* 
   * This is currently only used to look up system_utsname while
   * psupdate is building the database--it really should be phased out!
   */
  /* List of all bss and data symbols. */
  struct dbtbl_s vars;
  /* 
   * The list of tty names that kmemps likes/uses in no longer present
   * in the procps psdatabase--it was never being built by procps'
   * psupdate anyway, so I removed the entry from the database header.
   */
};

struct sym_s {
  unsigned long addr;		/* core address in kernel */
  int name;			/* offset from strings ptr */
};

struct tbl_s {
  struct sym_s *tbl;
  int nsym;
  char *strings;		/* ptr to start of strings */
};

extern struct psdb_hdr db_hdr;
extern struct tbl_s fncs, vars;

int read_tbl (struct dbtbl_s *, struct tbl_s *);
void *xmalloc (unsigned int);
void *xrealloc (void *, unsigned int);

#define MLSEEK(FD, WHERE, WHENCE, ERROR)\
if (lseek ((FD), (WHERE), (WHENCE)) == -1) {\
  perror ((ERROR));\
  exit (errno);\
}

#define MREAD(FD, WHAT, SIZE, ERROR)\
if (read ((FD), (WHAT), (SIZE)) != (SIZE)) {\
  perror ((ERROR));\
  exit (errno);\
}
