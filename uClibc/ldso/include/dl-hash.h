#ifndef _LD_HASH_H_
#define _LD_HASH_H_

#ifndef RTLD_NEXT
#define RTLD_NEXT	((void*)-1)
#endif

struct init_fini {
	struct elf_resolve **init_fini;
	unsigned long nlist; /* Number of entries in init_fini */
};

struct dyn_elf{
  struct elf_resolve * dyn;
  struct dyn_elf * next_handle;  /* Used by dlopen et al. */
  struct init_fini init_fini;
  struct dyn_elf * next;
  struct dyn_elf * prev;
};

/* Machines in which different sections may be relocated by different
   amounts should define this and LD_RELOC_ADDR.  If you change this,
   make sure you change struct link_map in include/link.h accordingly
   such that it matches a prefix of struct elf_resolve.  */
#ifndef DL_LOADADDR_TYPE
# define DL_LOADADDR_TYPE ElfW(Addr)
#endif

/* When DL_LOADADDR_TYPE is not a scalar value, or some different
   computation is needed to relocate an address, define this.  */
#ifndef DL_RELOC_ADDR
# define DL_RELOC_ADDR(ADDR, LOADADDR) \
  ((void*)((intptr_t)(ADDR) + (intptr_t)(LOADADDR)))
#endif

/* Use this macro to convert a pointer to a function's entry point to
   a pointer to function.  The pointer is assumed to have already been
   relocated.  LOADADDR is passed because it may contain additional
   information needed to compute the pointer to function.  */
#ifndef DL_ADDR_TO_FUNC_PTR
# define DL_ADDR_TO_FUNC_PTR(ADDR, LOADADDR) ((void(*)(void))(ADDR))
#endif

/* On some platforms, computing a pointer to function is more
   expensive than calling a function at a given address, so this
   alternative is provided.  The function signature must be given
   within parentheses, as in a type cast.  */
#ifndef DL_CALL_FUNC_AT_ADDR
# define DL_CALL_FUNC_AT_ADDR(ADDR, LOADADDR, SIGNATURE, ...) \
  ((*SIGNATURE DL_ADDR_TO_FUNC_PTR ((ADDR), (LOADADDR)))(__VA_ARGS__))
#endif

/* Define if any declarations/definitions of local variables are
   needed in a function that calls DT_INIT_LOADADDR or
   DL_INIT_LOADADDR_HDR.  Declarations must be properly terminated
   with a semicolon, and non-declaration statements are forbidden.  */
#ifndef DL_INIT_LOADADDR_EXTRA_DECLS
# define DL_INIT_LOADADDR_EXTRA_DECLS /* int i; */
#endif

/* Prepare a DL_LOADADDR_TYPE data structure for incremental
   initialization with DL_INIT_LOADADDR_HDR, given pointers to a base
   load address and to program headers.  */
#ifndef DL_INIT_LOADADDR
# define DL_INIT_LOADADDR(LOADADDR, BASEADDR, PHDR, PHDRCNT) \
  ((LOADADDR) = (BASEADDR))
#endif

/* Update LOADADDR with information about PHDR, just mapped to the
   given ADDR.  */
#ifndef DL_INIT_LOADADDR_HDR
# define DL_INIT_LOADADDR_HDR(LOADADDR, ADDR, PHDR) /* Do nothing.  */
#endif

/* Unmap all previously-mapped segments accumulated in LOADADDR.
   Generally used when an error occurs during loading.  */
#ifndef DL_LOADADDR_UNMAP
# define DL_LOADADDR_UNMAP(LOADADDR, LEN) \
  _dl_munmap((char *) (LOADADDR), (LEN))
#endif

/* Similar to DL_LOADADDR_UNMAP, but used for libraries that have been
   dlopen()ed successfully, when they're dlclose()d.  */
#ifndef DL_LIB_UNMAP
# define DL_LIB_UNMAP(LIB, LEN) (DL_LOADADDR_UNMAP ((LIB)->loadaddr, (LEN)))
#endif

/* Convert a DL_LOADADDR_TYPE to an identifying pointer.  Used mostly
   for debugging.  */
#ifndef DL_LOADADDR_BASE
# define DL_LOADADDR_BASE(LOADADDR) (LOADADDR)
#endif

/* Initialize a LOADADDR representing the loader itself.  It's only
   called from DL_BOOT, so additional arguments passed to it may be
   referenced.  */
#ifndef DL_INIT_LOADADDR_BOOT
# define DL_INIT_LOADADDR_BOOT(LOADADDR, BASEADDR) \
  ((LOADADDR) = (BASEADDR))
#endif

/* Initialize a LOADADDR representing the program.  It's called from
   DL_BOOT only.  */
#ifndef DL_INIT_LOADADDR_PROG
# define DL_INIT_LOADADDR_PROG(LOADADDR, BASEADDR) \
  ((LOADADDR) = (BASEADDR))
#endif

/* Test whether a given ADDR is more likely to be within the memory
   region mapped to TPNT (a struct elf_resolve *) than to TFROM.
   Everywhere that this is used, TFROM is initially NULL, and whenever
   a potential match is found, it's updated.  One might want to walk
   the chain of elf_resolve to locate the best match and return false
   whenever TFROM is non-NULL, or use an exact-matching algorithm
   using additional information encoded in DL_LOADADDR_TYPE to test
   for exact containment.  */
#ifndef DL_ADDR_IN_LOADADDR
# define DL_ADDR_IN_LOADADDR(ADDR, TPNT, TFROM) \
  ((void*)(TPNT)->loadaddr < (void*)(ADDR) \
   && (! (TFROM) || (TFROM)->loadaddr < (TPNT)->loadaddr))
#endif

/* For dynamic relocations that don't match _dl_symbol() are not to be
   skipped during bootstrap, arrange for this to return zero.  */
#ifndef DL_SKIP_BOOTSTRAP_RELOC
# define DL_SKIP_BOOTSTRAP_RELOC(SYMTAB, SYMTAB_INDEX, STRTAB) \
  DL_SKIP_BOOTSTRAP_RELOC_DEFAULT((SYMTAB), (SYMTAB_INDEX), (STRTAB))
#endif
#define DL_SKIP_BOOTSTRAP_RELOC_DEFAULT(SYMTAB, SYMTAB_INDEX, STRTAB) \
  (!_dl_symbol((STRTAB) + (SYMTAB)[(SYMTAB_INDEX)].st_name))

/* Define this to verify that a library named LIBNAME, whose ELF
   headers are pointed to by EPNT, is suitable for dynamic linking.
   If it is not, print an error message (optional) and return NULL.
   If the library can have its segments relocated independently,
   arrange for PICLIB to be set to 2.  If all segments have to be
   relocated by the same amount, set it to 1.  If it has to be loaded
   at physical addresses as specified in the program headers, set it
   to 0.  A reasonable (?) guess for PICLIB will already be in place,
   so it is safe to do nothing here.  */
#ifndef DL_CHECK_LIB_TYPE
# define DL_CHECK_LIB_TYPE(EPNT, PICLIB, PROGNAME, LIBNAME) (void)0
#endif

/* Define this if you want to modify the VALUE returned by
   _dl_find_hash for this reloc TYPE.  TPNT is the module in which the
   matching SYM was found.  */
#ifndef DL_FIND_HASH_VALUE
# define DL_FIND_HASH_VALUE(TPNT, TYPE, SYM) (DL_RELOC_ADDR ((SYM)->st_value, (TPNT)->loadaddr))
#endif

/* Define this if you have special segment.  */
#ifndef DL_IS_SPECIAL_SEGMENT
# define DL_IS_SPECIAL_SEGMENT(EPNT, PPNT) 0
#endif

/* Define this if you want to use special method to map the segment.  */
#ifndef DL_MAP_SEGMENT
# define DL_MAP_SEGMENT(EPNT, PPNT, INFILE, FLAGS) 0
#endif

/* Define this to enable the dynamic loader to use pread (or something
   equivalent) to load initialized data into anonymously privately
   mapped memory obtained for the entire data segment when PICLIB==2.
   It is only used when mmap fails, which is possible in case the mmap
   syscall doesn't support overlapping memory blocks.

   The definition should look something like:

   # define _DL_PREAD(FD, ADDR, LEN, OFST) _dl_pread(fd, addr, len, ofst)

   and you must also define a _dl_pread syscall wrapper.
*/

struct elf_resolve{
  /* These entries must be in this order to be compatible with the interface used
     by gdb to obtain the list of symbols. */
  DL_LOADADDR_TYPE loadaddr;	/* Base address shared object is loaded at.  */
  char *libname;		/* Absolute file name object was found in.  */
  ElfW(Dyn) *dynamic_addr;	/* Dynamic section of the shared object.  */
  struct elf_resolve * next;
  struct elf_resolve * prev;
  /* Nothing after this address is used by gdb. */
  enum {elf_lib, elf_executable,program_interpreter, loaded_file} libtype;
  struct dyn_elf * symbol_scope;
  unsigned short usage_count;
  unsigned short int init_flag;
  unsigned long rtld_flags; /* RTLD_GLOBAL, RTLD_NOW etc. */
  unsigned int nbucket;
  unsigned long * elf_buckets;
  struct init_fini_list *init_fini;
  struct init_fini_list *rtld_local; /* keep tack of RTLD_LOCAL libs in same group */
  /*
   * These are only used with ELF style shared libraries
   */
  unsigned long nchain;
  unsigned long * chains;
  unsigned long dynamic_info[DYNAMIC_SIZE];

  unsigned long n_phent;
  Elf32_Phdr * ppnt;

  ElfW(Addr) relro_addr;
  size_t relro_size;

#ifdef __powerpc__
  /* this is used to store the address of relocation data words, so
   * we don't have to calculate it every time, which requires a divide */
  unsigned long data_words;
#endif

#if defined __FRV_FDPIC__ || defined __BFIN_FDPIC__
  /* Every loaded module holds a hashtable of function descriptors of
     functions defined in it, such that it's easy to release the
     memory when the module is dlclose()d.  */
  struct funcdesc_ht *funcdesc_ht;
#endif
};

#define RELOCS_DONE         1
#define JMP_RELOCS_DONE     2
#define INIT_FUNCS_CALLED   4
#define FINI_FUNCS_CALLED   8

extern struct dyn_elf     * _dl_symbol_tables;
extern struct elf_resolve * _dl_loaded_modules;
extern struct dyn_elf 	  * _dl_handles;

extern struct elf_resolve * _dl_check_hashed_files(const char * libname);
extern struct elf_resolve * _dl_add_elf_hash_table(const char * libname, 
	DL_LOADADDR_TYPE loadaddr, unsigned long * dynamic_info, 
	unsigned long dynamic_addr, unsigned long dynamic_size);

extern char * _dl_find_hash(const char * name, struct dyn_elf * rpnt,
			    struct elf_resolve *mytpnt, int type_class);
extern char * _dl_find_hash_mod(const char * name, struct dyn_elf * rpnt,
				struct elf_resolve *mytpnt, int type_class,
				struct elf_resolve **tpntp);

extern int _dl_linux_dynamic_link(void);

extern char * _dl_library_path;
extern char * _dl_not_lazy;
extern unsigned long _dl_elf_hash(const unsigned char *name);

static inline int _dl_symbol(char * name)
{
  if(name[0] != '_' || name[1] != 'd' || name[2] != 'l' || name[3] != '_')
    return 0;
  return 1;
}


#define LD_ERROR_NOFILE 1
#define LD_ERROR_NOZERO 2
#define LD_ERROR_NOTELF 3
#define LD_ERROR_NOTMAGIC 4
#define LD_ERROR_NOTDYN 5
#define LD_ERROR_MMAP_FAILED 6
#define LD_ERROR_NODYNAMIC 7
#define LD_WRONG_RELOCS 8
#define LD_BAD_HANDLE 9
#define LD_NO_SYMBOL 10



#endif /* _LD_HASH_H_ */


