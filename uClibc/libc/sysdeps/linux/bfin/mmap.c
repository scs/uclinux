/* Use new style mmap for bfin */

#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifdef __NR_mmap2
#include <asm/page.h>

#define __NR___syscall_mmap2 __NR_mmap2
static inline _syscall6(__ptr_t, __syscall_mmap2, __ptr_t, addr, size_t, len,
                 int, prot, int, flags, int, fd, __off_t, offset);

__ptr_t mmap(__ptr_t addr, size_t len, int prot,
                    int flags, int fd, __off_t offset)
{
	if (offset & ~PAGE_MASK) {
		__set_errno(EINVAL);
		return NULL;
	}
	return __syscall_mmap2(addr, len, prot, flags, fd, offset >> PAGE_SHIFT);
}

#else

_syscall6(__ptr_t, mmap, __ptr_t, addr, size_t, len, int, prot,
          int, flags, int, fd, __off_t, offset);
#endif
