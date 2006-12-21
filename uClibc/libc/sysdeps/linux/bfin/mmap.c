/* Use new style mmap for bfin */

#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifdef __NR_mmap2
#include <asm/page.h>

inline __ptr_t mmap(__ptr_t addr, size_t len, int prot,
		int flags, int fd, __off_t offset)
{
	unsigned long buffer[6];

	if (offset & ~PAGE_MASK) {
		return NULL;
	}
	return __syscall_mmap2(addr, len, prot, flags, fd, offset >> PAGE_SHIFT);
}

#else

inline _syscall6 (__ptr_t, mmap, __ptr_t, addr, size_t, len, int, prot,
	   int, flags, int, fd, __off_t, offset);
#endif
