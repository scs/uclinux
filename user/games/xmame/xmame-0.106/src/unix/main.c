/*
 * X-mame main-routine
 */

#define __MAIN_C_
#include "xmame.h"
#include "sysdep/sysdep_display.h"

#if defined HAVE_MMAP || defined __QNXNTO__
#include <sys/mman.h>
#endif

static void osd_exit(void);

/* put here anything you need to do when the program is started. Return 0 if */
/* initialization was successful, nonzero otherwise. */
int osd_init(void)
{
	/* now invoice system-dependent initialization */
#ifdef XMAME_NET
	if (osd_net_init() != OSD_OK)
		return OSD_NOT_OK;
#endif	
	if (osd_input_initpre() != OSD_OK)
		return OSD_NOT_OK;

	add_exit_callback(osd_exit);

	return OSD_OK;
}

/*
 * Cleanup routines to be executed when the program is terminated.
 */
static void osd_exit(void)
{
#ifdef XMAME_NET
	osd_net_close();
#endif
	free_pathlists();
	osd_input_close();
}

void *osd_alloc_executable(size_t size)
{
#ifdef HAVE_MMAP
	void *addr = mmap(NULL, size + sizeof(size_t), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_SHARED, -1, 0);
	if (addr)
	{
		/* Store the size at the front for munmap. */
		*((size_t *)addr) = size + sizeof(size_t);
		addr = (char *)addr + sizeof(size_t);
	}
#else
	void *addr = malloc(size);
#endif
	return addr;
}

void osd_free_executable(void *ptr)
{
#ifdef HAVE_MMAP
	if (ptr)
	{
		ptr = (char *)ptr - sizeof(size_t);
		munmap(ptr, *((size_t *)ptr));
	}
#else
	free(ptr);
#endif
}

int osd_is_bad_read_ptr(const void *ptr, size_t size)
{
	/*
	 * Not the most correct way to do this, but I don't 
	 * know if it's worth writing a full implementation.
	 */
	if (!ptr)
		return TRUE;

	return FALSE;
}

int main(int argc, char **argv)
{
	int res;

#ifdef __QNXNTO__
	printf("info: Trying to enable swapfile.... ");
	munlockall();
	printf("Success!\n");
#endif

	/* some display methods need to do some stuff with root rights */
	if(sysdep_display_init())
		return 1;

	/* to be absolutely safe force giving up root rights here in case
	   a display method doesn't */
	if (setuid(getuid()))
	{
		perror("setuid");
		sysdep_display_exit();
		return OSD_NOT_OK;
	}

	/* Set the title, now auto build from defines from the makefile */
	sprintf(title,"%s (%s) version %s", NAME, DISPLAY_METHOD,
			build_version);

	/* parse configuration file and environment */
	if ((res = xmame_config_init(argc, argv)) == 1234)
	{
		/* go for it */
		res = run_game (game_index);
	}

	xmame_config_exit();
	sysdep_display_exit();

	return res;
}
