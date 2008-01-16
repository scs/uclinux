/***************************************************************************

    osd_tool.c

    OS-dependent code interface for tools

    Copyright (c) 1996-2006, Nicola Salmoria and the MAME Team.
    Visit http://mamedev.org for licensing and usage restrictions.

***************************************************************************/

#include "osdepend.h"
#include "osd_tool.h"

#ifdef HAVE_UNISTD_H
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef _POSIX_VERSION
#define OFF_T off_t
#define FSEEK fseeko
#define FTELL ftello
#else
#define OFF_T long
#define FSEEK fseek
#define FTELL ftell
#endif

typedef struct
{
	FILE	*file;
	char	*buf;
	OFF_T	size;
} iso_file_t;



/*-------------------------------------------------
    is_physical_drive - clue to Win32 code that
    we're reading a physical drive directly
-------------------------------------------------*/

int osd_is_physical_drive(const char *file)
{
	return FALSE;
}



/*-------------------------------------------------
    osd_get_physical_drive_geometry - retrieves
    geometry for physical drives
-------------------------------------------------*/

int osd_get_physical_drive_geometry(const char *filename, UINT32 *cylinders,
		UINT32 *heads, UINT32 *sectors, UINT32 *bps)
{
	return FALSE;
}



/*-------------------------------------------------
    osd_get_file_size - returns the 64-bit file size
    for a file
-------------------------------------------------*/

UINT64 osd_get_file_size(const char *file)
{
	OFF_T filesize;
	FILE *f;

	/* attempt to open the file */
	f = fopen(file, "rb");
	if (!f)
		return 0;

	/* get the size */
	FSEEK(f, 0, SEEK_END);
	filesize = FTELL(f);
	fclose(f);

	return filesize;
}



osd_tool_file *osd_tool_fopen(const char *filename, const char *mode)
{
	iso_file_t *iso_file = NULL;
	FILE *file = fopen(filename, mode);
	if (file)
	{
		OFF_T size;
		char *buf = (char *)malloc(BUFSIZ);
		if (buf)
		{
			/*
			 * Calling setbuf makes -createhd and -merge run 5 - 10x faster
			 * on Linux with the GNU C Library, and it shouldn't hurt
			 * performance on other platforms (verified on Mac OS X).
			 */
			setbuf(file, buf);
		}

		FSEEK(file, 0, SEEK_END);
		size = FTELL(file);
		rewind(file);

		iso_file = (iso_file_t *)malloc(sizeof(iso_file_t));
		if (iso_file)
		{
			iso_file->file = file;
			iso_file->buf = buf;
			iso_file->size = size;
		}
	}
	return (osd_tool_file *)iso_file;
}



void osd_tool_fclose(osd_tool_file *file)
{
	fclose(((iso_file_t *)file)->file);
	free(((iso_file_t *)file)->buf);
	free(file);
}



UINT32 osd_tool_fread(osd_tool_file *file, UINT64 offset, UINT32 count,
		void *buffer)
{
	iso_file_t *iso_file = (iso_file_t *)file;
	if (FSEEK(iso_file->file, offset, SEEK_SET) == 0)
		return fread(buffer, 1, count, iso_file->file);
	else
		return 0;
}



UINT32 osd_tool_fwrite(osd_tool_file *file, UINT64 offset, UINT32 count,
		const void *buffer)
{
	size_t bytes_written = 0;
	iso_file_t *iso_file = (iso_file_t *)file;
	if (FSEEK(iso_file->file, offset, SEEK_SET) == 0)
	{
		bytes_written = fwrite(buffer, 1, count, iso_file->file);
		if (offset + bytes_written > iso_file->size)
			iso_file->size = offset + bytes_written;
	}
	return bytes_written;
}



UINT64 osd_tool_flength(osd_tool_file *file)
{
		return ((iso_file_t *)file)->size;
}
