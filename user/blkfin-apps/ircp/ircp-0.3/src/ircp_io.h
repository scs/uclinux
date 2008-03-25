#ifndef IRCP_IO_H
#define IRCP_IO_H

typedef enum {
	CD_CREATE=1,
	CD_ALLOWABS=2
} cd_flags;

obex_object_t *build_object_from_file(obex_t *handle, const char *localname, const char *remotename);
int ircp_open_safe(const char *path, const char *name);
int ircp_checkdir(const char *path, const char *dir, cd_flags flags);

#endif /* IRCP_IO_H */
