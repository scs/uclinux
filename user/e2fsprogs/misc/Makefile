
include ../MCONFIG

E2IMAGE_PROG= e2image
SPROGS=		mke2fs badblocks tune2fs dumpe2fs $(E2IMAGE_PROG) fsck
USPROGS=	mklost+found

UPROGS=		chattr lsattr uuidgen

TUNE2FS_OBJS=	tune2fs.o util.o get_device_by_label.o
MKLPF_OBJS=	mklost+found.o
MKE2FS_OBJS=	mke2fs.o util.o get_device_by_label.o
CHATTR_OBJS=	chattr.o
LSATTR_OBJS=	lsattr.o
UUIDGEN_OBJS=	uuidgen.o
DUMPE2FS_OBJS=	dumpe2fs.o
BADBLOCKS_OBJS=	badblocks.o
E2IMAGE_OBJS=	e2image.o
FSCK_OBJS=	fsck.o get_device_by_label.o base_device.o fstype.o

LIBS= $(LIBEXT2FS) $(LIBCOM_ERR) 
DEPLIBS= $(LIBEXT2FS) $(LIBCOM_ERR) 

LIBS_E2P= $(LIBEXT2FS) $(LIBE2P) $(LIBCOM_ERR) 
DEPLIBS_E2P= $(LIBEXT2FS) $(LIBE2P) $(LIBCOM_ERR) 

all: $(SPROGS) $(UPROGS) $(USPROGS) $(SMANPAGES) $(UMANPAGES)

findsuper: findsuper.o
	$(CC) $(LDFLAGS) -o findsuper findsuper.o $(LDLIBS)

tune2fs: $(TUNE2FS_OBJS) $(DEPLIBS_E2P) $(DEPLIBUUID)
	$(CC) $(LDFLAGS) -o tune2fs $(TUNE2FS_OBJS) $(LIBS_E2P) $(LIBUUID) $(LDLIBS)

e2image: $(E2IMAGE_OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o e2image $(E2IMAGE_OBJS) $(LIBS) $(LDLIBS)

base_device: base_device.c
	$(CC) $(CFLAGS) $(ALL_LDFLAGS) $< -DDEBUG -o $@ $(LDLIBS)

mklost+found: $(MKLPF_OBJS)
	$(CC) $(LDFLAGS) -o mklost+found $(MKLPF_OBJS) $(LDLIBS)

mke2fs: $(MKE2FS_OBJS) $(DEPLIBS) $(LIBE2P) $(DEPLIBUUID)
	$(CC) $(LDFLAGS) -o mke2fs $(MKE2FS_OBJS) $(LIBS) $(LIBE2P) $(LIBUUID) $(LDLIBS)

resize2fs: resize2fs.o $(DEPLIBS)
	$(CC) $(LDFLAGS) -o resize2fs resize2fs.o $(LIBS) $(LDLIBS)

chattr: $(CHATTR_OBJS) $(DEPLIBS_E2P)
	$(CC) $(LDFLAGS) -o chattr $(CHATTR_OBJS) $(LIBS_E2P) $(LDLIBS)

lsattr: $(LSATTR_OBJS) $(DEPLIBS_E2P)
	$(CC) $(LDFLAGS) -o lsattr $(LSATTR_OBJS) $(LIBS_E2P) $(LDLIBS)

uuidgen: $(UUIDGEN_OBJS) $(DEPLIBUUID)
	$(CC) $(LDFLAGS) -o uuidgen $(UUIDGEN_OBJS) $(LIBUUID) $(LDLIBS)

dumpe2fs: $(DUMPE2FS_OBJS) $(DEPLIBS_E2P) $(DEPLIBUUID)
	$(CC) $(LDFLAGS) -o dumpe2fs $(DUMPE2FS_OBJS) $(LIBS_E2P) $(LIBUUID) $(LDLIBS)

fsck: $(FSCK_OBJS)
	$(CC) $(LDFLAGS) -o fsck $(FSCK_OBJS) $(LIBS) $(LDLIBS)

badblocks: $(BADBLOCKS_OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o badblocks $(BADBLOCKS_OBJS) $(LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_BADBLOCKS /bin/badblocks
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_CHATTR /bin/chattr
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_DUMPE2FS /bin/dumpe2fs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_E2LABEL /bin/e2label
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_FSCK /bin/fsck
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_LSATTR /bin/lsattr
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_MKE2FS /bin/mke2fs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_MKLOST_FOUND /bin/mklost+found
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_TUNE2FS /bin/tune2fs
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_MISC_UUIDGEN /bin/uuidgen

clean:
	$(RM) -f $(SPROGS) $(USPROGS) $(UPROGS) $(UMANPAGES) $(SMANPAGES) \
		base_device base_device.out mke2fs.static \
		\#* *.s *.gdb *.o *.a *~ core 

$(TUNE2FS_OBJS) $(MKLPF_OBJS) $(MKE2FS_OBJS) $(CHATTR_OBJS): ../MCONFIG
$(LSATTR_OBJS) $(UUIDGEN_OBJS) $(DUMPE2FS_OBJS) $(BADBLOCKS_OBJS): ../MCONFIG
$(E2IMAGE_OBJS) $(FSCK_OBJS): ../MCONFIG

