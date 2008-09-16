#ifndef _XENO_ASM_GENERIC_BITS_BIND_H
#define _XENO_ASM_GENERIC_BITS_BIND_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <asm/xenomai/syscall.h>

void xeno_handle_mlock_alert(int sig);

static inline int
xeno_bind_skin(unsigned skin_magic, const char *skin, const char *module)
{
	struct sigaction sa;
	xnfeatinfo_t finfo;
	int muxid;

	muxid = XENOMAI_SYSBIND(skin_magic,
				XENOMAI_FEAT_DEP, XENOMAI_ABI_REV, &finfo);
	switch (muxid) {
	case -EINVAL:

		fprintf(stderr, "Xenomai: incompatible feature set\n");
		fprintf(stderr,
			"(userland requires \"%s\", kernel provides \"%s\", missing=\"%s\").\n",
			finfo.feat_man_s, finfo.feat_all_s, finfo.feat_mis_s);
		exit(1);

	case -ENOEXEC:

		fprintf(stderr, "Xenomai: incompatible ABI revision level\n");
		fprintf(stderr, "(needed=%lu, current=%lu).\n",
			XENOMAI_ABI_REV, finfo.abirev);
		exit(1);

	case -ENOSYS:
	case -ESRCH:

		fprintf(stderr,
			"Xenomai: %s skin or CONFIG_XENO_OPT_PERVASIVE disabled.\n"
			"(modprobe %s?)\n", skin, module);
		exit(1);
	}

	if (muxid < 0) {
		fprintf(stderr, "Xenomai: binding failed: %s.\n",
			strerror(-muxid));
		exit(1);
	}

#ifdef xeno_arch_features_check
	xeno_arch_features_check();
#endif /* xeno_arch_features_check */

	/* Install a SIGXCPU handler to intercept alerts about unlocked
	   process memory. */

	sa.sa_handler = &xeno_handle_mlock_alert;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGXCPU, &sa, NULL);

	return muxid;
}

static inline int
xeno_bind_skin_opt(unsigned skin_magic, const char *skin, const char *module)
{
	xnfeatinfo_t finfo;
	int muxid;

	muxid = XENOMAI_SYSBIND(skin_magic,
				XENOMAI_FEAT_DEP, XENOMAI_ABI_REV, &finfo);
	switch (muxid) {
	case -EINVAL:

		fprintf(stderr, "Xenomai: incompatible feature set\n");
		fprintf(stderr,
			"(required=\"%s\", present=\"%s\", missing=\"%s\").\n",
			finfo.feat_man_s, finfo.feat_all_s, finfo.feat_mis_s);
		exit(1);

	case -ENOEXEC:

		fprintf(stderr, "Xenomai: incompatible ABI revision level\n");
		fprintf(stderr, "(needed=%lu, current=%lu).\n",
			XENOMAI_ABI_REV, finfo.abirev);
		exit(1);

	case -ENOSYS:
	case -ESRCH:

		return -1;
	}

	if (muxid < 0) {
		fprintf(stderr, "Xenomai: binding failed: %s.\n",
			strerror(-muxid));
		exit(1);
	}

#ifdef xeno_arch_features_check
	xeno_arch_features_check();
#endif /* xeno_arch_features_check */

	return muxid;
}

#endif /* _XENO_ASM_GENERIC_BITS_BIND_H */
