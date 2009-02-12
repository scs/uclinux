/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_ASM_SIM_BITS_INIT_H
#define _XENO_ASM_SIM_BITS_INIT_H

int __xeno_sys_init(void);

void __xeno_sys_exit(void);

int __xeno_skin_init(void);

void __xeno_skin_exit(void);

int __xeno_user_init(void);

void __xeno_user_exit(void);

static inline int xnarch_init (void)
{
    return 0;
}

static inline void xnarch_exit (void)
{
}

void mvm_root (void *cookie)
{
    int err;

    err = __xeno_skin_init();

    if (err)
	__mvm_breakable(mvm_fatal)("skin_init() failed, err=%x\n",err);

    err = __xeno_user_init();

    if (err)
	__mvm_breakable(mvm_fatal)("user_init() failed, err=%x\n",err);

    /* Wait for all RT-threads to finish */
    __mvm_breakable(mvm_join_threads)();

    __xeno_user_exit();
    __xeno_skin_exit();
    __xeno_sys_exit();

    __mvm_breakable(mvm_terminate)(0);
}

int main (int argc, char *argv[])
{
    xnarchtcb_t tcb;
    int err;

    err = __xeno_sys_init();

    if (err)
	__mvm_breakable(mvm_fatal)("sys_init() failed, err=%x\n",err);

    mvm_init(argc,argv);

    tcb.entry = &mvm_root;
    tcb.cookie = NULL;
    tcb.kthread = NULL;
    tcb.vmthread = NULL;
    tcb.imask = 0;

    return mvm_run(&tcb,(void *)&mvm_root);
}

#endif /* !_XENO_ASM_SIM_BITS_INIT_H */
