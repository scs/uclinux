/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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

#include <posix_test.h>

static pthread_t root_thread_tcb;

void *root_thread(void *cookie)
{
    TEST_START(0);

    TEST_CHECK_SEQUENCE(SEQ("root", 1),
                        END_SEQ);

    TEST_FINISH();

    return NULL;
}

int __xeno_user_init (void)
{
    int rc;
    pthread_attr_t attr;
    

    pthread_attr_init(&attr);
    pthread_attr_setname_np(&attr, "root");
    
    rc=pthread_create(&root_thread_tcb, &attr, root_thread, NULL);

    pthread_attr_destroy(&attr);

    return rc;
}

void __xeno_user_exit (void)
{
    pthread_kill(root_thread_tcb, 30);
    pthread_join(root_thread_tcb, NULL);
}
