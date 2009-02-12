/*
 * This file is part of the Xenomai project.
 *
 * Copyright (C) 2008 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <posix/sig.h>
#include <posix/apc.h>

#define PSE51_LO_MAX_REQUESTS 64	/* Must be a ^2 */

static int pse51_lostage_apc;

static struct pse51_lostageq_t {
	int in, out;
	struct pse51_lostage_req_t {
		int type;
		void *arg;
		size_t size;
	} req[PSE51_LO_MAX_REQUESTS];
} pse51_lostageq[XNARCH_NR_CPUS];

void pse51_schedule_lostage(int request, void *arg, size_t size)
{
	int cpuid = rthal_processor_id(), reqnum;
	struct pse51_lostageq_t *rq = &pse51_lostageq[cpuid];
	spl_t s;

	/* Signal the APC, to have it delegate signals to Linux. */
	splhigh(s);
	reqnum = rq->in;
	rq->req[reqnum].type = request;
	rq->req[reqnum].arg = arg;
	rq->req[reqnum].size = size;
	rq->in = (reqnum + 1) & (PSE51_LO_MAX_REQUESTS - 1);
	splexit(s);

	rthal_apc_schedule(pse51_lostage_apc);
}

static void pse51_lostage_handle_request(void *cookie)
{
	int cpuid = smp_processor_id(), reqnum;
	struct pse51_lostageq_t *rq = &pse51_lostageq[cpuid];

	while ((reqnum = rq->out) != rq->in) {
		struct pse51_lostage_req_t *req = &rq->req[reqnum];
		
		rq->out = (reqnum + 1) & (PSE51_LO_MAX_REQUESTS - 1);

		switch (req->type){
#ifdef CONFIG_XENO_OPT_PERVASIVE
		case PSE51_LO_SIGNAL_REQ:
			pse51_signal_handle_request((pthread_t) req->arg);
			break;
#endif
		case PSE51_LO_FREE_REQ:
			xnarch_free_host_mem(req->arg, req->size);
			break;
		}
	}
}

int pse51_apc_pkg_init(void)
{
	pse51_lostage_apc = rthal_apc_alloc("pse51_lostage_handler",
					    &pse51_lostage_handle_request, NULL);

	if (pse51_lostage_apc < 0)
		printk("Unable to allocate APC: %d !\n", pse51_lostage_apc);

	return pse51_lostage_apc < 0;
}

void pse51_apc_pkg_cleanup(void)
{
	rthal_apc_free(pse51_lostage_apc);
}
