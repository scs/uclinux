/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
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

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <rtai/fifo.h>

static RT_FIFO __fifo_table[CONFIG_XENO_OPT_PIPE_NRDEV];

#ifdef CONFIG_XENO_EXPORT_REGISTRY

extern xnptree_t __rtai_ptree;

static int __fifo_read_proc(char *page,
			    char **start,
			    off_t off, int count, int *eof, void *data)
{
	RT_FIFO *p = data;
	char *ptrW = page;
	int len;

	ptrW += sprintf(ptrW, "Size     - Written  - F - Handler  - Ref\n");

	/* Output buffer:  xnpipe_mh_t *buffer; */
	ptrW += sprintf(ptrW, "%08zX - %08zX - %p - %i\n",
			p->bufsz, p->fillsz, p->handler, p->refcnt);

	len = ptrW - page - off;
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}

static xnpnode_t __fifo_pnode = {

	.dir = NULL,
	.type = "fifo",
	.entries = 0,
	.read_proc = &__fifo_read_proc,
	.write_proc = NULL,
	.root = &__rtai_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __fifo_pnode = {

	.type = "fifo"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

#define CALL_FIFO_HANDLER(fifo, type)	\
	  ((int (*)(int, ...))((fifo)->handler))((fifo) - __fifo_table, (type))

static int __fifo_input_handler(struct xnpipe_mh *mh, int retval, void *xstate) /* nklock held */
{
	RT_FIFO *fifo = xstate;
	int err;

	if (retval >= 0 && fifo->handler) {
		err = CALL_FIFO_HANDLER(fifo, 'w');
		if (err < 0)
			retval = err;
	}

	return retval;
}

static void __fifo_output_handler(xnpipe_mh_t *mh, void *xstate) /* nklock held */
{
	RT_FIFO *fifo = xstate;

	if (fifo->handler)
		CALL_FIFO_HANDLER(fifo, 'r');
}

static void __fifo_ifree_handler(void *buf, void *xstate) /* nklock free */
{
	xnfree(buf);
}

static void __fifo_ofree_handler(void *buf, void *xstate) /* nklock free except when resizing */
{
	RT_FIFO *fifo = xstate;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	fifo->fillsz = 0;
	__clear_bit(RTFIFO_SYNCWAIT, &fifo->status);
	xnlock_put_irqrestore(&nklock, s);
}

static void __fifo_release_handler(void *xstate) /* nklock free */
{
	RT_FIFO *fifo = xstate;
	void *buffer;
	int size;
	spl_t s;

	xnlock_get_irqsave(&nklock, s); /* Protect against resizes. */
	buffer = fifo->buffer;
	size = fifo->bufsz;
	fifo->buffer = NULL;
	xnlock_put_irqrestore(&nklock, s);

	if (buffer)
		xnarch_free_host_mem(buffer, size + sizeof(xnpipe_mh_t));
}

int __rtai_fifo_pkg_init(void)
{
	int i;

	for (i = 0; i < CONFIG_XENO_OPT_PIPE_NRDEV; i++)
		inith(&__fifo_table[i].link);

	return 0;
}

void __rtai_fifo_pkg_cleanup(void)
{
}

int rtf_create(unsigned minor, int size)
{
	struct xnpipe_operations ops;
	int err, oldsize;
	RT_FIFO *fifo;
	void *buffer;
	spl_t s;

	if (minor >= CONFIG_XENO_OPT_PIPE_NRDEV)
		return -ENODEV;

	/* <!> We do check for the calling context albeit the original
	   API doesn't, but we don't want the box to break for
	   whatever reason, so sanity takes precedence over
	   compatibility here. */

	if (!xnpod_root_p())
		return -EPERM;

	if (!size)
		return -EINVAL;

	fifo = __fifo_table + minor;
	ops.output = &__fifo_output_handler;
	ops.input = &__fifo_input_handler;
	ops.release = &__fifo_release_handler;
	ops.free_ibuf = &__fifo_ifree_handler;
	ops.free_obuf = &__fifo_ofree_handler;
	/* Use defaults: */
	ops.alloc_ibuf = NULL;	/* i.e. xnmalloc() */

	err = xnpipe_connect(minor, &ops, fifo);
	if (err < 0 && err != -EBUSY)
		return err;

	xnlock_get_irqsave(&nklock, s);

	++fifo->refcnt;

	if (err == -EBUSY) {
		/* Resize the fifo on-the-fly if the specified buffer
		   size is different from the current one. */

		/*
		 * Make sure the streaming buffer is not enqueued for
		 * output.
		 */
		xnpipe_flush(minor, XNPIPE_OFLUSH);

		buffer = fifo->buffer;
		oldsize = fifo->bufsz;

		if (buffer == NULL)	/* Conflicting create/resize requests. */
			goto fail;

		if (oldsize == size) {
			err = minor;
			goto fail;	/* Same size, nop. */
		}

		fifo->buffer = NULL;
		/* We must not keep the nucleus lock while running
		 * Linux services. */
		xnlock_put_irqrestore(&nklock, s);
		xnarch_free_host_mem(buffer, oldsize + sizeof(xnpipe_mh_t));
		xnlock_get_irqsave(&nklock, s);
	} else
		fifo->buffer = NULL;

	xnlock_put_irqrestore(&nklock, s);
	buffer = xnarch_alloc_host_mem(size + sizeof(xnpipe_mh_t));

	if (buffer == NULL) {
		if (err >= 0)
			xnpipe_disconnect(minor);
		xnlock_get_irqsave(&nklock, s);
		--fifo->refcnt;
		err = -ENOMEM;
		goto fail;
	}

	xnlock_get_irqsave(&nklock, s);

	fifo->buffer = buffer;
	fifo->bufsz = size;
	fifo->fillsz = 0;
	fifo->status = 0;
	fifo->minor = minor;
	fifo->handler = NULL;

	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_REGISTRY
	{
		fifo->handle = 0;
		snprintf(fifo->name, sizeof(fifo->name), "rtf%u", minor);
		xnregistry_enter(fifo->name, fifo, &fifo->handle, &__fifo_pnode);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return minor;

fail:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rtf_destroy(unsigned minor)
{
	int refcnt, err = 0, oldsize;
	RT_FIFO *fifo;
	void *buffer;
	spl_t s;

	if (minor >= CONFIG_XENO_OPT_PIPE_NRDEV)
		return -ENODEV;

	if (!xnpod_root_p())
		return -EPERM;

	fifo = __fifo_table + minor;

	xnlock_get_irqsave(&nklock, s);

	refcnt = fifo->refcnt;

	if (refcnt == 0)
		err = -EINVAL;
	else {
		if (--refcnt == 0) {
			buffer = fifo->buffer;
			oldsize = fifo->bufsz;

			if (buffer == NULL) {	/* Fifo under (re-)construction. */
				err = -EBUSY;
				goto unlock_and_exit;
			}

#ifdef CONFIG_XENO_OPT_REGISTRY
			if (fifo->handle)
				xnregistry_remove(fifo->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */
			fifo->refcnt = 0;
			xnlock_put_irqrestore(&nklock, s);
			xnpipe_disconnect(minor);

			return 0;
		}

		fifo->refcnt = refcnt;
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

int rtf_get(unsigned minor, void *buf, int count)
{
	xnpipe_mh_t *msg;
	ssize_t nbytes;
	RT_FIFO *fifo;
	spl_t s;

	if (minor >= CONFIG_XENO_OPT_PIPE_NRDEV)
		return -ENODEV;

	if (count == 0)
		return 0;

	fifo = __fifo_table + minor;

	xnlock_get_irqsave(&nklock, s);

	if (fifo->refcnt == 0) {
		nbytes = -EINVAL;
		goto unlock_and_exit;
	}

	if (fifo->buffer == NULL) {
		nbytes = -EBUSY;
		goto unlock_and_exit;
	}

	nbytes = xnpipe_recv(minor, &msg, XN_NONBLOCK);

	if (nbytes < 0) {
		if (nbytes == -EWOULDBLOCK || nbytes == -EIDRM)
			nbytes = 0;

		goto unlock_and_exit;
	}

	/* <!> Behaviour differs from the original API: we don't scatter
	   the received data, so rtf_get() must be passed a buffer large
	   enough to collect the largest block of data sent by the
	   user-space in a single call to write(). */

	if (count < xnpipe_m_size(msg))
		nbytes = -ENOSPC;
	else if (xnpipe_m_size(msg) > 0)
		memcpy(buf, xnpipe_m_data(msg), xnpipe_m_size(msg));

	/* Zero-sized messages are allowed, so we still need to free the
	   message buffer even if no data copy took place. */

	xnfree(msg);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return nbytes;
}

int rtf_put(unsigned minor, const void *buf, int count)
{
	ssize_t outbytes;
	size_t fillptr;
	RT_FIFO *fifo;
	spl_t s;

	if (minor >= CONFIG_XENO_OPT_PIPE_NRDEV)
		return -ENODEV;

	fifo = __fifo_table + minor;

	xnlock_get_irqsave(&nklock, s);

	if (fifo->refcnt == 0) {
		outbytes = -EINVAL;
		goto unlock_and_exit;
	}

	if (fifo->buffer == NULL) {
		outbytes = -EBUSY;
		goto unlock_and_exit;
	}

	if (count > fifo->bufsz - fifo->fillsz)
		outbytes = fifo->bufsz - fifo->fillsz;
	else
		outbytes = count;

	if (outbytes > 0) {
		fillptr = fifo->fillsz;
		fifo->fillsz += outbytes;

		xnlock_put_irqrestore(&nklock, s);

		memcpy(xnpipe_m_data(fifo->buffer) + fillptr,
		       (caddr_t) buf, outbytes);

		xnlock_get_irqsave(&nklock, s);

		if (__test_and_set_bit(RTFIFO_SYNCWAIT, &fifo->status))
			outbytes =
			    xnpipe_mfixup(fifo->minor, fifo->buffer, outbytes);
		else {
			outbytes = xnpipe_send(fifo->minor, fifo->buffer,
					       outbytes + sizeof(xnpipe_mh_t),
					       XNPIPE_NORMAL);
			if (outbytes > 0)
				outbytes -= sizeof(xnpipe_mh_t);
		}
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return outbytes;
}

int rtf_reset(unsigned minor)
{
	RT_FIFO *fifo;

	if (minor >= CONFIG_XENO_OPT_PIPE_NRDEV)
		return -ENODEV;

	fifo = __fifo_table + minor;
	fifo->fillsz = 0;

	return 0;
}

int rtf_create_handler(unsigned minor, int (*handler) (unsigned minor))
{
	RT_FIFO *fifo;

	if (minor >= CONFIG_XENO_OPT_PIPE_NRDEV || !handler)
		return -EINVAL;

	fifo = __fifo_table + minor;
	fifo->handler = handler;

	return 0;
}

EXPORT_SYMBOL(rtf_create);
EXPORT_SYMBOL(rtf_destroy);
EXPORT_SYMBOL(rtf_put);
EXPORT_SYMBOL(rtf_get);
EXPORT_SYMBOL(rtf_reset);
EXPORT_SYMBOL(rtf_create_handler);
