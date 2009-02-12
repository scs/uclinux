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

/**
 * @ingroup posix_thread
 * @defgroup posix_threadattr Thread creation attributes.
 *
 * Thread creation attributes.
 *
 * The services described in this section allow to set the attributes of a
 * @b pthread_attr_t object, passed to the pthread_create() service in order
 * to set the attributes of a created thread.
 *
 * A @b pthread_attr_t object has to be initialized with pthread_attr_init()
 * first, which sets attributes to their default values, i.e. in kernel-space:
 * - @a detachstate to PTHREAD_CREATE_JOINABLE,
 * - @a stacksize to PTHREAD_STACK_MIN,
 * - @a inheritsched to PTHREAD_EXPLICIT_SCHED,
 * - @a schedpolicy to SCHED_OTHER,
 * - @a name to NULL (only available in kernel-space),
 * - scheduling priority to the minimum,
 * - floating-point hardware enabled (only available in kernel-space),
 * - processor affinity set to all available processors (only available as a
 *   thread attribute in kernel-space).
 *
 * In user-space, the attributes and their defaults values are those documented
 * by the underlying threading library (LinuxThreads or NPTL).
 * 
 *@{*/

#include <posix/internal.h>

static const pthread_attr_t default_thread_attr = {
      magic:PSE51_THREAD_ATTR_MAGIC,
      detachstate:PTHREAD_CREATE_JOINABLE,
      stacksize:PTHREAD_STACK_MIN,
      inheritsched:PTHREAD_EXPLICIT_SCHED,
      policy:SCHED_OTHER,
      schedparam:{
      sched_priority:0},

      name:NULL,
      fp:1,
      affinity:XNPOD_ALL_CPUS,
};

/**
 * Initialize a thread attributes object.
 *
 * This service initializes the thread creation attributes structure pointed to
 * by @a attr. Attributes are set to their default values (see @ref
 * posix_threadattr).
 *
 * If this service is called specifying a thread attributes object that was
 * already initialized, the attributes object is reinitialized.
 *
 * @param attr address of the thread attributes object to initialize.
 *
 * @return 0.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_init.html">
 * Specification.</a>
 * 
 */
int pthread_attr_init(pthread_attr_t * attr)
{
	*attr = default_thread_attr;

	return 0;
}

/**
 * Destroy a thread attributes object.
 *
 * This service invalidates the attribute object pointed to by @a attr. The
 * object becomes invalid for all services (they all return EINVAL) except
 * pthread_attr_init().
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_destroy.html">
 * Specification.</a>
 * 
 */
int pthread_attr_destroy(pthread_attr_t * attr)
{
	char *name;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	name = attr->name;
	pse51_mark_deleted(attr);
	xnlock_put_irqrestore(&nklock, s);

	if (name)
		xnfree(name);

	return 0;
}

/**
 * Get detachstate attribute.
 *
 * This service returns, at the address @a detachstate, the value of the
 * @a detachstate attribute in the thread attribute object @a attr.
 *
 * Valid values of this attribute are PTHREAD_CREATE_JOINABLE and
 * PTHREAD_CREATE_DETACHED. A detached thread is a thread which control block is
 * automatically reclaimed when it terminates. The control block of a joinable
 * thread, on the other hand, is only reclaimed when joined with the service
 * pthread_join().
 *
 * A thread that was created joinable may be detached after creation by using
 * the pthread_detach() service.
 *
 * @param attr attribute object
 *
 * @param detachstate address where the value of the detachstate attribute will
 * be stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid;
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_getdetachstate.html">
 * Specification.</a>
 * 
 */
int pthread_attr_getdetachstate(const pthread_attr_t * attr, int *detachstate)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*detachstate = attr->detachstate;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set detachstate attribute.
 *
 * This service sets to @a detachstate the value of the @a detachstate attribute
 * in the attribute object @a attr. 
 *
 * Valid values of this attribute are PTHREAD_CREATE_JOINABLE and
 * PTHREAD_CREATE_DETACHED. A detached thread is a thread which control block is
 * automatically reclaimed when it terminates. The control block of a joinable
 * thread, on the other hand, is only reclaimed when joined with the service
 * pthread_join().
 *
 * A thread that was created joinable may be detached after creation by using
 * the pthread_detach() service.
 *
 * @param attr attribute object;
 *
 * @param detachstate value of the detachstate attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, the attribute object @a attr is invalid
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_setdetachstate.html">
 * Specification.</a>
 * 
 */
int pthread_attr_setdetachstate(pthread_attr_t * attr, int detachstate)
{
	spl_t s;

	if (detachstate != PTHREAD_CREATE_JOINABLE
	    && detachstate != PTHREAD_CREATE_DETACHED)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->detachstate = detachstate;
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get stacksize attribute.
 *
 * This service stores, at the address @a stacksize, the value of the @a
 * stacksize attribute in the attribute object @a attr.
 *
 * The @a stacksize attribute is used as the stack size of the threads created
 * using the attribute object @a attr.
 *
 * @param attr attribute object;
 *
 * @param stacksize address where the value of the @a stacksize attribute will
 * be stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_getstacksize.html">
 * Specification.</a>
 *
 */
int pthread_attr_getstacksize(const pthread_attr_t * attr, size_t * stacksize)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*stacksize = attr->stacksize;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set stacksize attribute.
 *
 * This service set to @a stacksize, the value of the @a stacksize attribute in
 * the attribute object @a attr.
 *
 * The @a stacksize attribute is used as the stack size of the threads created
 * using the attribute object @a attr.
 *
 * The minimum value for this attribute is PTHREAD_STACK_MIN.
 *
 * @param attr attribute object;
 *
 * @param stacksize value of the @a stacksize attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr or @a stacksize is invalid.
 * 
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_setstacksize.html">
 * Specification.</a>
 * 
 */
int pthread_attr_setstacksize(pthread_attr_t * attr, size_t stacksize)
{
	spl_t s;

	if (stacksize < PTHREAD_STACK_MIN)
		return EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->stacksize = stacksize;
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get inheritsched attribute.
 *
 * This service returns at the address @a inheritsched the value of the @a
 * inheritsched attribute in the attribute object @a attr.
 *
 * Threads created with this attribute set to PTHREAD_INHERIT_SCHED will use
 * the same scheduling policy and priority as the thread calling
 * pthread_create(). Threads created with this attribute set to
 * PTHREAD_EXPLICIT_SCHED will use the value of the @a schedpolicy attribute as
 * scheduling policy, and the value of the @a schedparam  attribute as scheduling
 * priority.
 *
 * @param attr attribute object;
 *
 * @param inheritsched address where the value of the @a inheritsched attribute
 * will be stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_getinheritsched.html">
 * Specification.</a>
 * 
 */
int pthread_attr_getinheritsched(const pthread_attr_t * attr, int *inheritsched)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*inheritsched = attr->inheritsched;

	return 0;
}

/**
 * Set inheritsched attribute.
 *
 * This service set to @a inheritsched the value of the @a inheritsched
 * attribute in the attribute object @a attr.
 *
 * Threads created with this attribute set to PTHREAD_INHERIT_SCHED will use the
 * same scheduling policy and priority as the thread calling
 * pthread_create(). Threads created with this attribute set to
 * PTHREAD_EXPLICIT_SCHED will use the value of the @a schedpolicy attribute as
 * scheduling policy, and the value of the @a schedparam attribute as scheduling
 * priority.
 *
 * @param attr attribute object;
 *
 * @param inheritsched value of the @a inheritsched attribute,
 * PTHREAD_INHERIT_SCHED or PTHREAD_EXPLICIT_SCHED.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr or @a inheritsched is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_setinheritsched.html">
 * Specification.</a>
 * 
 */
int pthread_attr_setinheritsched(pthread_attr_t * attr, int inheritsched)
{
	spl_t s;

	switch (inheritsched) {
	default:
		return EINVAL;

	case PTHREAD_INHERIT_SCHED:
	case PTHREAD_EXPLICIT_SCHED:
		break;
	}

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->inheritsched = inheritsched;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get schedpolicy attribute.
 *
 * This service stores, at the address @a policy, the value of the @a policy
 * attribute in the attribute object @a attr.
 *
 * Threads created with the attribute object @a attr use the value of this
 * attribute as scheduling policy if the @a inheritsched attribute is set to
 * PTHREAD_EXPLICIT_SCHED. The value of this attribute is one of SCHED_FIFO,
 * SCHED_RR or SCHED_OTHER.
 *
 * @param attr attribute object;
 *
 * @param policy address where the value of the @a policy attribute in the
 * attribute object @a attr will be stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_getschedpolicy.html">
 * Specification.</a>
 * 
 */
int pthread_attr_getschedpolicy(const pthread_attr_t * attr, int *policy)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*policy = attr->policy;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set schedpolicy attribute.
 *
 * This service set to @a policy the value of the @a policy attribute in the
 * attribute object @a attr.
 *
 * Threads created with the attribute object @a attr use the value of this
 * attribute as scheduling policy if the @a inheritsched attribute is set to
 * PTHREAD_EXPLICIT_SCHED. The value of this attribute is one of SCHED_FIFO,
 * SCHED_RR or SCHED_OTHER.
 *
 * @param attr attribute object;
 *
 * @param policy value of the @a policy attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr or @a policy is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_setschedpolicy.html">
 * Specification.</a>
 * 
 */
int pthread_attr_setschedpolicy(pthread_attr_t * attr, int policy)
{
	spl_t s;

	switch (policy) {
	default:

		return EINVAL;

	case SCHED_OTHER:
	case SCHED_FIFO:
	case SCHED_RR:

		break;
	}

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->policy = policy;
	if (policy == SCHED_OTHER) {
		if (attr->schedparam.sched_priority != 0)
			attr->schedparam.sched_priority = 0;
	} else if (attr->schedparam.sched_priority == 0)
		attr->schedparam.sched_priority = PSE51_MIN_PRIORITY;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get schedparam attribute.
 *
 * This service stores, at the address @a par, the value of the @a schedparam
 * attribute in the attribute object @a attr.
 *
 * The only member of the @b sched_param structure used by this implementation
 * is @a sched_priority. Threads created with @a attr will use the value of this
 * attribute as a scheduling priority if the attribute @a inheritsched is set to
 * PTHREAD_EXPLICIT_SCHED. Valid priorities range from 1 to 99.
 *
 * @param attr attribute object;
 *
 * @param par address where the value of the @a schedparam attribute will be
 * stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_getschedparam.html">
 * Specification.</a>
 * 
 */
int pthread_attr_getschedparam(const pthread_attr_t * attr,
			       struct sched_param *par)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*par = attr->schedparam;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set schedparam attribute.
 *
 * This service set to @a par, the value of the @a schedparam attribute in the
 * attribute object @a attr.
 *
 * The only member of the @b sched_param structure used by this implementation
 * is @a sched_priority. Threads created with @a attr will use the value of this
 * attribute as a scheduling priority if the attribute @a inheritsched is set to
 * PTHREAD_EXPLICIT_SCHED. Valid priorities range from 1 to 99.
 *
 *
 * @param attr attribute object;
 *
 * @param par value of the @a schedparam attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr or @a par is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_setschedparam.html">
 * Specification.</a>
 * 
 */
int pthread_attr_setschedparam(pthread_attr_t * attr,
			       const struct sched_param *par)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	if ((attr->policy != SCHED_OTHER &&
	     (par->sched_priority < PSE51_MIN_PRIORITY
	      || par->sched_priority > PSE51_MAX_PRIORITY))
	    || (attr->policy == SCHED_OTHER && par->sched_priority != 0)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->schedparam = *par;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get contention scope attribute.
 *
 * This service stores, at the address @a scope, the value of the @a scope
 * attribute in the attribute object @a attr.
 *
 * The @a scope attribute represents the scheduling contention scope of threads
 * created with the attribute object @a attr. This implementation only supports
 * the value PTHREAD_SCOPE_SYSTEM.
 *
 * @param attr attribute object;
 *
 * @param scope address where the value of the @a scope attribute will be stored
 * on sucess.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_getscope.html">
 * Specification.</a>
 * 
 */
int pthread_attr_getscope(const pthread_attr_t * attr, int *scope)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*scope = PTHREAD_SCOPE_SYSTEM;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set contention scope attribute.
 *
 * This service set to @a scope the value of the @a scope attribute in the
 * attribute object @a attr.
 *
 * The @a scope attribute represents the scheduling contention scope of threads
 * created with the attribute object @a attr. This implementation only supports
 * the value PTHREAD_SCOPE_SYSTEM.
 *
 * @param attr attribute object;
 *
 * @param scope value of the @a scope attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - ENOTSUP, @a scope is an unsupported value of the scope attribute.
 * - EINVAL, @a attr is invalid.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/pthread_attr_setscope.html">
 * Specification.</a>
 * 
 */
int pthread_attr_setscope(pthread_attr_t * attr, int scope)
{
	spl_t s;

	if (scope != PTHREAD_SCOPE_SYSTEM)
		return ENOTSUP;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get name attribute.
 *
 * This service stores, at the address @a name, the value of the @a name
 * attribute in the attribute object @a attr.
 *
 * The @a name attribute is the name under which a thread created with the
 * attribute object @a attr will appear under /proc/xenomai/sched. 
 *
 * The name returned by this function is only valid until the name is changed
 * with pthread_attr_setname_np() or the @a attr object is destroyed with
 * pthread_attr_destroy().
 *
 * If @a name is @a NULL, a unique default name will be used.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param attr attribute object;
 *
 * @param name address where the value of the @a name attribute will be stored
 * on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - Xenomai kernel-space thread.
 */
int pthread_attr_getname_np(const pthread_attr_t * attr, const char **name)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*name = attr->name;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set name attribute.
 *
 * This service set to @a name, the value of the @a name attribute in the
 * attribute object @a attr.
 *
 * The @a name attribute is the name under which a thread created with the
 * attribute object @a attr will appear under /proc/xenomai/sched.
 *
 * If @a name is @a NULL, a unique default name will be used.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param attr attribute object;
 *
 * @param name value of the @a name attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid;
 * - ENOMEM, insufficient memory exists in the system heap to duplicate the name
 *   string, increase CONFIG_XENO_OPT_SYS_HEAPSZ.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - Xenomai kernel-space thread.
 */
int pthread_attr_setname_np(pthread_attr_t * attr, const char *name)
{
	char *old_name, *new_name;
	spl_t s;

	if (name) {
		new_name = xnmalloc(strlen(name) + 1);
		if (!new_name)
			return ENOMEM;

		strcpy(new_name, name);
	} else
		new_name = NULL;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		if (name)
			xnfree(new_name);
		return EINVAL;
	}

	old_name = attr->name;
	attr->name = new_name;
	xnlock_put_irqrestore(&nklock, s);

	if (old_name)
		xnfree(old_name);

	return 0;
}

/**
 * Get the floating point attribute.
 *
 * This service returns, at the address @a fp, the value of the @a fp attribute
 * in the attribute object @a attr.
 *
 * The @a fp attribute is a boolean attribute indicating whether a thread
 * created with the attribute @a attr may use floating-point hardware.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param attr attribute object;
 *
 * @param fp address where the value of the @a fp attribute will be stored on
 * success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - Xenomai kernel-space thread.
 */
int pthread_attr_getfp_np(const pthread_attr_t * attr, int *fp)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*fp = attr->fp;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the floating point attribute.
 *
 * This service set to @a fp, the value of the @a fp attribute in the attribute
 * object @a attr.
 *
 * The @a fp attribute is a boolean attribute indicating whether a thread
 * created with the attribute @a attr may use floating-point hardware.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param attr attribute object;
 *
 * @param fp value of the @a fp attribute.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - Xenomai kernel-space thread.
 */
int pthread_attr_setfp_np(pthread_attr_t * attr, int fp)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->fp = fp;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Get the processor affinity attribute.
 *
 * This service stores, at the address @a mask, the value of the @a affinity
 * attribute in the attribute object @a attr.
 *
 * The @a affinity attributes is a bitmask where bits set indicate processor
 * where a thread created with the attribute @a attr may run. The least
 * significant bit corresponds to the first logical processor.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param attr attribute object;
 *
 * @param mask address where the value of the @a affinity attribute will be
 * stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - Xenomai kernel-space thread.
 */
int
pthread_attr_getaffinity_np(const pthread_attr_t * attr, xnarch_cpumask_t *mask)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	*mask = attr->affinity;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set the processor affinity attribute.
 *
 * This service sets to @a mask, the value of the @a affinity attribute in the
 * attribute object @a attr.
 *
 * The @a affinity attributes is a bitmask where bits set indicate processor
 * where a thread created with the attribute @a attr may run. The least
 * significant bit corresponds to the first logical processor.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param attr attribute object;
 *
 * @param mask address where the value of the @a affinity attribute will be
 * stored on success.
 *
 * @return 0 on success;
 * @return an error number if:
 * - EINVAL, @a attr is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - Xenomai kernel-space thread.
 */
int pthread_attr_setaffinity_np(pthread_attr_t * attr, xnarch_cpumask_t mask)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(attr, PSE51_THREAD_ATTR_MAGIC, pthread_attr_t)) {
		xnlock_put_irqrestore(&nklock, s);
		return EINVAL;
	}

	attr->affinity = mask;

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/*@}*/

EXPORT_SYMBOL(pthread_attr_init);
EXPORT_SYMBOL(pthread_attr_destroy);
EXPORT_SYMBOL(pthread_attr_getdetachstate);
EXPORT_SYMBOL(pthread_attr_setdetachstate);
EXPORT_SYMBOL(pthread_attr_getstacksize);
EXPORT_SYMBOL(pthread_attr_setstacksize);
EXPORT_SYMBOL(pthread_attr_getinheritsched);
EXPORT_SYMBOL(pthread_attr_setinheritsched);
EXPORT_SYMBOL(pthread_attr_getschedpolicy);
EXPORT_SYMBOL(pthread_attr_setschedpolicy);
EXPORT_SYMBOL(pthread_attr_getschedparam);
EXPORT_SYMBOL(pthread_attr_setschedparam);
EXPORT_SYMBOL(pthread_attr_getscope);
EXPORT_SYMBOL(pthread_attr_setscope);
EXPORT_SYMBOL(pthread_attr_getname_np);
EXPORT_SYMBOL(pthread_attr_setname_np);
EXPORT_SYMBOL(pthread_attr_getfp_np);
EXPORT_SYMBOL(pthread_attr_setfp_np);
EXPORT_SYMBOL(pthread_attr_getaffinity_np);
EXPORT_SYMBOL(pthread_attr_setaffinity_np);
