/**
 * @file
 * Real-Time Driver Model for Xenomai, driver API header
 *
 * @note Copyright (C) 2005-2007 Jan Kiszka <jan.kiszka@web.de>
 * @note Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
 * @note Copyright (C) 2008 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * @ingroup driverapi
 */

#ifndef _RTDM_DRIVER_H
#define _RTDM_DRIVER_H

#ifndef __KERNEL__
#error This header is for kernel space usage only. \
       You are likely looking for rtdm/rtdm.h...
#endif /* !__KERNEL__ */

#include <asm/atomic.h>
#include <linux/list.h>

#include <nucleus/xenomai.h>
#include <nucleus/core.h>
#include <nucleus/heap.h>
#include <nucleus/pod.h>
#include <nucleus/synch.h>
#include <nucleus/select.h>
#include <rtdm/rtdm.h>

/* debug support */
#include <nucleus/assert.h>

#ifndef CONFIG_XENO_OPT_DEBUG_RTDM
#define CONFIG_XENO_OPT_DEBUG_RTDM	0
#endif

struct rtdm_dev_context;
typedef struct xnselector rtdm_selector_t;
enum rtdm_selecttype;

/*!
 * @addtogroup devregister
 * @{
 */

/*!
 * @anchor dev_flags @name Device Flags
 * Static flags describing a RTDM device
 * @{
 */
/** If set, only a single instance of the device can be requested by an
 *  application. */
#define RTDM_EXCLUSIVE			0x0001

/** If set, the device is addressed via a clear-text name. */
#define RTDM_NAMED_DEVICE		0x0010

/** If set, the device is addressed via a combination of protocol ID and
 *  socket type. */
#define RTDM_PROTOCOL_DEVICE		0x0020

/** Mask selecting the device type. */
#define RTDM_DEVICE_TYPE_MASK		0x00F0
/** @} Device Flags */

/*!
 * @anchor ctx_flags @name Context Flags
 * Dynamic flags describing the state of an open RTDM device (bit numbers)
 * @{
 */
/** Set by RTDM if the device instance was created in non-real-time
 *  context. */
#define RTDM_CREATED_IN_NRT		0

/** Set by RTDM when the device is being closed. */
#define RTDM_CLOSING			1

/** Lowest bit number the driver developer can use freely */
#define RTDM_USER_CONTEXT_FLAG		8  /* first user-definable flag */
/** @} Context Flags */

/*!
 * @anchor drv_versioning @name Driver Versioning
 * Current revisions of RTDM structures, encoding of driver versions. See
 * @ref api_versioning "API Versioning" for the interface revision.
 * @{
 */
/** Version of struct rtdm_device */
#define RTDM_DEVICE_STRUCT_VER		5

/** Version of struct rtdm_dev_context */
#define RTDM_CONTEXT_STRUCT_VER		3

/** Flag indicating a secure variant of RTDM (not supported here) */
#define RTDM_SECURE_DEVICE		0x80000000

/** Version code constructor for driver revisions */
#define RTDM_DRIVER_VER(major, minor, patch) \
	(((major & 0xFF) << 16) | ((minor & 0xFF) << 8) | (patch & 0xFF))

/** Get major version number from driver revision code */
#define RTDM_DRIVER_MAJOR_VER(ver)	(((ver) >> 16) & 0xFF)

/** Get minor version number from driver revision code */
#define RTDM_DRIVER_MINOR_VER(ver)	(((ver) >> 8) & 0xFF)

/** Get patch version number from driver revision code */
#define RTDM_DRIVER_PATCH_VER(ver)	((ver) & 0xFF)
/** @} Driver Versioning */

/*!
 * @addtogroup rtdmsync
 * @{
 */

/*!
 * @anchor RTDM_SELECTTYPE_xxx   @name RTDM_SELECTTYPE_xxx
 * Event types select can bind to
 * @{
 */
enum rtdm_selecttype {
	/** Select input data availability events */
	RTDM_SELECTTYPE_READ = XNSELECT_READ,

	/** Select ouput buffer availability events */
	RTDM_SELECTTYPE_WRITE = XNSELECT_WRITE,

	/** Select exceptional events */
	RTDM_SELECTTYPE_EXCEPT = XNSELECT_EXCEPT
};
/** @} RTDM_SELECTTYPE_xxx */

/** @} rtdmsync */

/*!
 * @name Operation Handler Prototypes
 * @{
 */

/**
 * Named device open handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[in] oflag Open flags as passed by the user
 *
 * @return 0 on success, otherwise negative error code
 *
 * @see @c open() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef int (*rtdm_open_handler_t)(struct rtdm_dev_context *context,
				   rtdm_user_info_t *user_info, int oflag);

/**
 * Socket creation handler for protocol devices
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[in] protocol Protocol number as passed by the user
 *
 * @return 0 on success, otherwise negative error code
 *
 * @see @c socket() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef int (*rtdm_socket_handler_t)(struct rtdm_dev_context *context,
				     rtdm_user_info_t *user_info, int protocol);

/**
 * Close handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 *
 * @return 0 on success, otherwise negative error code
 *
 * @see @c close() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef int (*rtdm_close_handler_t)(struct rtdm_dev_context *context,
				    rtdm_user_info_t *user_info);

/**
 * IOCTL handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[in] request Request number as passed by the user
 * @param[in,out] arg Request argument as passed by the user
 *
 * @return Positiv value on success, otherwise negative error code
 *
 * @see @c ioctl() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef int (*rtdm_ioctl_handler_t)(struct rtdm_dev_context *context,
				    rtdm_user_info_t *user_info,
				    unsigned int request, void __user *arg);

/**
 * Select binding handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in,out] selector Object that shall be bound to the given event
 * @param[in] type Event type the selector is interested in
 * @param[in] fd_index Opaque value, to be passed to rtdm_event_select_bind or
 * rtdm_sem_select_bind unmodfied
 *
 * @return 0 on success, otherwise negative error code
 */
typedef int (*rtdm_select_bind_handler_t)(struct rtdm_dev_context *context,
					  rtdm_selector_t *selector,
					  enum rtdm_selecttype type,
					  unsigned fd_index);

/**
 * Read handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[out] buf Input buffer as passed by the user
 * @param[in] nbyte Number of bytes the user requests to read
 *
 * @return On success, the number of bytes read, otherwise negative error code
 *
 * @see @c read() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef ssize_t (*rtdm_read_handler_t)(struct rtdm_dev_context *context,
				       rtdm_user_info_t *user_info,
				       void *buf, size_t nbyte);

/**
 * Write handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[in] buf Output buffer as passed by the user
 * @param[in] nbyte Number of bytes the user requests to write
 *
 * @return On success, the number of bytes written, otherwise negative error
 * code
 *
 * @see @c write() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef ssize_t (*rtdm_write_handler_t)(struct rtdm_dev_context *context,
					rtdm_user_info_t *user_info,
					const void *buf, size_t nbyte);

/**
 * Receive message handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[in,out] msg Message descriptor as passed by the user, automatically
 * mirrored to safe kernel memory in case of user mode call
 * @param[in] flags Message flags as passed by the user
 *
 * @return On success, the number of bytes received, otherwise negative error
 * code
 *
 * @see @c recvmsg() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef ssize_t (*rtdm_recvmsg_handler_t)(struct rtdm_dev_context *context,
					  rtdm_user_info_t *user_info,
					  struct msghdr *msg, int flags);

/**
 * Transmit message handler
 *
 * @param[in] context Context structure associated with opened device instance
 * @param[in] user_info Opaque pointer to information about user mode caller,
 * NULL if kernel mode call
 * @param[in] msg Message descriptor as passed by the user, automatically
 * mirrored to safe kernel memory in case of user mode call
 * @param[in] flags Message flags as passed by the user
 *
 * @return On success, the number of bytes transmitted, otherwise negative
 * error code
 *
 * @see @c sendmsg() in IEEE Std 1003.1,
 * http://www.opengroup.org/onlinepubs/009695399 */
typedef ssize_t (*rtdm_sendmsg_handler_t)(struct rtdm_dev_context *context,
					  rtdm_user_info_t *user_info,
					  const struct msghdr *msg, int flags);
/** @} Operation Handler Prototypes */

typedef int (*rtdm_rt_handler_t)(struct rtdm_dev_context *context,
				 rtdm_user_info_t *user_info, void *arg);
/**
 * Device operations
 */
struct rtdm_operations {
	/*! @name Common Operations
	 * @{ */
	/** Close handler for real-time contexts (optional) */
	rtdm_close_handler_t close_rt;
	/** Close handler for non-real-time contexts (required) */
	rtdm_close_handler_t close_nrt;

	/** IOCTL from real-time context (optional) */
	rtdm_ioctl_handler_t ioctl_rt;
	/** IOCTL from non-real-time context (optional) */
	rtdm_ioctl_handler_t ioctl_nrt;

	/** Select binding handler for any context (optional) */
	rtdm_select_bind_handler_t select_bind;
	/** @} Common Operations */

	/*! @name Stream-Oriented Device Operations
	 * @{ */
	/** Read handler for real-time context (optional) */
	rtdm_read_handler_t read_rt;
	/** Read handler for non-real-time context (optional) */
	rtdm_read_handler_t read_nrt;

	/** Write handler for real-time context (optional) */
	rtdm_write_handler_t write_rt;
	/** Write handler for non-real-time context (optional) */
	rtdm_write_handler_t write_nrt;
	/** @} Stream-Oriented Device Operations */

	/*! @name Message-Oriented Device Operations
	 * @{ */
	/** Receive message handler for real-time context (optional) */
	rtdm_recvmsg_handler_t recvmsg_rt;
	/** Receive message handler for non-real-time context (optional) */
	rtdm_recvmsg_handler_t recvmsg_nrt;

	/** Transmit message handler for real-time context (optional) */
	rtdm_sendmsg_handler_t sendmsg_rt;
	/** Transmit message handler for non-real-time context (optional) */
	rtdm_sendmsg_handler_t sendmsg_nrt;
	/** @} Message-Oriented Device Operations */
};

struct rtdm_devctx_reserved {
	void *owner;
};

/**
 * @brief Device context
 *
 * A device context structure is associated with every open device instance.
 * RTDM takes care of its creation and destruction and passes it to the
 * operation handlers when being invoked.
 *
 * Drivers can attach arbitrary data immediately after the official structure.
 * The size of this data is provided via rtdm_device.context_size during
 * device registration.
 */
struct rtdm_dev_context {
	/** Context flags, see @ref ctx_flags "Context Flags" for details */
	unsigned long context_flags;

	/** Associated file descriptor */
	int fd;

	/** Lock counter of context, held while structure is referenced by an
	 *  operation handler */
	atomic_t close_lock_count;

	/** Set of active device operation handlers */
	struct rtdm_operations *ops;

	/** Reference to owning device */
	struct rtdm_device *device;

	/** Data stored by RTDM inside a device context (internal use only) */
	struct rtdm_devctx_reserved reserved;

	/** Begin of driver defined context data structure */
	char dev_private[0];
};

struct rtdm_dev_reserved {
	struct list_head entry;
	atomic_t refcount;
	struct rtdm_dev_context *exclusive_context;
};

/**
 * @brief RTDM device
 *
 * This structure specifies a RTDM device. As some fields, especially the
 * reserved area, will be modified by RTDM during runtime, the structure must
 * not reside in write-protected memory.
 */
struct rtdm_device {
	/** Revision number of this structure, see
	 *  @ref drv_versioning "Driver Versioning" defines */
	int struct_version;

	/** Device flags, see @ref dev_flags "Device Flags" for details */
	int device_flags;
	/** Size of driver defined appendix to struct rtdm_dev_context */
	size_t context_size;

	/** Named device identification (orthogonal to Linux device name space) */
	char device_name[RTDM_MAX_DEVNAME_LEN + 1];

	/** Protocol device identification: protocol family (PF_xxx) */
	int protocol_family;
	/** Protocol device identification: socket type (SOCK_xxx) */
	int socket_type;

	/** Named device instance creation for real-time contexts,
	 *  optional if open_nrt is non-NULL, ignored for protocol devices */
	rtdm_open_handler_t open_rt;
	/** Named device instance creation for non-real-time contexts,
	 *  optional if open_rt is non-NULL, ignored for protocol devices */
	rtdm_open_handler_t open_nrt;

	/** Protocol socket creation for real-time contexts,
	 *  optional if socket_nrt is non-NULL, ignored for named devices */
	rtdm_socket_handler_t socket_rt;
	/** Protocol socket creation for non-real-time contexts,
	 *  optional if socket_rt is non-NULL, ignored for named devices */
	rtdm_socket_handler_t socket_nrt;

	/** Default operations on newly opened device instance */
	struct rtdm_operations ops;

	/** Device class ID, see @ref RTDM_CLASS_xxx */
	int device_class;
	/** Device sub-class, see RTDM_SUBCLASS_xxx definition in the
	 *  @ref profiles "Device Profiles" */
	int device_sub_class;
	/** Supported device profile version */
	int profile_version;
	/** Informational driver name (reported via /proc) */
	const char *driver_name;
	/** Driver version, see @ref drv_versioning "Driver Versioning" defines */
	int driver_version;
	/** Informational peripheral name the device is attached to
	 *  (reported via /proc) */
	const char *peripheral_name;
	/** Informational driver provider name (reported via /proc) */
	const char *provider_name;

	/** Name of /proc entry for the device, must not be NULL */
	const char *proc_name;
	/** Set to device's /proc root entry after registration, do not modify */
	struct proc_dir_entry *proc_entry;

	/** Driver definable device ID */
	int device_id;
	/** Driver definable device data */
	void *device_data;

	/** Data stored by RTDM inside a registered device (internal use only) */
	struct rtdm_dev_reserved reserved;
};
/** @} devregister */

/* --- device registration --- */

int rtdm_dev_register(struct rtdm_device *device);
int rtdm_dev_unregister(struct rtdm_device *device, unsigned int poll_delay);

/* --- inter-driver API --- */

#define rtdm_open		rt_dev_open
#define rtdm_socket		rt_dev_socket
#define rtdm_close		rt_dev_close
#define rtdm_ioctl		rt_dev_ioctl
#define rtdm_read		rt_dev_read
#define rtdm_write		rt_dev_write
#define rtdm_recvmsg		rt_dev_recvmsg
#define rtdm_recv		rt_dev_recv
#define rtdm_recvfrom		rt_dev_recvfrom
#define rtdm_sendmsg		rt_dev_sendmsg
#define rtdm_send		rt_dev_send
#define rtdm_sendto		rt_dev_sendto
#define rtdm_bind		rt_dev_bind
#define rtdm_listen		rt_dev_listen
#define rtdm_accept		rt_dev_accept
#define rtdm_getsockopt		rt_dev_getsockopt
#define rtdm_setsockopt		rt_dev_setsockopt
#define rtdm_getsockname	rt_dev_getsockname
#define rtdm_getpeername	rt_dev_getpeername
#define rtdm_shutdown		rt_dev_shutdown

struct rtdm_dev_context *rtdm_context_get(int fd);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline void rtdm_context_lock(struct rtdm_dev_context *context)
{
	atomic_inc(&context->close_lock_count);
}

static inline void rtdm_context_unlock(struct rtdm_dev_context *context)
{
	atomic_dec(&context->close_lock_count);
}

/* --- clock services --- */
struct xntbase;
extern struct xntbase *rtdm_tbase;

static inline nanosecs_abs_t rtdm_clock_read(void)
{
	return xntbase_ticks2ns(rtdm_tbase, xntbase_get_time(rtdm_tbase));
}

static inline nanosecs_abs_t rtdm_clock_read_monotonic(void)
{
	return xntbase_ticks2ns(rtdm_tbase, xntbase_get_jiffies(rtdm_tbase));
}
#endif /* !DOXYGEN_CPP */

/*!
 * @addtogroup rtdmsync
 * @{
 */

int rtdm_select_bind(int fd, rtdm_selector_t *selector,
		     enum rtdm_selecttype type, unsigned fd_index);

/* --- spin lock services --- */
/*!
 * @name Global Lock across Scheduler Invocation
 * @{
 */

/**
 * @brief Execute code block atomically
 *
 * Generally, it is illegal to suspend the current task by calling
 * rtdm_task_sleep(), rtdm_event_wait(), etc. while holding a spinlock. In
 * contrast, this macro allows to combine several operations including
 * a potentially rescheduling call to an atomic code block with respect to
 * other RTDM_EXECUTE_ATOMICALLY() blocks. The macro is a light-weight
 * alternative for protecting code blocks via mutexes, and it can even be used
 * to synchronise real-time and non-real-time contexts.
 *
 * @param code_block Commands to be executed atomically
 *
 * @note It is not allowed to leave the code block explicitly by using
 * @c break, @c return, @c goto, etc. This would leave the global lock held
 * during the code block execution in an inconsistent state. Moreover, do not
 * embed complex operations into the code bock. Consider that they will be
 * executed under preemption lock with interrupts switched-off. Also note that
 * invocation of rescheduling calls may break the atomicity until the task
 * gains the CPU again.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: possible, depends on functions called within @a code_block.
 */
#ifdef DOXYGEN_CPP /* Beautify doxygen output */
#define RTDM_EXECUTE_ATOMICALLY(code_block)	\
{						\
	<ENTER_ATOMIC_SECTION>			\
	code_block;				\
	<LEAVE_ATOMIC_SECTION>			\
}
#else /* This is how it really works */
#define RTDM_EXECUTE_ATOMICALLY(code_block)	\
{						\
	spl_t s;				\
						\
	xnlock_get_irqsave(&nklock, s);		\
	code_block;				\
	xnlock_put_irqrestore(&nklock, s);	\
}
#endif
/** @} Global Lock across Scheduler Invocation */

/*!
 * @name Spinlock with Preemption Deactivation
 * @{
 */

/**
 * Static lock initialisation
 */
#define RTDM_LOCK_UNLOCKED	RTHAL_SPIN_LOCK_UNLOCKED

/** Lock variable */
typedef rthal_spinlock_t rtdm_lock_t;

/** Variable to save the context while holding a lock */
typedef unsigned long rtdm_lockctx_t;

/**
 * Dynamic lock initialisation
 *
 * @param lock Address of lock variable
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: never.
 */
#define rtdm_lock_init(lock)	rthal_spin_lock_init(lock)

/**
 * Acquire lock from non-preemptible contexts
 *
 * @param lock Address of lock variable
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: never.
 */
#define rtdm_lock_get(lock)	rthal_spin_lock(lock)

/**
 * Release lock without preemption restoration
 *
 * @param lock Address of lock variable
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: never.
 */
#define rtdm_lock_put(lock)	rthal_spin_unlock(lock)

/**
 * Acquire lock and disable preemption
 *
 * @param lock Address of lock variable
 * @param context name of local variable to store the context in
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: never.
 */
#define rtdm_lock_get_irqsave(lock, context)	\
	rthal_spin_lock_irqsave(lock, context)

/**
 * Release lock and restore preemption state
 *
 * @param lock Address of lock variable
 * @param context name of local variable which stored the context
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: possible.
 */
#define rtdm_lock_put_irqrestore(lock, context)	\
	rthal_spin_unlock_irqrestore(lock, context)

/**
 * Disable preemption locally
 *
 * @param context name of local variable to store the context in
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: never.
 */
#define rtdm_lock_irqsave(context)	\
	rthal_local_irq_save(context)

/**
 * Restore preemption state
 *
 * @param context name of local variable which stored the context
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: possible.
 */
#define rtdm_lock_irqrestore(context)	\
	rthal_local_irq_restore(context)
/** @} Spinlock with Preemption Deactivation */

/** @} rtdmsync */

/* --- Interrupt management services --- */
/*!
 * @addtogroup rtdmirq
 * @{
 */

typedef xnintr_t rtdm_irq_t;

/*!
 * @anchor RTDM_IRQTYPE_xxx   @name RTDM_IRQTYPE_xxx
 * Interrupt registrations flags
 * @{
 */
/** Enable IRQ-sharing with other real-time drivers */
#define RTDM_IRQTYPE_SHARED		XN_ISR_SHARED
/** Mark IRQ as edge-triggered, relevant for correct handling of shared
 *  edge-triggered IRQs */
#define RTDM_IRQTYPE_EDGE		XN_ISR_EDGE
/** @} RTDM_IRQTYPE_xxx */

/**
 * Interrupt handler
 *
 * @param[in] irq_handle IRQ handle as returned by rtdm_irq_request()
 *
 * @return 0 or a combination of @ref RTDM_IRQ_xxx flags
 */
typedef int (*rtdm_irq_handler_t)(rtdm_irq_t *irq_handle);

/*!
 * @anchor RTDM_IRQ_xxx   @name RTDM_IRQ_xxx
 * Return flags of interrupt handlers
 * @{
 */
/** Unhandled interrupt */
#define RTDM_IRQ_NONE			XN_ISR_NONE
/** Denote handled interrupt */
#define RTDM_IRQ_HANDLED		XN_ISR_HANDLED
/** @} RTDM_IRQ_xxx */

/**
 * Retrieve IRQ handler argument
 *
 * @param irq_handle IRQ handle
 * @param type Type of the pointer to return
 *
 * @return The argument pointer registered on rtdm_irq_request() is returned,
 * type-casted to the specified @a type.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Interrupt service routine
 *
 * Rescheduling: never.
 */
#define rtdm_irq_get_arg(irq_handle, type)	((type *)irq_handle->cookie)
/** @} rtdmirq */

int rtdm_irq_request(rtdm_irq_t *irq_handle, unsigned int irq_no,
		     rtdm_irq_handler_t handler, unsigned long flags,
		     const char *device_name, void *arg);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline int rtdm_irq_free(rtdm_irq_t *irq_handle)
{
	return xnintr_detach(irq_handle);
}

static inline int rtdm_irq_enable(rtdm_irq_t *irq_handle)
{
	return xnintr_enable(irq_handle);
}

static inline int rtdm_irq_disable(rtdm_irq_t *irq_handle)
{
	return xnintr_disable(irq_handle);
}
#endif /* !DOXYGEN_CPP */

/* --- non-real-time signalling services --- */

/*!
 * @addtogroup nrtsignal
 * @{
 */

typedef unsigned rtdm_nrtsig_t;

/**
 * Non-real-time signal handler
 *
 * @param[in] nrt_sig Signal handle as returned by rtdm_nrtsig_init()
 * @param[in] arg Argument as passed to rtdm_nrtsig_init()
 *
 * @note The signal handler will run in soft-IRQ context of the non-real-time
 * subsystem. Note the implications of this context, e.g. no invocation of
 * blocking operations.
 */
typedef void (*rtdm_nrtsig_handler_t)(rtdm_nrtsig_t nrt_sig, void *arg);
/** @} nrtsignal */

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline int rtdm_nrtsig_init(rtdm_nrtsig_t *nrt_sig,
				   rtdm_nrtsig_handler_t handler, void *arg)
{
	*nrt_sig = rthal_alloc_virq();

	if (*nrt_sig == 0)
		return -EAGAIN;

	rthal_virtualize_irq(rthal_root_domain, *nrt_sig, handler, arg, NULL,
			     IPIPE_HANDLE_MASK);
	return 0;
}

static inline void rtdm_nrtsig_destroy(rtdm_nrtsig_t *nrt_sig)
{
	rthal_free_virq(*nrt_sig);
}

static inline void rtdm_nrtsig_pend(rtdm_nrtsig_t *nrt_sig)
{
	rthal_trigger_irq(*nrt_sig);
}
#endif /* !DOXYGEN_CPP */

/* --- timer services --- */

/*!
 * @addtogroup rtdmtimer
 * @{
 */

typedef xntimer_t rtdm_timer_t;

/**
 * Timer handler
 *
 * @param[in] timer Timer handle as returned by rtdm_timer_init()
 */
typedef void (*rtdm_timer_handler_t)(rtdm_timer_t *timer);

/*!
 * @anchor RTDM_TIMERMODE_xxx   @name RTDM_TIMERMODE_xxx
 * Timer operation modes
 * @{
 */
enum rtdm_timer_mode {
	/** Monotonic timer with relative timeout */
	RTDM_TIMERMODE_RELATIVE = XN_RELATIVE,

	/** Monotonic timer with absolute timeout */
	RTDM_TIMERMODE_ABSOLUTE = XN_ABSOLUTE,

	/** Adjustable timer with absolute timeout */
	RTDM_TIMERMODE_REALTIME = XN_REALTIME
};
/** @} RTDM_TIMERMODE_xxx */

/** @} rtdmtimer */

#ifndef DOXYGEN_CPP /* Avoid broken doxygen output */
#define rtdm_timer_init(timer, handler, name)		\
({							\
	xntimer_init((timer), rtdm_tbase, handler);	\
	xntimer_set_name((timer), (name));		\
	0;						\
})
#endif /* !DOXYGEN_CPP */

void rtdm_timer_destroy(rtdm_timer_t *timer);

int rtdm_timer_start(rtdm_timer_t *timer, nanosecs_abs_t expiry,
		     nanosecs_rel_t interval, enum rtdm_timer_mode mode);

void rtdm_timer_stop(rtdm_timer_t *timer);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline int rtdm_timer_start_in_handler(rtdm_timer_t *timer,
					      nanosecs_abs_t expiry,
					      nanosecs_rel_t interval,
					      enum rtdm_timer_mode mode)
{
	return xntimer_start(timer, xntbase_ns2ticks_ceil(rtdm_tbase, expiry),
			     xntbase_ns2ticks_ceil(rtdm_tbase, interval),
			     (xntmode_t)mode);
}

static inline void rtdm_timer_stop_in_handler(rtdm_timer_t *timer)
{
	xntimer_stop(timer);
}
#endif /* !DOXYGEN_CPP */

/* --- task services --- */
/*!
 * @addtogroup rtdmtask
 * @{
 */

typedef xnthread_t rtdm_task_t;

/**
 * Real-time task procedure
 *
 * @param[in,out] arg argument as passed to rtdm_task_init()
 */
typedef void (*rtdm_task_proc_t)(void *arg);

/*!
 * @anchor taskprio @name Task Priority Range
 * Maximum and minimum task priorities
 * @{ */
#define RTDM_TASK_LOWEST_PRIORITY	XNCORE_LOW_PRIO
#define RTDM_TASK_HIGHEST_PRIORITY	XNCORE_HIGH_PRIO
/** @} Task Priority Range */

/*!
 * @anchor changetaskprio @name Task Priority Modification
 * Raise or lower task priorities by one level
 * @{ */
#define RTDM_TASK_RAISE_PRIORITY	(+1)
#define RTDM_TASK_LOWER_PRIORITY	(-1)
/** @} Task Priority Modification */

/** @} rtdmtask */

int rtdm_task_init(rtdm_task_t *task, const char *name,
		   rtdm_task_proc_t task_proc, void *arg,
		   int priority, nanosecs_rel_t period);
int __rtdm_task_sleep(xnticks_t timeout, xntmode_t mode);
void rtdm_task_busy_sleep(nanosecs_rel_t delay);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline void rtdm_task_destroy(rtdm_task_t *task)
{
	xnpod_delete_thread(task);
}

void rtdm_task_join_nrt(rtdm_task_t *task, unsigned int poll_delay);

static inline void rtdm_task_set_priority(rtdm_task_t *task, int priority)
{
	xnpod_renice_thread(task, priority);
	xnpod_schedule();
}

static inline int rtdm_task_set_period(rtdm_task_t *task,
				       nanosecs_rel_t period)
{
	if (period < 0)
		period = 0;
	return xnpod_set_thread_periodic(task, XN_INFINITE,
					 xntbase_ns2ticks_ceil
					 (xnthread_time_base(task), period));
}

static inline int rtdm_task_unblock(rtdm_task_t *task)
{
	int res = xnpod_unblock_thread(task);

	xnpod_schedule();
	return res;
}

static inline rtdm_task_t *rtdm_task_current(void)
{
	return xnpod_current_thread();
}

static inline int rtdm_task_wait_period(void)
{
	XENO_ASSERT(RTDM, !xnpod_unblockable_p(), return -EPERM;);
	return xnpod_wait_thread_period(NULL);
}

static inline int rtdm_task_sleep(nanosecs_rel_t delay)
{
	return __rtdm_task_sleep(delay, XN_RELATIVE);
}

static inline int
rtdm_task_sleep_abs(nanosecs_abs_t wakeup_date, enum rtdm_timer_mode mode)
{
	/* For the sake of a consistent API usage... */
	if (mode != RTDM_TIMERMODE_ABSOLUTE && mode != RTDM_TIMERMODE_REALTIME)
		return -EINVAL;
	return __rtdm_task_sleep(wakeup_date, (xntmode_t)mode);
}

/* rtdm_task_sleep_abs shall be used instead */
static inline int __deprecated rtdm_task_sleep_until(nanosecs_abs_t wakeup_time)
{
	return __rtdm_task_sleep(wakeup_time, XN_REALTIME);
}
#endif /* !DOXYGEN_CPP */

/* --- timeout sequences */

typedef nanosecs_abs_t rtdm_toseq_t;

void rtdm_toseq_init(rtdm_toseq_t *timeout_seq, nanosecs_rel_t timeout);

/* --- event services --- */

typedef struct {
	xnsynch_t synch_base;
	DECLARE_XNSELECT(select_block);
} rtdm_event_t;

#define RTDM_EVENT_PENDING		XNSYNCH_SPARE1

void rtdm_event_init(rtdm_event_t *event, unsigned long pending);
#ifdef CONFIG_XENO_OPT_RTDM_SELECT
int rtdm_event_select_bind(rtdm_event_t *event, rtdm_selector_t *selector,
			   enum rtdm_selecttype type, unsigned fd_index);
#else /* !CONFIG_XENO_OPT_RTDM_SELECT */
#define rtdm_event_select_bind(e, s, t, i) ({ -EBADF; })
#endif /* !CONFIG_XENO_OPT_RTDM_SELECT */
int rtdm_event_wait(rtdm_event_t *event);
int rtdm_event_timedwait(rtdm_event_t *event, nanosecs_rel_t timeout,
			 rtdm_toseq_t *timeout_seq);
void rtdm_event_signal(rtdm_event_t *event);

void rtdm_event_clear(rtdm_event_t *event);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
void __rtdm_synch_flush(xnsynch_t *synch, unsigned long reason);

static inline void rtdm_event_pulse(rtdm_event_t *event)
{
	trace_mark(xn_rtdm_event_pulse, "event %p", event);
	__rtdm_synch_flush(&event->synch_base, 0);
}

static inline void rtdm_event_destroy(rtdm_event_t *event)
{
	trace_mark(xn_rtdm_event_destroy, "event %p", event);
	__rtdm_synch_flush(&event->synch_base, XNRMID);
	xnselect_destroy(&event->select_block);
}
#endif /* !DOXYGEN_CPP */

/* --- semaphore services --- */

typedef struct {
	unsigned long value;
	xnsynch_t synch_base;
	DECLARE_XNSELECT(select_block);
} rtdm_sem_t;

void rtdm_sem_init(rtdm_sem_t *sem, unsigned long value);
#ifdef CONFIG_XENO_OPT_RTDM_SELECT
int rtdm_sem_select_bind(rtdm_sem_t *sem, rtdm_selector_t *selector,
			 enum rtdm_selecttype type, unsigned fd_index);
#else /* !CONFIG_XENO_OPT_RTDM_SELECT */
#define rtdm_sem_select_bind(s, se, t, i) ({ -EBADF; })
#endif /* !CONFIG_XENO_OPT_RTDM_SELECT */
int rtdm_sem_down(rtdm_sem_t *sem);
int rtdm_sem_timeddown(rtdm_sem_t *sem, nanosecs_rel_t timeout,
		       rtdm_toseq_t *timeout_seq);
void rtdm_sem_up(rtdm_sem_t *sem);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline void rtdm_sem_destroy(rtdm_sem_t *sem)
{
	trace_mark(xn_rtdm_sem_destroy, "sem %p", sem);
	__rtdm_synch_flush(&sem->synch_base, XNRMID);
	xnselect_destroy(&sem->select_block);
}
#endif /* !DOXYGEN_CPP */

/* --- mutex services --- */

typedef struct {
	xnsynch_t synch_base;
} rtdm_mutex_t;

void rtdm_mutex_init(rtdm_mutex_t *mutex);
int rtdm_mutex_lock(rtdm_mutex_t *mutex);
int rtdm_mutex_timedlock(rtdm_mutex_t *mutex, nanosecs_rel_t timeout,
			 rtdm_toseq_t *timeout_seq);

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline void rtdm_mutex_unlock(rtdm_mutex_t *mutex)
{
	XENO_ASSERT(RTDM, !xnpod_asynch_p(), return;);

	trace_mark(xn_rtdm_mutex_unlock, "mutex %p", mutex);

	if (unlikely(xnsynch_wakeup_one_sleeper(&mutex->synch_base) != NULL))
		xnpod_schedule();
}

static inline void rtdm_mutex_destroy(rtdm_mutex_t *mutex)
{
	trace_mark(xn_rtdm_mutex_destroy, "mutex %p", mutex);

	__rtdm_synch_flush(&mutex->synch_base, XNRMID);
}
#endif /* !DOXYGEN_CPP */

/* --- utility functions --- */

#define rtdm_printk(format, ...)	printk(format, ##__VA_ARGS__)

#ifndef DOXYGEN_CPP /* Avoid static inline tags for RTDM in doxygen */
static inline void *rtdm_malloc(size_t size)
{
	return xnmalloc(size);
}

static inline void rtdm_free(void *ptr)
{
	xnfree(ptr);
}

#ifdef CONFIG_XENO_OPT_PERVASIVE
int rtdm_mmap_to_user(rtdm_user_info_t *user_info,
		      void *src_addr, size_t len,
		      int prot, void **pptr,
		      struct vm_operations_struct *vm_ops,
		      void *vm_private_data);
int rtdm_iomap_to_user(rtdm_user_info_t *user_info,
		       unsigned long src_addr, size_t len,
		       int prot, void **pptr,
		       struct vm_operations_struct *vm_ops,
		       void *vm_private_data);
int rtdm_munmap(rtdm_user_info_t *user_info, void *ptr, size_t len);

static inline int rtdm_read_user_ok(rtdm_user_info_t *user_info,
				    const void __user *ptr, size_t size)
{
	return __xn_access_ok(user_info, VERIFY_READ, ptr, size);
}

static inline int rtdm_rw_user_ok(rtdm_user_info_t *user_info,
				  const void __user *ptr, size_t size)
{
	return __xn_access_ok(user_info, VERIFY_WRITE, ptr, size);
}

static inline int rtdm_copy_from_user(rtdm_user_info_t *user_info,
				      void *dst, const void __user *src,
				      size_t size)
{
	return __xn_copy_from_user(user_info, dst, src, size) ? -EFAULT : 0;
}

static inline int rtdm_safe_copy_from_user(rtdm_user_info_t *user_info,
					   void *dst, const void __user *src,
					   size_t size)
{
	return (!__xn_access_ok(user_info, VERIFY_READ, src, size) ||
		__xn_copy_from_user(user_info, dst, src, size)) ? -EFAULT : 0;
}

static inline int rtdm_copy_to_user(rtdm_user_info_t *user_info,
				    void __user *dst, const void *src,
				    size_t size)
{
	return __xn_copy_to_user(user_info, dst, src, size) ? -EFAULT : 0;
}

static inline int rtdm_safe_copy_to_user(rtdm_user_info_t *user_info,
					 void __user *dst, const void *src,
					 size_t size)
{
	return (!__xn_access_ok(user_info, VERIFY_WRITE, dst, size) ||
		__xn_copy_to_user(user_info, dst, src, size)) ? -EFAULT : 0;
}

static inline int rtdm_strncpy_from_user(rtdm_user_info_t *user_info,
					 char *dst,
					 const char __user *src, size_t count)
{
	if (unlikely(!__xn_access_ok(user_info, VERIFY_READ, src, 1)))
		return -EFAULT;
	return __xn_strncpy_from_user(user_info, dst, src, count);
}
#else /* !CONFIG_XENO_OPT_PERVASIVE */
/* Define void user<->kernel services that simply fail */
#define rtdm_mmap_to_user(...)		({ -ENOSYS; })
#define rtdm_munmap(...)		({ -ENOSYS; })
#define rtdm_read_user_ok(...)		({ 0; })
#define rtdm_rw_user_ok(...)		({ 0; })
#define rtdm_copy_from_user(...)	({ -ENOSYS; })
#define rtdm_safe_copy_from_user(...)	({ -ENOSYS; })
#define rtdm_copy_to_user(...)		({ -ENOSYS; })
#define rtdm_safe_copy_to_user(...)	({ -ENOSYS; })
#define rtdm_strncpy_from_user(...)	({ -ENOSYS; })
#endif /* CONFIG_XENO_OPT_PERVASIVE */

static inline int rtdm_in_rt_context(void)
{
	return (rthal_current_domain != rthal_root_domain);
}
#endif /* !DOXYGEN_CPP */

int rtdm_exec_in_rt(struct rtdm_dev_context *context,
		    rtdm_user_info_t *user_info, void *arg,
		    rtdm_rt_handler_t handler);

#endif /* _RTDM_DRIVER_H */
