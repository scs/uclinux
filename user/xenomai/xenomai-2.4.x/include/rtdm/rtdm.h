/**
 * @file
 * Real-Time Driver Model for Xenomai, user API header
 *
 * @note Copyright (C) 2005, 2006 Jan Kiszka <jan.kiszka@web.de>
 * @note Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
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
 * @ingroup userapi
 */

/*!
 * @defgroup rtdm Real-Time Driver Model
 *
 * The Real-Time Driver Model (RTDM) provides a unified interface to
 * both users and developers of real-time device
 * drivers. Specifically, it addresses the constraints of mixed
 * RT/non-RT systems like Xenomai. RTDM conforms to POSIX
 * semantics (IEEE Std 1003.1) where available and applicable.
 *
 * @b API @b Revision: 7
 */

/*!
 * @ingroup rtdm
 * @defgroup userapi User API
 *
 * This is the upper interface of RTDM provided to application programs both
 * in kernel and user space. Note that certain functions may not be
 * implemented by every device. Refer to the @ref profiles "Device Profiles"
 * for precise information.
 */

#ifndef _RTDM_H
#define _RTDM_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/ioctl.h>
#include <linux/sched.h>
#include <linux/socket.h>

typedef u32 socklen_t;
typedef struct task_struct rtdm_user_info_t;

#else /* !__KERNEL__ */

#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#endif /* !__KERNEL__ */

/*!
 * @addtogroup rtdm
 * @{
 */

/*!
 * @anchor api_versioning @name API Versioning
 * @{ */
/** Common user and driver API version */
#define RTDM_API_VER			7

/** Minimum API revision compatible with the current release */
#define RTDM_API_MIN_COMPAT_VER		6
/** @} API Versioning */

/** RTDM type for representing absolute dates. Its base type is a 64 bit
 *  unsigned integer. The unit is 1 nanosecond. */
typedef uint64_t nanosecs_abs_t;

/** RTDM type for representing relative intervals. Its base type is a 64 bit
 *  signed integer. The unit is 1 nanosecond. Relative intervals can also
 *  encode the special timeouts "infinite" and "non-blocking", see
 *  @ref RTDM_TIMEOUT_xxx. */
typedef int64_t nanosecs_rel_t;

/*!
 * @anchor RTDM_TIMEOUT_xxx @name RTDM_TIMEOUT_xxx
 * Special timeout values
 * @{ */
/** Block forever. */
#define RTDM_TIMEOUT_INFINITE		0

/** Any negative timeout means non-blocking. */
#define RTDM_TIMEOUT_NONE		(-1)
/** @} RTDM_TIMEOUT_xxx */
/** @} rtdm */

/*!
 * @addtogroup profiles
 * @{
 */

/*!
 * @anchor RTDM_CLASS_xxx   @name RTDM_CLASS_xxx
 * Device classes
 * @{ */
#define RTDM_CLASS_PARPORT		1
#define RTDM_CLASS_SERIAL		2
#define RTDM_CLASS_CAN			3
#define RTDM_CLASS_NETWORK		4
#define RTDM_CLASS_RTMAC		5
#define RTDM_CLASS_TESTING		6
/*
#define RTDM_CLASS_USB			?
#define RTDM_CLASS_FIREWIRE		?
#define RTDM_CLASS_INTERBUS		?
#define RTDM_CLASS_PROFIBUS		?
#define ...
*/
#define RTDM_CLASS_EXPERIMENTAL		224
#define RTDM_CLASS_MAX			255
/** @} RTDM_CLASS_xxx */

#define RTDM_SUBCLASS_GENERIC		(-1)

#define RTIOC_TYPE_COMMON		0

/*!
 * @anchor device_naming    @name Device Naming
 * Maximum length of device names (excluding the final null character)
 * @{
 */
#define RTDM_MAX_DEVNAME_LEN		31
/** @} Device Naming */

/**
 * Device information
 */
typedef struct rtdm_device_info {
	/** Device flags, see @ref dev_flags "Device Flags" for details */
	int device_flags;

	/** Device class ID, see @ref RTDM_CLASS_xxx */
	int device_class;

	/** Device sub-class, either RTDM_SUBCLASS_GENERIC or a
	 *  RTDM_SUBCLASS_xxx definition of the related @ref profiles
	 *  "Device Profile" */
	int device_sub_class;

	/** Supported device profile version */
	int profile_version;
} rtdm_device_info_t;

/*!
 * @anchor RTDM_PURGE_xxx_BUFFER    @name RTDM_PURGE_xxx_BUFFER
 * Flags selecting buffers to be purged
 * @{ */
#define RTDM_PURGE_RX_BUFFER		0x0001
#define RTDM_PURGE_TX_BUFFER		0x0002
/** @} RTDM_PURGE_xxx_BUFFER*/

/*!
 * @anchor common_IOCTLs    @name Common IOCTLs
 * The following IOCTLs are common to all device profiles.
 * @{
 */

/**
 * Retrieve information about a device or socket.
 * @param[out] arg Pointer to information buffer (struct rtdm_device_info)
 */
#define RTIOC_DEVICE_INFO \
	_IOR(RTIOC_TYPE_COMMON, 0x00, struct rtdm_device_info)

/**
 * Purge internal device or socket buffers.
 * @param[in] arg Purge mask, see @ref RTDM_PURGE_xxx_BUFFER
 */
#define RTIOC_PURGE		_IOW(RTIOC_TYPE_COMMON, 0x10, int)
/** @} Common IOCTLs */
/** @} rtdm */

/* Internally used for mapping socket functions on IOCTLs */
struct _rtdm_getsockopt_args {
	int level;
	int optname;
	void *optval;
	socklen_t *optlen;
};

struct _rtdm_setsockopt_args {
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

struct _rtdm_getsockaddr_args {
	struct sockaddr *addr;
	socklen_t *addrlen;
};

struct _rtdm_setsockaddr_args {
	const struct sockaddr *addr;
	socklen_t addrlen;
};

#define _RTIOC_GETSOCKOPT	_IOW(RTIOC_TYPE_COMMON, 0x20,		\
				     struct _rtdm_getsockopt_args)
#define _RTIOC_SETSOCKOPT	_IOW(RTIOC_TYPE_COMMON, 0x21,		\
				     struct _rtdm_setsockopt_args)
#define _RTIOC_BIND		_IOW(RTIOC_TYPE_COMMON, 0x22,		\
				     struct _rtdm_setsockaddr_args)
#define _RTIOC_CONNECT		_IOW(RTIOC_TYPE_COMMON, 0x23,		\
				     struct _rtdm_setsockaddr_args)
#define _RTIOC_LISTEN		_IOW(RTIOC_TYPE_COMMON, 0x24,		\
				     int)
#define _RTIOC_ACCEPT		_IOW(RTIOC_TYPE_COMMON, 0x25,		\
				     struct _rtdm_getsockaddr_args)
#define _RTIOC_GETSOCKNAME	_IOW(RTIOC_TYPE_COMMON, 0x26,		\
				     struct _rtdm_getsockaddr_args)
#define _RTIOC_GETPEERNAME	_IOW(RTIOC_TYPE_COMMON, 0x27,		\
				     struct _rtdm_getsockaddr_args)
#define _RTIOC_SHUTDOWN		_IOW(RTIOC_TYPE_COMMON, 0x28,		\
				     int)

#ifdef __KERNEL__
int __rt_dev_open(rtdm_user_info_t *user_info, const char *path, int oflag);
int __rt_dev_socket(rtdm_user_info_t *user_info, int protocol_family,
		    int socket_type, int protocol);
int __rt_dev_close(rtdm_user_info_t *user_info, int fd);
int __rt_dev_ioctl(rtdm_user_info_t *user_info, int fd, int request, ...);
ssize_t __rt_dev_read(rtdm_user_info_t *user_info, int fd, void *buf,
		      size_t nbyte);
ssize_t __rt_dev_write(rtdm_user_info_t *user_info, int fd, const void *buf,
		       size_t nbyte);
ssize_t __rt_dev_recvmsg(rtdm_user_info_t *user_info, int fd,
			 struct msghdr *msg, int flags);
ssize_t __rt_dev_sendmsg(rtdm_user_info_t *user_info, int fd,
			 const struct msghdr *msg, int flags);
#endif /* __KERNEL__ */

/* Define RTDM_NO_DEFAULT_USER_API to switch off the default rt_dev_xxx
 * interface when providing a customised user API */
#ifndef RTDM_NO_DEFAULT_USER_API

#ifdef __KERNEL__

#define rt_dev_open(path, oflag, ...)				\
	__rt_dev_open(NULL, path, oflag)

#define rt_dev_socket(protocol_family, socket_type, protocol)	\
	__rt_dev_socket(NULL, protocol_family, socket_type, protocol)

#define rt_dev_close(fd)					\
	__rt_dev_close(NULL, fd)

#define rt_dev_ioctl(fd, request, ...)				\
	__rt_dev_ioctl(NULL, fd, request, __VA_ARGS__)

#define rt_dev_read(fd, buf, nbyte)				\
	__rt_dev_read(NULL, fd, buf, nbyte)

#define rt_dev_write(fd, buf, nbyte)				\
	__rt_dev_write(NULL, fd, buf, nbyte)

#define rt_dev_recvmsg(fd, msg, flags)				\
	__rt_dev_recvmsg(NULL, fd, msg, flags)

#define rt_dev_sendmsg(fd, msg, flags)				\
	__rt_dev_sendmsg(NULL, fd, msg, flags)

static inline ssize_t rt_dev_recvfrom(int fd, void *buf, size_t len, int flags,
				      struct sockaddr *from,
				      socklen_t *fromlen)
{
	struct iovec iov;
	struct msghdr msg;
	int ret;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_name = from;
	msg.msg_namelen = from ? *fromlen : 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	ret = rt_dev_recvmsg(fd, &msg, flags);
	if (ret >= 0 && from)
		*fromlen = msg.msg_namelen;
	return ret;
}

#else /* !__KERNEL__ */

#ifdef __cplusplus
extern "C" {
#endif

int rt_dev_open(const char *path, int oflag, ...);
int rt_dev_socket(int protocol_family, int socket_type, int protocol);
int rt_dev_close(int fd);
int rt_dev_ioctl(int fd, int request, ...);
ssize_t rt_dev_read(int fd, void *buf, size_t nbyte);
ssize_t rt_dev_write(int fd, const void *buf, size_t nbyte);
ssize_t rt_dev_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t rt_dev_sendmsg(int fd, const struct msghdr *msg, int flags);

ssize_t rt_dev_recvfrom(int fd, void *buf, size_t len, int flags,
			struct sockaddr *from, socklen_t *fromlen);

#ifdef __cplusplus
}
#endif

#endif /* !__KERNEL__ */

#ifdef __cplusplus
extern "C" {
#endif

static inline ssize_t rt_dev_recv(int fd, void *buf, size_t len, int flags)
{
	return rt_dev_recvfrom(fd, buf, len, flags, NULL, NULL);
}

static inline ssize_t rt_dev_sendto(int fd, const void *buf, size_t len,
				    int flags, const struct sockaddr *to,
				    socklen_t tolen)
{
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	msg.msg_name = (struct sockaddr *)to;
	msg.msg_namelen = tolen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	return rt_dev_sendmsg(fd, &msg, flags);
}

static inline ssize_t rt_dev_send(int fd, const void *buf, size_t len,
				  int flags)
{
	return rt_dev_sendto(fd, buf, len, flags, NULL, 0);
}

static inline int rt_dev_getsockopt(int fd, int level, int optname,
				    void *optval, socklen_t *optlen)
{
	struct _rtdm_getsockopt_args args =
		{ level, optname, optval, optlen };

	return rt_dev_ioctl(fd, _RTIOC_GETSOCKOPT, &args);
}

static inline int rt_dev_setsockopt(int fd, int level, int optname,
				    const void *optval, socklen_t optlen)
{
	struct _rtdm_setsockopt_args args =
		{ level, optname, (void *)optval, optlen };

	return rt_dev_ioctl(fd, _RTIOC_SETSOCKOPT, &args);
}

static inline int rt_dev_bind(int fd, const struct sockaddr *my_addr,
			      socklen_t addrlen)
{
	struct _rtdm_setsockaddr_args args = { my_addr, addrlen };

	return rt_dev_ioctl(fd, _RTIOC_BIND, &args);
}

static inline int rt_dev_connect(int fd, const struct sockaddr *serv_addr,
				 socklen_t addrlen)
{
	struct _rtdm_setsockaddr_args args = { serv_addr, addrlen };

	return rt_dev_ioctl(fd, _RTIOC_CONNECT, &args);
}

static inline int rt_dev_listen(int fd, int backlog)
{
	return rt_dev_ioctl(fd, _RTIOC_LISTEN, backlog);
}

static inline int rt_dev_accept(int fd, struct sockaddr *addr,
				socklen_t *addrlen)
{
	struct _rtdm_getsockaddr_args args = { addr, addrlen };

	return rt_dev_ioctl(fd, _RTIOC_ACCEPT, &args);
}

static inline int rt_dev_getsockname(int fd, struct sockaddr *name,
				     socklen_t *namelen)
{
	struct _rtdm_getsockaddr_args args = { name, namelen };

	return rt_dev_ioctl(fd, _RTIOC_GETSOCKNAME, &args);
}

static inline int rt_dev_getpeername(int fd, struct sockaddr *name,
				     socklen_t *namelen)
{
	struct _rtdm_getsockaddr_args args = { name, namelen };

	return rt_dev_ioctl(fd, _RTIOC_GETPEERNAME, &args);
}

static inline int rt_dev_shutdown(int fd, int how)
{
	return rt_dev_ioctl(fd, _RTIOC_SHUTDOWN, how);
}

#ifdef __cplusplus
}
#endif

#endif /* RTDM_NO_DEFAULT_USER_API */

#endif /* _RTDM_H */
