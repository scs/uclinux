/*
 * define path names
 *
 * $Id$
 */

#ifdef HAVE_PATHS_H
#include <paths.h>

#else
#define _PATH_DEVNULL	"/dev/null"
#endif

#ifdef PATH_ETC_CONFIG
#define _ROOT_PATH
#define _PATH_VARRUN 	"/var/run/"
#define _PATH_UPAPFILE 	"/etc/config/pap-secrets"
#define _PATH_CHAPFILE 	"/etc/config/chap-secrets"
#define _PATH_SYSOPTIONS "/etc/config/options"
#define _PATH_IPUP	"/etc/config/ip-up"
#define _PATH_DEFAULT_IPUP	"/etc/default/ip-up"
#define _PATH_IPDOWN	"/etc/config/ip-down"
#define _PATH_DEFAULT_IPDOWN	"/etc/default/ip-down"
#define _PATH_AUTHUP	"/bin/auth-up"
#define _PATH_AUTHDOWN	"/bin/auth-down"
#define _PATH_TTYOPT	"/etc/config/options."
#define _PATH_CONNERRS	"/var/log/connect-errors"
#define _PATH_USEROPT	".ppprc"
#define _PATH_PEERFILES	"/etc/config/peers/"
#define _PATH_RESOLV	"/etc/config/resolv.conf"
#define _PATH_TEMP      "/etc/config/resolv.XXXXXX"
#else
#define _ROOT_PATH
#define _PATH_VARRUN 	"/etc/ppp/"
#define _PATH_UPAPFILE 	"/etc/ppp/pap-secrets"
#define _PATH_CHAPFILE 	"/etc/ppp/chap-secrets"
#define _PATH_SYSOPTIONS "/etc/ppp/options"
#define _PATH_IPUP	"/etc/ppp/ip-up"
#define _PATH_IPDOWN	"/etc/ppp/ip-down"
#define _PATH_AUTHUP	"/etc/ppp/auth-up"
#define _PATH_AUTHDOWN	"/etc/ppp/auth-down"
#define _PATH_TTYOPT	"/etc/ppp/options."
#define _PATH_CONNERRS	"/etc/ppp/connect-errors"
#define _PATH_USEROPT	".ppprc"
#define _PATH_PEERFILES	"/etc/ppp/peers/"
#define _PATH_RESOLV	"/etc/ppp/resolv.conf"
#define _PATH_TEMP      "/etc/ppp/resolv.XXXXXX"
#endif

#ifdef IPX_CHANGE
#define _PATH_IPXUP	"/etc/ppp/ipx-up"
#define _PATH_IPXDOWN	"/etc/ppp/ipx-down"
#endif /* IPX_CHANGE */
