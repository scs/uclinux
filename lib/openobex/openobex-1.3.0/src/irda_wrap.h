#ifndef IRDA_WRAP_H
#define IRDA_WRAP_H

#ifdef _WIN32
#define _WIN32_WINNT

#include <af_irda.h>
struct irda_device_list {DEVICELIST;};
struct irda_device_info {IRDA_DEVICE_INFO;};
struct sockaddr_irda {SOCKADDR_IRDA;};
#define sir_name irdaServiceName
#define sir_family irdaAddressFamily

#else /* _WIN32 */

#include <irda.h>

#endif /* _WIN32 */

#endif /* IRDA_WRAP_H */
