/**
 * @file opd_interface.h
 *
 * Module / user space interface for 2.6 kernels and above
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 */

#ifndef OPD_INTERFACE_H
#define OPD_INTERFACE_H

#define CTX_SWITCH_CODE			1
#define CPU_SWITCH_CODE			2
#define COOKIE_SWITCH_CODE		3
#define KERNEL_ENTER_SWITCH_CODE	4
#define KERNEL_EXIT_SWITCH_CODE		5
#define MODULE_LOADED_CODE              6
#define CTX_TGID_CODE			7
#define TRACE_BEGIN_CODE		8
#define LAST_CODE			9
 
#endif /* OPD_INTERFACE_H */
