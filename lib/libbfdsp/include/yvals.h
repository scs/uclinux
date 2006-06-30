 /* yvals.h
 *
 * (c) Copyright 2002-2005 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * (c) Copyright 1996-1999 by P.J. Plauger.  ALL RIGHTS RESERVED.

 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * Consult your license regarding permissions and restrictions.
 * $Revision$
 ************************************************************************/

/*
** yvals.h for ADIDSP's version 3.1.0 library
*/

#if !defined _YVALS
#define _YVALS

/*
** Namespace support
*/
/* # define _HAS_NAMESPACE                        */
# define _STD_BEGIN
# define _STD_END
# define _C_STD_BEGIN
# define _C_STD_END
# ifdef __cplusplus
#  define _STD                              ::
#  define _CSTD                             ::
# else /* __cplusplus */
#  define _STD
#  define _CSTD
# endif /* __cplusplus */


/*
** Naming properties
*/
# if defined(__cplusplus)
#  define _C_LIB_DECL extern "C" {
#  define _END_C_LIB_DECL }
#  define _EXTERN_C extern "C" {
#  define _END_EXTERN_C }
# else
#  define _C_LIB_DECL
#  define _END_C_LIB_DECL
#  define _EXTERN_C
#  define _END_EXTERN_C
# endif /* __cplusplus */


#endif

