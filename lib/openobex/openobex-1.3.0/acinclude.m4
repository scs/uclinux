dnl
dnl IRDA_HOOK (script-if-irda-found, failflag)
dnl
dnl if failflag is "failure" it aborts if obex is not found.
dnl

AC_DEFUN([IRDA_HOOK],[
	AC_CACHE_CHECK([for IrDA support],am_cv_irda_found,[

		AC_TRY_COMPILE([#include <sys/socket.h>
				#include "src/irda.h"],
		[struct irda_device_list l;],
		am_cv_irda_found=yes,
		am_cv_irda_found=no)])

		if test $am_cv_irda_found = yes; then
			AC_DEFINE(HAVE_IRDA,1,[Define if system supports IrDA])

		fi
	])

])

AC_DEFUN([IRDA_CHECK], [
	IRDA_HOOK([],failure)
])


dnl
dnl BLUETOOTH_HOOK (script-if-bluetooth-found, failflag)
dnl
dnl if failflag is "failure" it aborts if obex is not found.
dnl

AC_DEFUN([BLUETOOTH_HOOK],[
	AC_CACHE_CHECK([for Bluetooth support],am_cv_bluetooth_found,[

		AC_TRY_COMPILE([#include <sys/socket.h>
				#include <bluetooth/bluetooth.h>
				#include <bluetooth/rfcomm.h>],
		[bdaddr_t bdaddr;
		 struct sockaddr_rc addr;],
		am_cv_bluetooth_found=yes,
		am_cv_bluetooth_found=no)])

		if test $am_cv_bluetooth_found = yes; then
			AC_DEFINE(HAVE_BLUETOOTH,1,[Define if system supports Bluetooth])

		fi
	])

])

AC_DEFUN([BLUETOOTH_CHECK], [
	BLUETOOTH_HOOK([],failure)
])
