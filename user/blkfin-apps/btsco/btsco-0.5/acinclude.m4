AC_DEFUN([AC_ARG_BTSCO], [
	ao_enable=no
	AC_ARG_ENABLE(all, AC_HELP_STRING([--enable-all], [enable all extra options below]), [
		ao_enable=${enableval}
                fixed_enable=${enableval}
	])
        AC_ARG_ENABLE(ao, AC_HELP_STRING([--enable-ao], [enable libao support]), [
                ao_enable=${enableval}
        ])

	AM_CONDITIONAL(AO, test "${ao_enable}" = "yes")

        fixed_enable=no
        AC_ARG_ENABLE(fixed, AC_HELP_STRING([--enable-fixed], [enable fixed point optimizations]), [
                fixed_enable=${enableval}
        ])

	AM_CONDITIONAL(FIXED, test "${fixed_enable}" = "yes")

        alsaplugin_enable=no
        AC_ARG_ENABLE(alsaplugin, AC_HELP_STRING([--enable-alsaplugin], [enable alsa plugin build]), [
                alsaplugin_enable=${enableval}
        ])

        AM_CONDITIONAL(ALSAPLUGIN, test "${alsaplugin_enable}" = "yes")
])

AC_DEFUN([AC_PATH_BLUEZ], [
	bluez_prefix=${prefix}

	AC_ARG_WITH(bluez, AC_HELP_STRING([--with-bluez=DIR], [BlueZ library is installed in DIR]), [
		if (test "${withval}" != "yes"); then
			bluez_prefix=${withval}
		fi
	])

	ac_save_CPPFLAGS=$CPPFLAGS
	ac_save_LDFLAGS=$LDFLAGS

	BLUEZ_CFLAGS=""
	test -d "${bluez_prefix}/include" && BLUEZ_CFLAGS="$BLUEZ_CFLAGS -I${bluez_prefix}/include"

	CPPFLAGS="$CPPFLAGS $BLUEZ_CFLAGS"
	AC_CHECK_HEADER(bluetooth/bluetooth.h,, AC_MSG_ERROR(Bluetooth header files not found))

	BLUEZ_LIBS=""
	if (test "${prefix}" = "${bluez_prefix}"); then
		test -d "${libdir}" && BLUEZ_LIBS="$BLUEZ_LIBS -L${libdir}"
	else
		test -d "${bluez_prefix}/lib64" && BLUEZ_LIBS="$BLUEZ_LIBS -L${bluez_prefix}/lib64"
		test -d "${bluez_prefix}/lib" && BLUEZ_LIBS="$BLUEZ_LIBS -L${bluez_prefix}/lib"
	fi

	LDFLAGS="$LDFLAGS $BLUEZ_LIBS"
	AC_CHECK_LIB(bluetooth, hci_open_dev, BLUEZ_LIBS="$BLUEZ_LIBS -lbluetooth", AC_MSG_ERROR(Bluetooth library not found))
	AC_CHECK_LIB(bluetooth, sdp_connect,, AC_CHECK_LIB(sdp, sdp_connect, BLUEZ_LIBS="$BLUEZ_LIBS -lsdp"))

	CPPFLAGS=$ac_save_CPPFLAGS
	LDFLAGS=$ac_save_LDFLAGS

	AC_SUBST(BLUEZ_CFLAGS)
	AC_SUBST(BLUEZ_LIBS)
])
