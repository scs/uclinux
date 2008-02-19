AC_DEFUN([MS_CHECK_DEP],[
	dnl $1=dependency description
	dnl $2=dependency short name, will be suffixed with _CFLAGS and _LIBS
	dnl $3=headers's place
	dnl $4=lib's place
	dnl $5=header to check
	dnl $6=lib to check
	dnl $7=function to check in library
	
	NAME=$2
	dep_headersdir=$3
	dep_libsdir=$4
	dep_header=$5
	dep_lib=$6
	dep_funclib=$7
	other_libs=$8	
	
	if test "$dep_headersdir" != "/usr/include" ; then
		eval ${NAME}_CFLAGS=\"-I$dep_headersdir \"
	fi
	eval ${NAME}_LIBS=\"-L$dep_libsdir -l$dep_lib\"
	
	CPPFLAGS_save=$CPPFLAGS
	LDFLAGS_save=$LDFLAGS
	CPPFLAGS="-I$dep_headersdir "
	LDFLAGS="-L$dep_libsdir "
	
	AC_CHECK_HEADERS([$dep_header],[AC_CHECK_LIB([$dep_lib],[$dep_funclib],found=yes,found=no, [$other_libs])
	],found=no)
	
	if test "$found" = "yes" ; then
		eval ${NAME}_found=yes
		AC_SUBST($2_CFLAGS)
		AC_SUBST($2_LIBS)
	else
		eval ${NAME}_found=no
		eval ${NAME}_CFLAGS=
		eval ${NAME}_LIBS=
	fi
	CPPFLAGS=$CPPFLAGS_save
	LDFLAGS=$LDFLAGS_save
	
])


AC_DEFUN([MS_CHECK_VIDEO],[

	dnl conditionnal build of video support
	AC_ARG_ENABLE(video,
		  [  --enable-video    Turn on video support compiling],
		  [case "${enableval}" in
			yes) video=true ;;
			no)  video=false ;;
			*) AC_MSG_ERROR(bad value ${enableval} for --enable-video) ;;
		  esac],[video=true])
		  
	AC_ARG_WITH( ffmpeg,
		  [  --with-ffmpeg		Sets the installation prefix of ffmpeg, needed for video support. [default=/usr] ],
		  [ ffmpegdir=${withval}],[ ffmpegdir=/usr ])
	
	AC_ARG_WITH( sdl,
		  [  --with-sdl		Sets the installation prefix of libSDL, needed for video support. [default=/usr] ],
		  [ libsdldir=${withval}],[ libsdldir=/usr ])
	
	if test "$video" = "true"; then
		
		dnl test for ffmpeg presence
		PKG_CHECK_MODULES(FFMPEG, [libavcodec >= 50.0.0 ],ffmpeg_found=yes , ffmpeg_found=no)
		dnl workaround for debian...
		PKG_CHECK_MODULES(FFMPEG, [libavcodec >= 0d.50.0.0 ], ffmpeg_found=yes, ffmpeg_found=no)
		if test x$ffmpeg_found = xno ; then
			AC_MSG_ERROR([Could not find ffmpeg headers and library. This is mandatory for video support])
		fi

		dnl to workaround a bug on debian and ubuntu, check if libavcodec needs -lvorbisenc to compile	
		AC_CHECK_LIB(avcodec,avcodec_register_all, novorbis=yes , [
			LIBS="$LIBS -lvorbisenc"
		], $FFMPEG_LIBS )

		dnl check if sws_scale is available
		AC_CHECK_LIB(avcodec,sws_scale, have_sws_scale=yes , have_sws_scale=no,
		 	$FFMPEG_LIBS )
		if test x$have_sws_scale = xno ; then
			PKG_CHECK_MODULES(SWSCALE, [libswscale >= 0.5.0 ], need_swscale=yes, need_swscale=no)
		fi

		MS_CHECK_DEP([SDL],[SDL],[${libsdldir}/include],[${libsdldir}/lib],[SDL/SDL.h],[SDL],[SDL_Init])
		if test "$SDL_found" = "no" ; then
			AC_MSG_ERROR([Could not find libsdl headers and library. This is mandatory for video support])
		fi

		PKG_CHECK_MODULES(THEORA, [theora >= 1.0alpha7 ], [have_theora=yes],
					[have_theora=no])
	
		VIDEO_CFLAGS=" $FFMPEG_CFLAGS $SDL_CFLAGS -DVIDEO_ENABLED "
		VIDEO_LIBS=" $FFMPEG_LIBS $SWSCALE_LIBS $SDL_LIBS"
	fi
	
	AC_SUBST(VIDEO_CFLAGS)
	AC_SUBST(VIDEO_LIBS)
])
