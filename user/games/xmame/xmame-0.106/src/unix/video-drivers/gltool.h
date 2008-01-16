#ifndef _GLTOOL_H
	#define _GLTOOL_H

	/**
	 * gltool.h
	 *
	 * Copyright (C) 2001  Sven Goethel
	 *
	 * GNU Library General Public License 
	 * as published by the Free Software Foundation
	 *
	 * http://www.gnu.org/copyleft/lgpl.html
	 * General dynamical loading OpenGL (GL/GLU) support for:
	 *
	 *
	 * <OS - System>          <#define>  commentary
	 * -----------------------------------------------
	 * GNU/Linux, Unices/X11  _X11_
	 * Macinstosh OS9         _MAC_OS9_
	 * Macinstosh OSX         _MAC_OSX_
	 * Win32                  _WIN32_
	 *
	 */

	#include <stdio.h>
	#include <stdlib.h>
	#include <stdarg.h>
	#include <string.h>

	#ifdef _WIN32_
		#include <windows.h>

		#ifdef LIBAPIENTRY
			#undef LIBAPIENTRY
		#endif
		#ifdef LIBAPI
			#undef LIBAPI
		#endif
	 
		#define LIBAPI          __declspec(dllexport)
		#define LIBAPIENTRY    __stdcall
	#else
		#include <ctype.h>
		#include <math.h>
		#define CALLBACK
	#endif

	#ifdef _X11_
		#include <dlfcn.h>
		#include <X11/Xlib.h>
		#include <X11/Xutil.h>
		#include <X11/Xatom.h>

		#ifndef __ARCH_solaris
		#define XMD_H 1
		#endif

		#include <GL/glx.h>
	#endif

	#ifdef _MAC_OS9_
		#include <agl.h>
		#include <CodeFragments.h>
		#include <Errors.h>
		#include <TextUtils.h>
		#include <StringCompare.h>
	 
		#define fragNoErr 0
	#endif

	#include <GL/gl.h>
	#include <GL/glu.h>

	#ifndef LIBAPIENTRY
                #define LIBAPIENTRY
        #endif
        #ifndef LIBAPI
                #define LIBAPI extern
        #endif

	#include "glcaps.h"
	#include "gl-disp-var.h"
	#include "glu-disp-var.h"

	#ifndef USE_64BIT_POINTER
		typedef int  PointerHolder;
	#else
		typedef long PointerHolder;
	#endif

	#if defined _WIN32_ && !defined NOGLCHECKS
		#define CHECK_WGL_ERROR(a,b,c) check_wgl_error(a,b,c)
	#else
		#define CHECK_WGL_ERROR(a,b,c)
	#endif

	#ifndef NOGLCHECKS
		#define PRINT_GL_ERROR(a, b)	print_gl_error((a), __FILE__, __LINE__, (b))
		#define CHECK_GL_ERROR()  	\
		{ \
		  GLenum errorcode = disp__glGetError(); \
		  if (errorcode != GL_NO_ERROR) \
		    print_gl_error("GLCHECK", __FILE__, __LINE__, errorcode); \
                }
	#else
		#define PRINT_GL_ERROR(a, b)	
		#define CHECK_GL_ERROR()  
	#endif
	
	#ifdef GLDEBUG
	  #define GL_BEGIN(m)    	__sglBegin(__FILE__, __LINE__, m)
	  #define GL_END()       	__sglEnd(__FILE__, __LINE__)
	  #define SHOW_GL_BEGINEND()	showGlBeginEndBalance(__FILE__, __LINE__)
	  #define CHECK_GL_BEGINEND()	checkGlBeginEndBalance(__FILE__, __LINE__)
	#else
	  #define GL_BEGIN(m)		disp__glBegin(m)
	  #ifndef NOGLCHECKS
	    #define GL_END()     	\
	    { \
              GLenum errorcode; \
	      disp__glEnd(); \
              errorcode = disp__glGetError(); \
	      if (errorcode != GL_NO_ERROR) \
	        print_gl_error("GL-PostEND-CHECK", __FILE__, __LINE__, \
	          errorcode); \
            }
	  #else
	    #define GL_END()     	disp__glEnd()
	  #endif
	  #define SHOW_GL_BEGINEND()	
	  #define CHECK_GL_BEGINEND()	
	#endif

	#if defined _WIN32_ && !defined NOGLCHECKS
	LIBAPI void LIBAPIENTRY check_wgl_error 
		(HWND wnd, const char *file, int line);
	#endif
	
	#ifndef NOGLCHECKS
	LIBAPI void LIBAPIENTRY print_gl_error 
		(const char *msg, const char *file, int line, GLenum errorcode);
        #endif
        
        #ifdef GLDEBUG
	LIBAPI void LIBAPIENTRY showGlBeginEndBalance
		(const char *file, int line);

	LIBAPI void LIBAPIENTRY checkGlBeginEndBalance
		(const char *file, int line);

	LIBAPI void LIBAPIENTRY __sglBegin
		(const char * file, int line, GLenum mode);

	LIBAPI void LIBAPIENTRY __sglEnd
		(const char * file, int line);
        #endif

	LIBAPI int LIBAPIENTRY unloadGLLibrary (void);

	LIBAPI int LIBAPIENTRY loadGLLibrary 
        	(const char * libGLName, const char * libGLUName);

	LIBAPI void * LIBAPIENTRY getGLProcAddressHelper 
		(const char * libGLName, const char * libGLUName,
		 const char *func, int *method, int debug, int verbose);

        LIBAPI void LIBAPIENTRY fetch_GL_FUNCS 
		(const char * libGLName, const char * libGLUName, int force);
#endif
