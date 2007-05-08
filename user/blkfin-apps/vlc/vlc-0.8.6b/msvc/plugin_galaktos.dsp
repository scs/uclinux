# Microsoft Developer Studio Project File - Name="plugin_galaktos" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=plugin_galaktos - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "plugin_galaktos.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "plugin_galaktos.mak" CFG="plugin_galaktos - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "plugin_galaktos - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "plugin_galaktos - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "plugin_galaktos - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_MT" /D "_DLL" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "." /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_MT" /D "_DLL" /YX /FD -I..\include /c
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /out:"plugins\libgalaktos_plugin.dll"
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /opt:ref /out:"plugins\libgalaktos_plugin.dll"

!ELSEIF  "$(CFG)" == "plugin_galaktos - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_MT" /D "_DLL" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /ZI /Od /I "." /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_MT" /D "_DLL" /FR /YX /FD /GZ -I..\include /c
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libgalaktos_plugin.pdb" /out:"plugins\libgalaktos_plugin.dll"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libgalaktos_plugin.pdb" /out:"plugins\libgalaktos_plugin.dll"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "plugin_galaktos - Win32 Release"
# Name "plugin_galaktos - Win32 Debug"

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE="..\modules\visualization\galaktos\plugin.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\main.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\preset.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\beat_detect.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\param.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\engine_vars.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\parser.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\builtin_funcs.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\eval.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\init_cond.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\PCM.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\fftsg.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_frame_eqn.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\splaytree.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\custom_shape.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\func.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_pixel_eqn.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\tree_types.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\custom_wave.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\video_init.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=galaktos" /D "MODULE_NAME_IS_galaktos" 
!IF "$(CFG)" == "plugin_galaktos - Win32 Release"
# PROP Output_Dir "Release\modules\visualization\galaktos"
# PROP Intermediate_Dir "Release\modules\visualization\galaktos"
!ELSEIF "$(CFG)" == "plugin_galaktos - Win32 Debug"
# PROP Output_Dir "Debug\modules\visualization\galaktos"
# PROP Intermediate_Dir "Debug\modules\visualization\galaktos"
# End Source File

# End Group

# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"

# Begin Source File
SOURCE="..\modules\visualization\galaktos\plugin.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\main.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\preset.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\preset_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\beat_detect.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\builtin_funcs.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\common.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\compare.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\expr_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\fatal.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\idle_preset.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\interface_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_point_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\param.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\param_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\engine_vars.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\parser.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\eval.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\init_cond.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\init_cond_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\PCM.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_frame_eqn.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_frame_eqn_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\splaytree.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\splaytree_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\custom_shape.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\custom_shape_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\func.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\func_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_pixel_eqn.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\per_pixel_eqn_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\tree_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\custom_wave.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\custom_wave_types.h"
# End Source File
# Begin Source File
SOURCE="..\modules\visualization\galaktos\video_init.h"
# End Source File

# End Group

# End Target
# End Project
