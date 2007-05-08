# Microsoft Developer Studio Project File - Name="plugin_skins2" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=plugin_skins2 - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "plugin_skins2.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "plugin_skins2.mak" CFG="plugin_skins2 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "plugin_skins2 - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "plugin_skins2 - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "plugin_skins2 - Win32 Release"

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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /out:"plugins\libskins2_plugin.dll"
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /opt:ref /out:"plugins\libskins2_plugin.dll"

!ELSEIF  "$(CFG)" == "plugin_skins2 - Win32 Debug"

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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libskins2_plugin.pdb" /out:"plugins\libskins2_plugin.dll"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libskins2_plugin.pdb" /out:"plugins\libskins2_plugin.dll"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "plugin_skins2 - Win32 Release"
# Name "plugin_skins2 - Win32 Debug"

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE="..\modules\gui\skins2\commands\async_queue.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\async_queue.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_add_item.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_add_item.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_audio.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_audio.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_dummy.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_dvd.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_dvd.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_generic.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_change_skin.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_change_skin.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_dialogs.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_fullscreen.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_fullscreen.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_input.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_input.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_layout.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_layout.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_muxer.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_muxer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_on_top.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_on_top.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_playlist.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_playlist.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_playtree.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_playtree.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_minimize.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_minimize.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_quit.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_quit.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_resize.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_resize.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_snapshot.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_snapshot.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_show_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_vars.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\commands\cmd_vars.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_button.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_button.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_checkbox.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_checkbox.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_flat.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_generic.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_generic.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_image.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_image.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_list.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_list.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_tree.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_tree.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_move.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_move.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_resize.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_resize.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_slider.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_slider.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_radialslider.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_radialslider.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_text.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_text.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_video.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\controls\ctrl_video.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_enter.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_focus.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_generic.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_input.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_input.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_key.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_key.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_leave.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_menu.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_motion.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_mouse.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_mouse.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_refresh.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_special.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_special.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_scroll.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\events\evt_scroll.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\builder.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\builder.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\builder_data.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\expr_evaluator.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\expr_evaluator.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\interpreter.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\interpreter.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\skin_parser.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\skin_parser.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\xmlparser.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\parser\xmlparser.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\anchor.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\anchor.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\anim_bitmap.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\anim_bitmap.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\bitmap_font.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\bitmap_font.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\dialogs.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\dialogs.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\file_bitmap.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\file_bitmap.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\ft2_bitmap.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\ft2_bitmap.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\ft2_font.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\ft2_font.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_bitmap.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_bitmap.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_font.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_layout.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_layout.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_window.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\generic_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\ini_file.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\ini_file.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\logger.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\logger.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_factory.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_factory.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_graphics.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_loop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_popup.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_timer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\os_tooltip.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\popup.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\popup.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\scaled_bitmap.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\scaled_bitmap.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\skin_main.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\skin_common.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\theme.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\theme.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\theme_loader.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\theme_loader.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\theme_repository.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\theme_repository.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\tooltip.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\tooltip.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\top_window.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\top_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\var_manager.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\var_manager.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\vlcproc.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\vlcproc.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\vout_window.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\vout_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\window_manager.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\src\window_manager.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\bezier.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\bezier.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\fsm.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\fsm.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\observer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\pointer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\position.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\position.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\ustring.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\ustring.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\variable.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_bool.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_bool.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_list.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_list.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_percent.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_percent.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_text.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_text.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_tree.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\utils\var_tree.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\equalizer.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\equalizer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\playlist.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\playlist.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\playtree.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\playtree.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\time.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\time.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\volume.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\vars\volume.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_dragdrop.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_dragdrop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_factory.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_factory.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_graphics.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_graphics.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_loop.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_loop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_popup.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_popup.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_timer.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_timer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_tooltip.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_tooltip.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_window.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\win32\win32_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_display.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_display.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_dragdrop.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_dragdrop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_factory.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_factory.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_graphics.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_graphics.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_loop.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_loop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_popup.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_popup.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_timer.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_timer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_window.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_tooltip.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\x11\x11_tooltip.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_dragdrop.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_dragdrop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_factory.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_factory.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_graphics.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_graphics.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_loop.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_loop.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_popup.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_popup.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_timer.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_timer.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_window.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_window.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_tooltip.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\macosx\macosx_tooltip.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\unzip\ioapi.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\unzip\unzip.c"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=skins2" /D "MODULE_NAME_IS_skins2" 
!IF "$(CFG)" == "plugin_skins2 - Win32 Release"
# PROP Output_Dir "Release\modules\gui\skins2"
# PROP Intermediate_Dir "Release\modules\gui\skins2"
!ELSEIF "$(CFG)" == "plugin_skins2 - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\skins2"
# PROP Intermediate_Dir "Debug\modules\gui\skins2"
# End Source File

# End Group

# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"

# Begin Source File
SOURCE="..\modules\gui\skins2\unzip\crypt.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\unzip\ioapi.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\skins2\unzip\unzip.h"
# End Source File

# End Group

# End Target
# End Project
