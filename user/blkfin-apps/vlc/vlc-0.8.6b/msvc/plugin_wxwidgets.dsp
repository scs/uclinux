# Microsoft Developer Studio Project File - Name="plugin_wxwidgets" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=plugin_wxwidgets - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "plugin_wxwidgets.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "plugin_wxwidgets.mak" CFG="plugin_wxwidgets - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "plugin_wxwidgets - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "plugin_wxwidgets - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "plugin_wxwidgets - Win32 Release"

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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /out:"plugins\libwxwidgets_plugin.dll"
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /opt:ref /out:"plugins\libwxwidgets_plugin.dll"

!ELSEIF  "$(CFG)" == "plugin_wxwidgets - Win32 Debug"

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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libwxwidgets_plugin.pdb" /out:"plugins\libwxwidgets_plugin.dll"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libwxwidgets_plugin.pdb" /out:"plugins\libwxwidgets_plugin.dll"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "plugin_wxwidgets - Win32 Release"
# Name "plugin_wxwidgets - Win32 Debug"

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE="..\modules\gui\wxwidgets\wxwidgets.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\wxwidgets.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\streamdata.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\interface.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\extrapanel.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\menus.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\timer.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\video.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\input_manager.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\playlist_manager.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\open.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\interaction.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\streamout.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\wizard.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\messages.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\playlist.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\iteminfo.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\infopanels.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\preferences.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\preferences_widgets.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\fileinfo.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\updatevlc.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\subtitles.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\bookmarks.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_slider_manager.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_slider_manager.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_stream.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_stream.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_wrapper.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_wrapper.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_streampanel.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_streampanel.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_panel.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\vlm\vlm_panel.hpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=wxwidgets" /D "MODULE_NAME_IS_wxwidgets" 
!IF "$(CFG)" == "plugin_wxwidgets - Win32 Release"
# PROP Output_Dir "Release\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Release\modules\gui\wxwidgets"
!ELSEIF "$(CFG)" == "plugin_wxwidgets - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\wxwidgets"
# PROP Intermediate_Dir "Debug\modules\gui\wxwidgets"
# End Source File

# End Group

# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"

# Begin Source File
SOURCE="..\modules\gui\wxwidgets\streamdata.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\wxwidgets\dialogs\preferences_widgets.h"
# End Source File

# End Group

# End Target
# End Project
