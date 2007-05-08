# Microsoft Developer Studio Project File - Name="plugin_beos" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=plugin_beos - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "plugin_beos.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "plugin_beos.mak" CFG="plugin_beos - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "plugin_beos - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "plugin_beos - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "plugin_beos - Win32 Release"

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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /out:"plugins\libbeos_plugin.dll"
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /machine:I386 /entry:_CRT_INIT@12 /opt:ref /out:"plugins\libbeos_plugin.dll"

!ELSEIF  "$(CFG)" == "plugin_beos - Win32 Debug"

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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libbeos_plugin.pdb" /out:"plugins\libbeos_plugin.dll"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib netapi32.lib winmm.lib comctl32.lib rpcrt4.lib /nologo /dll /subsystem:console /debug /machine:I386 /pdbtype:sept /entry:_CRT_INIT@12 /pdb:"plugins\libbeos_plugin.pdb" /out:"plugins\libbeos_plugin.dll"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "plugin_beos - Win32 Release"
# Name "plugin_beos - Win32 Debug"

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"

# Begin Source File
SOURCE="..\modules\gui\beos\BeOS.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\AudioOutput.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\VideoOutput.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\Interface.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\InterfaceWindow.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\ListViews.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\DrawingTidbits.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\TransportButton.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\PlayListWindow.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\PreferencesWindow.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\MessagesWindow.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\MediaControlView.cpp"
# ADD CPP /D "__VLC__" /D "__PLUGIN__"  /D "MODULE_NAME=beos" /D "MODULE_NAME_IS_beos" 
!IF "$(CFG)" == "plugin_beos - Win32 Release"
# PROP Output_Dir "Release\modules\gui\beos"
# PROP Intermediate_Dir "Release\modules\gui\beos"
!ELSEIF "$(CFG)" == "plugin_beos - Win32 Debug"
# PROP Output_Dir "Debug\modules\gui\beos"
# PROP Intermediate_Dir "Debug\modules\gui\beos"
# End Source File

# End Group

# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"

# Begin Source File
SOURCE="..\modules\gui\beos\InterfaceWindow.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\ListViews.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\DrawingTidbits.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\TransportButton.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\PlayListWindow.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\PreferencesWindow.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\MessagesWindow.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\MediaControlView.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\Bitmaps.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\MsgVals.h"
# End Source File
# Begin Source File
SOURCE="..\modules\gui\beos\VideoWindow.h"
# End Source File

# End Group

# End Target
# End Project
