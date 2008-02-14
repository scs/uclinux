@Echo OFF
SETLOCAL
for %%I in (%0) do %%~dI
for %%I in (%0) do cd "%%~pI"
cd liveMedia
del /Q liveMedia.mak
del /Q Makefile
type Makefile.head ..\win32config Makefile.tail > liveMedia.mak
cd ../groupsock
del /Q groupsock.mak
del /Q Makefile
type Makefile.head ..\win32config Makefile.tail > groupsock.mak
cd ../UsageEnvironment
del /Q UsageEnvironment.mak
del /Q Makefile
type Makefile.head ..\win32config Makefile.tail > UsageEnvironment.mak
cd ../BasicUsageEnvironment
del /Q BasicUsageEnvironment.mak
del /Q Makefile
type Makefile.head ..\win32config Makefile.tail > BasicUsageEnvironment.mak
cd ../testProgs
del /Q testProgs.mak
del /Q Makefile
type Makefile.head ..\win32config Makefile.tail > testProgs.mak
cd ../mediaServer
del /Q mediaServer.mak
del /Q Makefile
type Makefile.head ..\win32config Makefile.tail > mediaServer.mak


ENDLOCAL
