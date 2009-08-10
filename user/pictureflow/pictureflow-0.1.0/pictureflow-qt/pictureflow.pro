TARGET = pictureflow
TEMPLATE = app
#Some funtions in QtGui lib depend on zlib and libpng. Blackfin toolchain
#asks the link flags of zlib and libpng be put behind the QtGui, otherwize
#link tool reports "symbol not found". LIBS macro in project file is always
#put before the link flags generated via CONFIG macro, while QMAKE_LIBS_THREAD
#is on the contrary. So, hacking it via QMAKE_LIBS_THREAD instead. 
linux-bfin-* {
	QMAKE_LIBS_THREAD += -lz -lpng
}
HEADERS = pictureflow.h
SOURCES = pictureflow.cpp main.cpp
