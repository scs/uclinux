TARGET = pictureflow
TEMPLATE = app
linux-bfin-flat-* {
	QMAKE_LIBS_THREAD += -lz -lpng
}
HEADERS = pictureflow.h
SOURCES = pictureflow.cpp main.cpp
