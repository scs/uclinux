lib_LTLIBRARIES = libmvm.la

libmvm_la_LDFLAGS = -version-info 2:0:0

libmvm_la_SOURCES = \
	daemon.cc \
	display.cc \
	event.cc \
	flag.cc \
	interrupt.cc \
	manager.cc \
	monitor.cc \
	numlaws.cc \
	pipe.cc \
	queue.cc \
	resource.cc \
	simapi.cc \
	source.cc \
	stream.cc \
	synchro.cc \
	thread.cc \
	timed.cc \
	timer.cc \
	trace.cc \
	trigger.cc

noinst_HEADERS = \
	daemon.h \
	display.h \
	event.h \
	flag.h \
	interrupt.h \
	manager.h \
	monitor.h \
	numlaws.h \
	pipe.h \
	queue.h \
	resource.h \
	source.h \
	stream.h \
	synchro.h \
	thread.h \
	timed.h \
	timer.h \
	trace.h \
	trigger.h

libmvm_la_CPPFLAGS = \
	@MVM_CXXFLAGS@ \
	-D__XENO_SIM__ \
	-I$(srcdir)/..
