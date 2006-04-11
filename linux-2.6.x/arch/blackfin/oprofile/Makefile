obj-$(CONFIG_PROFILING) += oprofile.o

DRIVER_OBJS := $(addprefix ../../../drivers/oprofile/, \
oprof.o cpu_buffer.o buffer_sync.o \
event_buffer.o oprofile_files.o \
oprofilefs.o oprofile_stats.o \
timer_int.o )
oproflie-y 				:= $(DRIVER_OBJS)
oprofile-$(CONFIG_HARDWARE_PM) 		+= op_model_bf533.o common.o
