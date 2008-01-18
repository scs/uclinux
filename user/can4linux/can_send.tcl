#!/usr/bin/tclsh
# Tcl CAN Layer 2 example
# sending as fast as the process can
#

load ./canLtwo.so
puts "....... swig wrapper loaded"

# open the can interface /dev/can0
# but before, set the baud rate if other than default
exec /bin/echo 125 > /proc/sys/Can/Baud
puts "....... bit rate changed"

set device 1
set can_fd [can_open $device]
puts "....... /dev/can$device opened"

# now send messages
# send 8 byte, message id 100
#
# takes 1588µs per message on my 1009.955 MHz AuthenticAMD
#
set n 2000
puts "... send $n messages"
set t [time {can_send $can_fd 8 100:1,2,3,4,5,6,7,8} $n]
puts $t
#while 1 {
#    can_send $can_fd 8 100:1,2,3,4,5,6,7,8
#}


