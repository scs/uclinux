#!/usr/bin/tclsh
# Tcl CAN Layer 2 example
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

# send 8 byte, message id 100
can_send $can_fd 8 100:1,2,3,4,5,6,7,8
puts "... sent message"

# don't specify message length
can_send $can_fd 0 100:8,7,6,5,4,3,2,1
puts "... sent message"

# send RTR messages
can_send $can_fd 0 r200
puts "... sent message"

can_send $can_fd 4 r101
puts "... sent message"


set timeout 10
# try to receive something from can_fd, timeout in µs
# wait forever if timeout == 0
puts "Wait $timeout sec for an message....."
puts [can_read $can_fd [expr $timeout * 1000000]]
puts "Wait $timeout sec for an message....."
puts [can_read $can_fd [expr $timeout * 1000000]]
puts "Wait default timeout for an message....."
puts [can_read $can_fd]

can_close $can_fd
puts "....... /dev/can$device closed"


