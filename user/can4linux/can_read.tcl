#!/usr/bin/tclsh
# Tcl CAN Layer 2 example
# simple CAN Analyzer
#

load ./canLtwo.so
puts "....... swig wrapper loaded"

# open the can interface /dev/can0
# but before, set the baud rate if other than default
exec /bin/echo 125 > /proc/sys/Can/Baud
puts "....... bit rate changed"

set device 0
set can_fd [can_open $device]
puts "....... /dev/can$device opened, got descriptor $can_fd"

puts "... wait for messages"
# now go into receive loop
#
while 1 {
    puts [can_read2 $can_fd 0]
}
can_close $can_fd
puts "....... /dev/can$device closed"

