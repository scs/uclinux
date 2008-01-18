#
# Example for using a file-event
#
# load some basic functions
load ./canLtwo.so
puts "....... swig wrapper loaded"


# define a event handler function for CAN messages
proc got_CAN {fid} {
    puts "received Message"
    # use can_read, it only aquires one CAN message
    # from a file handler with data available
    puts [can_read $fid 0]

}

exec /bin/echo 125 > /proc/sys/Can/Baud
set cfd [open /dev/can0]
puts "....... raw can4linux dev can0 opened, got: $cfd"

# irgendwie den absoluten file handler herausbekommen
# open liefert "file4", dann muss fid = 4 sein
#set fid [regex "file(.)" $cfd $fid]
set fid 4

puts "....... using file descriptor $fid for the event handler"
fileevent $cfd readable "got_CAN $fid"
puts ".......  file handler installed"

#close $cfd
