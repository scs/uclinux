#  This file is part of the XENOMAI project.
#
#  Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
#  Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; either version 2 of the
#  License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  Author(s): rpm
#  Contributor(s):
#
#  Adapted to XENOMAI by Philippe Gerum.

# This Tcl script supports various aspects of the dialog with a GDB
# session. This script should be totally rewritten (so as some parts
# of the gdb helper) to make full use of GDB's annotation
# feature. Anyway, this is a quite good example of what can be done
# when annotation is not available from a debug engine... Currently,
# only the --fullname extension is used.

set gdb:args "--quiet --nx --nw --fullname --readnow"
set gdb:traps {"^Program received signal .*" \
	       "^warning: \[A-Za-z\]* \[Ww\]atchpoint \[0-9\]+: Could not insert watchpoint" \
	       "^\032\032.*" \
	       "Breakpoint \[0-9\]+, ((0x)|\[_A-Za-z\]+).*" \
	       "0x\[0-9a-fA-F\]+ in .*" \
	       "^Program exited normally" \
	       "^Program exited abnormally" \
	       "^Program exited with code .*" \
	       "^Program terminated .*" }

set gdb:signaled false
set gdb:siginfo ""
set gdb:killed false
set gdb:btcache {}
set gdb:stream {}
set gdb:pipe {}
set gdb:lasterror {}
set gdb:bhook {}
set gdb:wpsupport unknown
set gdb:mvmcr0 {}
set gdb:mvmcr1 {}
set gdb:mvmcr2 {}
set gdb:mvmcr3 {}
set gdb:mvmeh 0
set gdb:lastexpr {}
set gdb:obsoleted false
# C++ linkvar: boolean gdb:dead

# global tcl_traceExec
# set tcl_traceExec 1

proc gdb:oread {pipe} {

    while {[gets $pipe s] != -1} {
	puts stdout $s
    }
}

proc gdb:init {context gdbpath filename simargs srcDirs pipeout} {

    global gdb:killed gdb:stream gdb:bhook gdb:pipe
    global gdb:args gdb:btcache gdb:signaled

    set gdb:killed false
    set gdb:signaled false
    set gdb:btcache {}
    set gdb:stream {}
    # Assume the first stop is caused by the preamble breakpoint.
    set gdb:bhook gdb:preamble

    if {[catch {
	# must have GDB's stdout/stderr grouped in a single stream...
	set stream [open "|$gdbpath ${gdb:args} --tty $pipeout $filename |& cat" r+]
    }] == 1} {
  	# GDB not found or unstartable
	return {}
    }

    if {$stream == {}} {
  	# Problem starting GDB
  	return {}
    }

    # Initialize the i/o sub-layer (C++ part)
    set gdb:stream $stream
    gdb:initio $stream

    set gdb:pipe [open $pipeout r+]
    fconfigure ${gdb:pipe} -blocking false -translation binary -buffering none
    fileevent ${gdb:pipe} readable "gdb:oread ${gdb:pipe}"

    # Event handler must be set before calling gdb:waitprompt
    fconfigure $stream -blocking false -translation binary -buffering none
    fileevent $stream readable gdb:iread
    # Ensure we'll have the right prompt
    gdb:send "set prompt %gdb%"

    if {[gdb:waitprompt] == -1} {
	# debug session has been aborted
	return {}
    }

    # Set miscellaneous attributes
    gdb:command "set editing off"
    gdb:command "set height 0"
    gdb:command "set width 0"
    gdb:command "set confirm off"

    # Ensure the shared libs are attached before an attempt is
    # made to set the internal breakpoints. We do this by executing
    # the crt prolog (bp main + run). Better ideas are welcome... 
    set rl [gdb:command "break main" l {"^Breakpoint \[0-9\]+.*"}]
    set nre [lindex $rl 0]
    if {$nre != 0} {
	set matched [lindex [lindex $rl 2] 0]
	gdb:close $context
	tk_messageBox \
	    -message "GDB error: $matched" \
	    -type ok -icon error -title " "
	return {}
    }
    regexp "^Breakpoint (\[0-9\]+)" [lindex $rl 1] mvar bpnum
    gdb:command "run"
    gdb:command "delete $bpnum"

    # Install internal breakpoints on break trap and exception handler

    foreach bp {mvm_bp mvm_eh} {
	set rl [gdb:command "break *$bp" l {"^Breakpoint \[0-9\]+.*"}]
	set nre [lindex $rl 0]
	if {$nre != 0} {
	    # cannot set internal breakpoint in debuggee's code
	    set matched [lindex [lindex $rl 2] 0]
	    gdb:close $context
	    tk_messageBox \
		-message "GDB error: $matched" \
		-type ok -icon error -title " "
	    return {}
	}
    }

    # Setup source directories list (if given)
    if {$srcDirs != {}} {
	gdb:command "directory $srcDirs"
    }

    return $stream
}

proc gdb:close {context} {

    global gdb:dead gdb:killed gdb:stream gdb:pipe

    catch { close ${gdb:pipe} }
    gdb:doneio
    catch { fileevent ${gdb:stream} readable {} }
    set gdb:killed true

    if {${gdb:dead} == 0} {
	# Help Tcl a bit by wiping GDB out before actually
	# closing the pipe.
	catch { exec -- kill -HUP [lindex [pid ${gdb:stream}] 0] }
	set gdb:dead 1
	catch { close ${gdb:stream} }
    }
}

proc gdb:waitprompt {} {
    return [lindex [gdb:expect {"^%gdb%"}] 0]
}

# FIXME: the current implementation views the dispatch loop
# processing messages from GDB as a synchronous activity. This
# is quite a dumb choice. The next implementation, using the
# annotation level, should integrate the dispatch loop to the
# input "expect" routine, so as to view it as an asynchronous
# task. This way, we should be able to say that we *always* listen
# to what GDB says, and not only when we are expecting something
# from it. Error processing should be considerably eased and made
# more robust after this improvement.

proc gdb:dispatch {context {notify true}} {

    global gdb:traps gdb:signaled gdb:siginfo
    global gdb:killed gdb:bhook gdb:obsoleted

    set rl [gdb:expect ${gdb:traps}]
    set nre [lindex $rl 0]
    set matched [lindex $rl 1]

    if {$nre == -1} {
	# do not raise fatal error if we did kill the inferior GDB
	# inside gdb:close().
	if {${gdb:killed} == "false"} {
	    gdb:fatal $context "debugger died unexpectedly!?"
	}
	return
    }

    if {$nre != 0} {
	# Eat the next prompt sent by GDB as it regained control
	# over the debuggee... except if we are next to process
	# a signal receipt. Yes, this is a slimy hack! This prevents
	# the prompt to be matched *before* the faulty address
	# is caught as a recognized regexp by gdb:dispatch().
	# Otherwise, the fault breakpoint would be discarded in the
	# process of matching it.
	gdb:waitprompt
    }

    switch -- $nre {

	0 {
	    # program received a signal - a break is expected next to this
	    regexp "Program received signal (.*)" $matched mvar gdb:siginfo
	    set gdb:signaled true
	    # Always notify on signal receipt - dispatch could recurse
	    # indefinitely if running an internal debug control operation,
	    # but the debugger will display the fault address;
	    # anyway, the simulation should never catch a signal during
	    # a thread bump, otherwise, this situation really needs to be
	    # inspected!
	    # go fetching the faulty code location
	    gdb:dispatch $context
	}

	1 {
	    # watchpoint error -- we *must* trap this error condition at
	    # this level too (i.e. so as switchout does). Watchpoint support for
	    # the GDB module is really a mess!
	    if {[regexp "\[Ww\]atchpoint (\[0-9\]+):" $matched mvar wpnum] == 1} {
		# notify the front-end this watchpoint is about to be disabled
		global gdb:lasterror
		set gdb:lasterror $matched
		Debugger:notifyWatchError $context $wpnum
		# automatically disable faulty watchpoint and resume
		gdb:disablewp $wpnum
		gdb:send cont
		# go back listening to GDB
		gdb:dispatch $context
	    }
	}

	2 {
	    # Breakpoint hit in a portion of source compiled with
	    # debugging information- --fullname option makes gdb emit
	    # this kind of informative line when a bp is reached:
	    # ^Z^Z<source-file>:<source-line>:<char-num>:<mid/beg>:<pc>
	    # "beg/mid" standing for a flag indicating whether the returned
	    # pc points to the beginning of the line or not (i.e. "mid"
	    # for middle).

	    # If returning from an internal dispatch: do not notify
	    # user layer about it - otherwise, we would recurse
	    # indefinitely...

	    if {$notify == "true"} {
		set l [split $matched :]
		set sourcefile [string range [lindex $l 0] 2 end]
		set lineno [lindex $l 1]

		if {${gdb:signaled} == "true"} {
		    Debugger:notifyException $context \
			[list $sourcefile $lineno] ${gdb:siginfo}
		} {
		    global gdb:mvmeh
		    set bpaddr [lindex $l 4]

		    # Check that the trapped address is located in a range
		    # of 8 bytes starting from the mvm_eh() prologue do
		    # determine whether we've juste caught an exception
		    # or not. Ahemmm... not proud of this code, sorry :-/

		    if {[expr $bpaddr >= ${gdb:mvmeh} && $bpaddr <= ${gdb:mvmeh} + 8]} {
			# An unexpected exception
			# has just be caught -- make the signal being
			# raised again telling GDB to handle it as a
			# fault this time. RE #0 should be selected
			# next on input.
			gdb:send cont
			gdb:dispatch $context
		    } {
			${gdb:bhook} $context [list $sourcefile $lineno]
		    }
		}
	    }
	}

	3 - 4 {
	    # Breakpoint/stop hit in a portion of source compiled
	    # with no debugging information available.

	    if {$notify == "true"} {
		if {[regexp ".*0x\[0-9a-fA-F\]+ in (\[^ \]+).*" \
			 $matched mvar function] == 0} {
		    regexp ".*, (\[_a-zA-Z\]+) \\(\\)" \
			$matched mvar function
		}

		if {${gdb:signaled} == "true"} {
		    if {[string match *SIGTRAP* ${gdb:siginfo}] == 0} {
			Debugger:notifyException $context \
			    [list $function] ${gdb:siginfo}
		    } {
			# Circumvent GDB problem raised by catching a SIGTRAP
			# exception which should not happen, but do occur on some
			# platforms.
			set gdb:signaled false
			gdb:send cont
			gdb:dispatch $context
		    }
		} {
		    if {$function == "mvm_eh"} {
			# An unexpected exception
			# has just be caught -- make the signal being
			# raised again telling GDB to handle it as a
			# fault this time. RE #0 should be selected
			# next on input.
			gdb:send cont
			gdb:dispatch $context
		    } {
			${gdb:bhook} $context [list $function]
		    }
		}
	    }
	}

	5 {
	    # Program exited normally
	    gdb:close $context
	    Debugger:exit $context
	}

	6 {
	    # Program exited abnormally
	    gdb:close $context
	    Debugger:exit $context $matched
	}

	7 {
	    # Program exited with code "nn"
	    gdb:close $context
	    Debugger:exit $context $matched
	}

	8 {
	    # Program terminated (SIGKILL)
	    set gdb:signaled true
	    gdb:close $context
	    Debugger:exit $context $matched
	}
    }
}

proc gdb:switchin {context focuscmd {fnum {}}} {

    global gdb:mvmcr0 gdb:mvmcr1

    # Direct stack context to the designated focus
    set scope [lindex $focuscmd 0]
    set flag [TkRequest $context GetCtlCode $scope]
    set id [lindex $focuscmd 1]

    gdb:command "set *((int *)${gdb:mvmcr0}) |= $flag"
    gdb:command "set *((int *)${gdb:mvmcr1}) = $id"
    gdb:command "call mvm_switch()"

    if {$fnum != {}} {
	# Adjust the stack level to the specified one; also
	# return the code location reached after the adjustment.
	set hotspot [gdb:movestack $context up $fnum]
	return $hotspot
    }

    return {}
}

proc gdb:switchout {context} {

    # GDB may experience problems resetting watchpoints in the
    # user-code when returning from the internal breakpoint
    # (i.e. thread context bump).  Trap this error here, and notify
    # the ISE that the faulty watchpoint has been automatically
    # disabled.

    while {1} {
	set rl [gdb:command cont - \
		{ "^warning: \[A-Za-z\]* \[Ww\]atchpoint \[0-9\]+: Could not insert watchpoint" }]
	set nre [lindex $rl 0]
	if {$nre == 0} {
	    global gdb:lasterror
	    set matched [lindex $rl 1]
	    regexp "\[Ww\]atchpoint (\[0-9\]+):" $matched mvar wpnum
	    set gdb:lasterror $matched
	    # disable the faulty watchpoint
	    gdb:disablewp $wpnum
	    # notify the front-end this watchpoint is about to be disabled
	    Debugger:notifyWatchError $context $wpnum
	    # automatically disable faulty watchpoint and resume
	} {
	    break
	}
    }
}

proc gdb:getctl {context {focuscmd {}} {fnum {}}} {

    global gdb:signaled gdb:stream

    if {${gdb:signaled} == "true"} {
	# A signaled process is always considered to be
	# in a controlled -and uncontinuable- state.
	if {$focuscmd != {}} {
	    set hotspot [gdb:switchin $context $focuscmd $fnum]
	    return $hotspot
	} {
	    return true
	}
    }

    # Wait for the debuggee to hit a breakpoint; true is returned
    # if all is ok, false if the dispatcher returned due to a
    # simulation kill.
    gdb:dispatch $context false

    if {[catch { fconfigure ${gdb:stream} -eofchar } v] == 0} {
	if {$focuscmd != {}} {
	    # when a focus is requested, return the reached code
	    # location to the caller.
	    set hotspot [gdb:switchin $context $focuscmd $fnum]
	    return $hotspot
	}
	return true
    }
    return false
}

proc gdb:relctl {context focuscmd} {

    global gdb:signaled

    if {$focuscmd != {}} {
	# Exit from bump handler first
	gdb:switchout $context
    }
    if {${gdb:signaled} == "false"} {
	gdb:send cont
    }
}

proc gdb:release {context} {

    global gdb:btcache gdb:signaled gdb:stream

    if {${gdb:signaled} == "true"} {
	# A signaled process is always considered to be
	# in an uncontinuable state.
	return
    }

    set gdb:btcache {}

    # dispatch GDB output until the debuggee stops then
    # process the next breakpoint notification...
    gdb:dispatch $context

    if {[catch { fconfigure ${gdb:stream} -eofchar } v] == 0 &&
	${gdb:signaled} == "false"} {
	# Assume that all operations needing a "hard" break
	# state are now over; give control back to the embedded
	# monitor which still remains in a stopped state. This
	# way, monitor commands can be issued and answered back
	# immediately.
	# Pretend that any signal/fault stopping the child leads
	# to an unrecoverable error state, preventing the debuggee
	# to continue.
	gdb:send cont
    }
}

proc gdb:run {context args} {

    set s run
    # This silly code assumes args are passed as a
    # list of vector args; the outer loop expands
    # the list, the second the vector.
    foreach l $args {
	foreach w $l {
	    append s " "
	    append s $w
	}
    }

    gdb:send $s
}

proc gdb:preamble {context location} {

    # Fetch the addresses of the simulation control registers. Setting
    # a register's value using its memory address is faster than
    # refering to its symbolic name, especially if the debuggee's
    # namelist is huge.

    for {set n 0} {$n < 4} {incr n} {
	global gdb:mvmcr${n}
	set rl [gdb:command "print /x &mvmcr${n}" l]
	set gdb:mvmcr${n} [lindex [lindex [lindex $rl 2] 0] 2]
    }

    # Fetch the address of our internal exception handler.
    global gdb:mvmeh
    set rl [gdb:command "print /x &mvm_eh" l]
    set gdb:mvmeh [lindex [lindex [lindex $rl 2] 0] 2]

    # Further breakpoints should be directly notified to the ISE
    global gdb:bhook
    set gdb:bhook Debugger:notifyBreak
    # Notify the ISE
    Debugger:notifyPreamble $context
    # Resume the simulation
    gdb:send cont
    gdb:dispatch $context
}

proc gdb:stop {context} {

    gdb:close $context
}

# A hard breakpoint is a native GDB breakpoint. When reached, the
# simulator is not fully in control. For instance, change of focus by
# the operator will have the undesirable side-effect of restarting the
# simulation. It is used in combination with an internal control
# command to obtain a soft breakpoint.

proc gdb:sethardbp {where} {

    set rl [gdb:command "break $where" l {"^Breakpoint [0-9]+.*"}]
    set nre [lindex $rl 0]
    set matched [lindex [lindex $rl 2] 0]

    if {$nre == 0} {
	regexp "^Breakpoint (\[0-9\]+)" $matched mvar bpnum
    } {
	global gdb:lasterror
	set gdb:lasterror $matched
	set bpnum {}
    }

    return $bpnum
}

# A soft breakpoint tells GDB to execute a debug control operation
# when the breakpoint location is hit; this operation will plan for
# the internal breakpoint to be hit as soon as the scope condition is
# met (if any) and the simulator enters a safe place to stop
# at. Because the "silent" option is passed, no code location will be
# output by GDB when this breakpoint is hit thus this interface will
# just not know about the hard breakpoint.

proc gdb:setsoftbp {context focuscmd file lineno} {

    global gdb:mvmcr0 gdb:mvmcr1

    set where [join [list [file tail $file] : $lineno] ""]
    set bpnum [gdb:sethardbp $where]

    if {$bpnum == {}} {
	return {}
    }

    gdb:send "commands"
    gdb:send "silent"
    set scope [lindex $focuscmd 0]
    set flag [TkRequest $context GetCtlCode DEBUGTRAP_BREAK $scope]
    set id [lindex $focuscmd 1]

    gdb:send "set *((int *)${gdb:mvmcr0}) |= $flag"
    gdb:send "set *((int *)${gdb:mvmcr1}) = $id"
    gdb:send "continue"
    gdb:send "end"

    gdb:waitprompt

    return $bpnum
}

proc gdb:setbpcondition {bpnum cond} {

    global gdb:lastexpr
    set gdb:lastexpr $cond
    set rl [gdb:command "condition $bpnum $cond" l]
    set emsg [lindex [lindex $rl 2] 0]
    if {$emsg != {} && $cond != {}} {
	# ignore GDB ack on condition removal, otherwise GDB
	# should remain silent after trying to set a condition
	global gdb:lasterror
	set gdb:lasterror $emsg
	set bpnum {}
    }
    return $bpnum
}

proc gdb:removebp {bpnum} {
    gdb:command "delete $bpnum"
}

proc gdb:disablebp {bpnum} {
    gdb:command "disable $bpnum"
    return true
}

proc gdb:enablebp {bpnum} {
    gdb:command "enable $bpnum"
}

# Query breakpoint location given its internal id.
# number.

proc gdb:getbpinfo {bpnum} {

    set rl [gdb:command "info breakpoints $bpnum" l \
		{ "^\[0-9\]+.*0x\[0-9a-fA-F\]+ in \[^ \]+(\\(.*\\))? at \[^ \]+$" \
		"^\[0-9\]+.*0x\[0-9a-fA-F\]+ +<.*>$" } ]
    set nre [lindex $rl 0]
    set matched [lindex $rl 1]
    set location [list 0 0x0]

    # find out breakpoint information. (note: we could have used gdb's
    # "list *<expr>" syntax to get to the same result).

    switch -- $nre {
	0 {
	    # (symbolic information available)
	    # the way we retrieve the source file name is a bit tricky, but
	    # let GDB resolve the source directory bummer for us. The steps
	    # are as follows:
	    # 1st- retrieve the file position expr returned by the last
	    # breakpoint information query. This information is given
	    # in the form <file>:<lineno>.
	    # 2nd- ask GDB to consider this file as the current source;
	    # "list $filepos,$filepos" makes GDB do the switch and
	    # list a single -unused- line from this file.
	    # 3rd- query information about the current source (i.e.
	    # the file where the breakpoint has been set). A line of the
	    # output log starting with "Located in" gives the actual full
	    # pathname of the current file.

	    if {[regexp "^\[0-9\]+.*(0x\[0-9a-fA-F\]+) in (\[^ (\]+)(\\(.*\\))? at (\[^ \]+)$" \
		     $matched mvar addr function cplusplus filepos] == 1} {
		gdb:command "list $filepos,$filepos"
		set rl [gdb:command "info source" l]
		set log [lindex $rl 2]
 		set fileloc [lindex $log [lsearch -regexp $log "^Located in.*"]]
		regexp "^Located in (\[^ \]+)$" $fileloc mvar file
		regexp ".*:(\[0-9\]+)$" $filepos mvar lineno
		set location [list $addr $function $file $lineno]
	    }
	}

	1 {
	    # (no symbolic information available)
	    if {[regexp "^\[0-9\]+.*(0x\[0-9a-fA-F\]+) +<(\[^ (]+)(\\(.*\\))?(\\+.*)>$" \
		     $matched mvar addr function cplusplus offset] == 1} {
		set location [list $addr $function]
	    }
	}
    }

    return $location
}

proc gdb:setwatchpoint {context cond} {

    global gdb:wpsupport gdb:mvmcr0
    global gdb:lastexpr

    if {${gdb:wpsupport} == "unknown"} {
	set rl [gdb:command "awatch *((int *)${gdb:mvmcr0})" l \
	{ "Target does not have this type of hardware watchpoint support." \
	  ".* watchpoint \[0-9\]+.*:"}]
	set nre [lindex $rl 0]
	if {$nre == 0} {
	    set gdb:wpsupport no
	} {
	    if {$nre == 1} {
		set matched [lindex $rl 1]
		regexp ".* watchpoint (\[0-9\]+):" $matched mvar wpnum
		gdb:command "delete $wpnum"
		set gdb:wpsupport yes
	    }
	}
    }

    if {${gdb:wpsupport} != "yes"} {
	if {[tk_messageBox \
		 -message "GDB: there is no hardware support for watchpoints\
on this platform. Using them will dramatically slow the simulation \
(and the ISE) down. Are you sure you still want to do that?" \
		 -type yesno -icon warning -title Warning] == "no"} {
	    global gdb:lasterror
	    set gdb:lasterror "No hardware support for watchpoints."
	    return {}
	}
    set gdb:wpsupport yes
    }

    set gdb:lastexpr $cond
    set rl [gdb:command "watch $cond" l \
		{ "^\[A-Za-z \]*\[Ww\]atchpoint \[0-9\]+.*:" \
		      "^No symbol table.*" \
		      "^No symbol .*" }]
    set nre [lindex $rl 0]
    set matched [lindex $rl 1]

    if {$nre == 0} {
	regexp "^\[A-Za-z \]*\[Ww\]atchpoint (\[0-9\]+):" $matched mvar wpnum
    } {
	global gdb:lasterror
	set gdb:lasterror [lindex [lindex $rl 2] 0]
	return {}
    }

    # Note: GDB randomly crashes when attempting to execute commands
    # involving function calls in the user code after a watchpoint is reached.
    # So don't even try to use the "call" feature from a breakpoint command
    # list. Instead, we directly write into the debug control register of the
    # simulator to schedule a break state at the next code preemption.

    gdb:send "commands"
    gdb:send "silent"
    set flag [TkRequest $context GetCtlCode WATCHPOINT_BREAK]
    gdb:send "set *((int *)${gdb:mvmcr0}) |= $flag"
    gdb:send "continue"
    gdb:send "end"
    gdb:waitprompt

    return $wpnum
}

proc gdb:removewp {wpnum} {
    gdb:command "delete $wpnum"
}

proc gdb:disablewp {wpnum} {
    gdb:command "disable $wpnum"
    return true
}

proc gdb:enablewp {wpnum} {
    gdb:command "enable $wpnum"
}

proc gdb:fatal {context errmsg} {
    gdb:close $context
    Debugger:exit $context $errmsg
}

proc gdb:movestack {context whence {levels 1}} {

    # Move up/down in the current stack and return the new code
    # location. GDB output PC locations differently whether it has
    # found debug information or not for the code spot.

    set nre {}
    set log {}
    set matched {}

    set rl [gdb:command "$whence $levels" l \
		 { "^\032\032.*" \
 		       "^#\[0-9\]+ +0x\[0-9a-fA-F\]+ in \[^ \]+ \\(\\)$" }]
    set nre [lindex $rl 0]
    set matched [lindex $rl 1]
    set log [lindex $rl 2]

    if {$nre == -1} {
	gdb:fatal $context "debugger died unexpectedly!?"
	return {}
    }

    set hotspot {}
    set pos [lsearch -regexp $log "^#\[0-9\]+.*"]

    switch -- $nre {
	    0 {
		# ^Z^Z RE matched: find function name in log
		if {[regexp "^#\[0-9\]+ +0x\[0-9a-fA-F\]+ in (\[^ \]+) .*" \
			 [lindex $log $pos] mvar function] == 0} {
		    regexp "^#\[0-9\]+ +(\[^ \]+) \\(.*" \
			[lindex $log $pos] mvar function
		}
		set l [split $matched :]
		set sourcefile [string range [lindex $l 0] 2 end]
		set lineno [lindex $l 1]
		set hotspot [list $function $sourcefile $lineno]
	    }

	    default {
		# debug-disabled code  RE matched: extract function name
		# this may also occur if the source file cannot be reached
		# by GDB (e.g. wrong source directory list).
 		if {[regexp "^#\[0-9\]+ +0x\[0-9a-fA-F\]+ in (\[^ \]+).*" \
 			 [lindex $log $pos] mvar function] == 0} {
 		    regexp "^.*, (\[_a-zA-Z\]+) \\(\\)" \
			[lindex $log $pos] mvar function
		}
		# matching could fail (in currently unknown cases)
		# so be conservative and catch error if function
		# has not been identified properly.
		catch { set hotspot [list $function] }
	    }
    }

    return $hotspot
}

proc gdb:seek {context focuscmd location {focusvar {}} {localsvar {}}} {

    global gdb:mvmcr0 gdb:mvmcr1 gdb:mvmcr2

    # Direct stack context to the designated focus
    set scope [lindex $focuscmd 0]
    set flag [TkRequest $context GetCtlCode $scope]
    set id [lindex $focuscmd 1]

    gdb:command "set *((int *)${gdb:mvmcr0}) |= $flag"
    gdb:command "set *((int *)${gdb:mvmcr1}) = $id"
    set rl [gdb:command "call mvm_switch()" - {"^Breakpoint [0-9]+.*" }]

    if {$focusvar != {}} {
	# Fetch the current focus as a C string stored in the mvmcr2
	# control register. Note the explicit cast to pointer to character
	# in order to force a C string as a result, even if the module
	# implementing this routine does not include any debug
	# information (i.e. was not compiled using the -g option).
	# Otherwise, GDB would have output a signed integer representing
	# the value of the returned pointer, which is not what we asked for.
	set rl [gdb:command "print *((char **)${gdb:mvmcr2})" l "\$.*"]
	set matched [lindex $rl 1]
	# fetch current focus
	upvar $focusvar curfocus
	regexp "\[^\"\]+.(\[^\"\]+).*" $matched mvar curfocus
    }

    # query stack information -- auto-limit to the inner last 32
    # frames in order to work-around the issue GDB 6.x has with
    # ucontext(2) driven co-routines.
    set rl [gdb:command "where 32" ls]
    set stackinfo [lindex $rl 2]

    if {$stackinfo == {}} {
	upvar $location _location
	set _location {preamble}
	# no stack (i.e. no root level found)? this must be a thread preamble.
	return {}
    }

    # Find out at least the function name, and if possible, the source
    # file and the line number of the outer code location where we stopped.
    # The C++ support has already made the harder stuff, filtering out
    # internal frames and returned a significant stack information log of
    # the following format: { {fnum {frame-info}} {fnum2 {frame-info2}} ...} 
    # ordered from outer to inner locations.
    # We finish the job by searching for the outer viewable piece of code
    # (if any).

    upvar $location hotspot
    set oldfnum 0
    set viewspot {}
    set hotspot {}
    set ups 0

    foreach frame $stackinfo {
	set fnum [lindex $frame 0]
	set fdisp [expr $fnum - $oldfnum]
	# Note: "up 0" makes GDB nicely repeat its current location
	set _hotspot [gdb:movestack $context up $fdisp]

	if {$_hotspot == {}} {
	    # something weird happened!
	    return {}
	}
	if {$ups == 0} {
	    set hotspot $_hotspot
	}

	incr ups $fdisp

	if {[llength $_hotspot] > 1} {
	    # got debug information for this one
	    set viewspot $_hotspot
	    break
	}
	set oldfnum $fnum
    }

    if {[llength $hotspot] == 1 && $viewspot != {}} {
	# append a visible code location to the outer
	# function name (where we stopped). A ? prefix
	# is prepended to inform our caller that the function
	# name does not match the returned code location.
	set hotspot [concat ? $hotspot [lrange $viewspot 1 end]]
	# reset the stack pointer down to the outer frame
	gdb:movestack $context down $ups
    }

    if {$localsvar != {}} {
	# query locals list as needed
	upvar $localsvar locals
	set locals [gdb:getlocals]
    }

    return $stackinfo
}

proc gdb:backtrace {context focuscmd location focusvar {localsvar {}}} {

    global gdb:btcache

    upvar $location _location
    upvar $focusvar _focusvar

    if {$localsvar != {}} {
 	upvar $localsvar _localsvar
 	set locals _localsvar
	# never reuse the cache if locals are wanted.
	set gdb:btcache {}
     } {
 	set _localsvar {}
 	set locals {}
     }

    if {[lindex ${gdb:btcache} 0] != $focuscmd} {
	set stackinfo [gdb:seek $context \
			   $focuscmd _location _focusvar $locals]
	if {$stackinfo != {}} {
	    set gdb:btcache [list $focuscmd $stackinfo $_location \
				 $_focusvar $_localsvar]
	} {
	    set _location {$kprea$}
	    set _focusvar {preamble}
	}
	# exit from thread bump call() before returning
	gdb:switchout $context

    } {
	set stackinfo [lindex ${gdb:btcache} 1]
	set _location [lindex ${gdb:btcache} 2]
	set _focusvar [lindex ${gdb:btcache} 3]
    }

    return $stackinfo
}

proc gdb:down {context focuscmd fnum} {

    set location {}
    gdb:seek $context $focuscmd location

    if {$fnum > 0} {
	gdb:command "up $fnum"
    }

    set hotspot [gdb:movestack $context down]
    # exit from thread bump call() before returning
    gdb:command cont

    return $hotspot
}

proc gdb:up {context focuscmd fnum} {

    set location {}
    gdb:seek $context $focuscmd location
    set levels [expr $fnum + 1]

    set hotspot [gdb:movestack $context up $levels]
    # exit from thread bump call() before returning
    gdb:command cont

    return $hotspot
}

proc gdb:getdata {expr format treestyle} {

    global gdb:lastexpr

    set gdb:lastexpr $expr
    switch -exact -- $format {
       octal { set fmt o }
       decimal { set fmt d }
       unsigned { set fmt u }
       binary { set fmt t }
       float { set fmt f }
       address { set fmt a }
       char { set fmt c }
       hex { set fmt x}
       default { set fmt ""}
    }
    set rl [gdb:command "output /${fmt} $expr" l]
    set log [lindex $rl 2]

    if {${treestyle} == "true"} {
	set log [gdb:parsedata $log]
    } {
	# if no tree formatting is requested, perform some sanity
	# checks on the returned value.
	set s [lindex $log 0]
	if {$s == {} ||
	    [regexp "^Attempt .*" $s] == 1 ||
	    [regexp "^No symbol .*" $s] == 1 ||
	    [regexp "^A parse error .*" $s] == 1} {
	    # oops, does not look good! tell caller to forget it...
	    global gdb:lasterror
	    set gdb:lasterror $log
	    set log {}
	}
    }
    return $log
}

proc gdb:followdata {expr} {

    # followdata always requires tree style formatting
    return [gdb:getdata [format "*(%s)" $expr] "no_format" true]
}

proc gdb:dumpdata {expr format count size} {

    global gdb:lastexpr

    # compute format and size letters
    switch -exact -- $format {
	octal { set fmt o }
	decimal { set fmt d }
	unsigned { set fmt u }
	binary { set fmt t }
	float { set fmt f }
	address { set fmt a }
	char { set fmt c }
	string { set fmt s }
	instruction { set fmt i}
	default { set fmt x }
    }
    switch -exact -- $size {
	short { set sz h }
	long { set sz w }
	giant { set sz g }
	default -
	byte { set sz b }
    }

    set gdb:lastexpr $expr
    set rl [gdb:command "x/${count}${fmt}${sz} $expr" l]
    set log [lindex $rl 2]
    set s [lindex $log 0]

    if {$s == {} ||
	[regexp "^0x\[0-9A-Fa-f\]*:\[ \t\]*Cannot access memory.*" $s] == 1 ||
	[regexp "^Attempt .*" $s] == 1 ||
	[regexp "^No symbol .*" $s] == 1 ||
	[regexp "^A parse error .*" $s] == 1} {
	# oops, does not look good! tell caller to forget it...
	global gdb:lasterror
	set gdb:lasterror $log
	set log {}
    }
    return $log
}

proc gdb:setdata {lhs rhs} {

    # GDB's set command does not output anything unless
    # something wrong happened. Thus, this procedure's
    # return value is an error message on failure, or
    # nil if all is ok.
    set rl [gdb:command "set $lhs = $rhs" l]
    return [lindex $rl 2]
}

proc gdb:typeinfo {expr} {

    global gdb:lastexpr

    set gdb:lastexpr $expr

    set rl [gdb:command "ptype $expr" l]
    set nre [lindex $rl 0]
    set log [lindex $rl 2]

    if {$nre == -1} {
	return {}
    }
    
    set s [lindex $log 0]
    
    if {$s == {} || [regexp "^type = .*" $s] == 0} {
	# oops, does not look good! tell caller to forget it...
	set log {}
    } {
	# prepend the expression to the result -- note that
	# the tricky way to do this is absolutely needed
	# for Tcl lists evaluation reasons.
	set expr [format "\"%s\" " $expr]
	set s [concat $expr $s]
	set log [lreplace $log 0 0 $s]
    }

    return $log
}

proc gdb:getlocals {} {

    set rl1 [gdb:command "info args" l]
    set rl2 [gdb:command "info locals" l]
    set locals {}

    # Ensure each variable is unique.
    foreach line [concat [lindex $rl1 2] [lindex $rl2 2]] {
	# ...allow $ in identifiers...
	if {[regexp "^(\[a-zA-Z_\]\[a-zA-Z0-9_\$\]*) =.*" $line mvar varname] == 1} {
	    if {[lsearch -regexp $locals "^$varname"] == -1} {
		lappend locals $varname
	    }
	}
    }

    return $locals
}

proc gdb:setsrc {srcDirs} {
    global gdb:btcache
    # Setup source directories list (if empty,
    # GDB will reset it to the default ($cdir:$cwd))
    gdb:command "directory $srcDirs"
    # flush the backtrace cache to allow reevaluation
    # of current hotspot
    set gdb:btcache {}
}

proc gdb:locate {expr} {

    set rl [gdb:command "info line $expr" - \
		{ "^\032\032.*" \
		  "^Line number \[0-9\]+ is out of range.*" }]
    set nre [lindex $rl 0]
    set matched [lindex $rl 1]

    if {$nre == -1} {
	return {}
    }

    switch -- $nre {
	    0 {
		# ^Z^Z RE matched (usually for a function)
		set l [split $matched :]
		set sourcefile [string range [lindex $l 0] 2 end]
		set lineno [lindex $l 1]
	    }

	    1 {
		# Found a match, but we should help GDB to find the
		# actual file name (GDB seems to be confused when
		# trying to determine the location of a data
		# declaration -- in fact, GCC emits a N_SO stab with
		# the main input filename as value, which is our
		# temporary file path when compiling, not the original
		# one we cautiously kept unchanged from the line
		# information directives, and GDB uses it to search
		# for the source location, damn it!)
 		if {[regexp "^Line number (\[0-9\]+) is out of range for \"(.*)\".*" \
 			 $matched mvar lineno sourcefile] == 0} {
		    set lineno 0
		    set sourcefile {}
		} {
		    # This is a hack to work around the state of
		    # confusion GDB seems to experience with the
		    # source information of data symbols as tweaked by
		    # the C/C++ instrumenter.  this hack has a flaw:
		    # if multiple files share the same base name, the
		    # first one returned by GDB will always be
		    # picked. However, this is harmless for the debug
		    # session.  HACKHACK: we DO KNOW that gcic
		    # prepends the 'ic1@' string in front of the
		    # original source file to compose the temporary
		    # file name. So we have to remove it when asking
		    # GDB to find this file using its original
		    # name. Sorry for this...
		    # FIXME: maybe not needed by GCIC since data are
		    # not vectorized anymore?
		    set basename [file tail $sourcefile]
		    if {[string match ic1@* $basename]} {
			set basename [string range $basename 4 end]
		    }
		    gdb:command "list $basename:1,1"
		    set rl [gdb:command "info source" l]
		    set log [lindex $rl 2]
		    set fileloc [lindex $log [lsearch -regexp $log "^Located in.*"]]
		    regexp "^Located in (\[^ \]+)$" $fileloc mvar sourcefile
		}
	    }

	    default {
		# not found
		set lineno 0
		set sourcefile {}
	    }
    }

    return [list $sourcefile $lineno]
}
