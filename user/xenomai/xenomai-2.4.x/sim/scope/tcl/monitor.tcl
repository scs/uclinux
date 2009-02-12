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
#  Contributor(s): ym
#
#  Adapted to XENOMAI by Philippe Gerum.

# NOTE: All monitor globals are project-dependent or
# runtime-dependent, except Monitor:slaveMode which
# is session-dependent.
# server socket handle
set Monitor:server {}
# Working directory of simulation
set Monitor:channel {}
# polling timer handle
set Monitor:timer {}
# watchdog timer handle
set Monitor:watchdog {}
# last received simulation time stamp
set Monitor:currentTime {}
# simulator init state
set Monitor:initState fail
# simulation process state
set Monitor:simulationState dead
# per-condition stop icon table
set Monitor:stopIcons { \
    brkuncond brktimer brkgraph brktrace \
    brkerror brkdebug brkwatch brkassert \
    brksmile \
}
# last stop condition index
set Monitor:stopCond -1
# False if debugger active, True otherwise
# C++ linkvar: boolean Monitor:standaloneRun
# False if connection master, True if slave
# C++ linkvar: boolean Monitor:slaveMode

proc Monitor:initialize {context} {

    global Monitor:main

    ### create the error log window - this window is never destroyed
    ### but its content is flushed when the simulation starts to keep
    ### the messages available, even after a fatal error.

    set Monitor:main $context

    toplevel $context
    wm title $context "Error Log"
    wm geometry $context 700x400
    wm withdraw $context
    wm protocol $context WM_DELETE_WINDOW "wm withdraw $context"
    # make this window appear in the workspace's "Windows" menu for fast access
    TkRequest $context CacheWindowIn $context "Error log"

    set mbar [frame $context.mbar -relief groove]
    pack $mbar -side top -fill x

    menubutton $mbar.file -text File \
	-menu $mbar.file.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.file.m -tearoff false

    $mbar.file.m add command -label "Save log" \
	-command "Monitor:saveErrorLog $context" \
	-underline 0

    $mbar.file.m add command -label "Clear log" \
	-command "Monitor:clearErrorLog $context" \
	-underline 0

    $mbar.file.m add sep

    $mbar.file.m add command -label Close \
	-command "wm withdraw $context" \
	-underline 0

    pack $mbar.file -side left

    tixScrolledText $context.log -options {
	text.spacing1 0
	text.spacing3 0
	text.state disabled
	text.height 12
    }

    pack $context.log -side top -expand yes -fill both

    ### register trace hook to get informed of major context changes
    traceEvent Application:event \
	eventQueue:$context \
	"Monitor:processGlobalEvent $context"
}

proc Monitor:displayErrorLog {context} {
	wm deiconify $context
	raise $context
}

proc Monitor:saveErrorLog {context} {

    set w $context.savelog

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	return
    }

    toplevel $w
    wm title $w "Save Error Log"
    cascadeWindow $w $context
    
    set f [frame $w.f -relief sunken -bd 1]
    pack $f

    tixFileEntry $f.logfile -label "To file: " \
	-validatecmd "Monitor:valErrorLogFileName" \
	-dialogtype tixFileSelectDialog \
 	-options {
 	    entry.width 25
 	    label.anchor e
	}
    pack $f.logfile -side top -anchor e -padx 10 -pady 10

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add update -text Save \
 	-command "Monitor:saveErrorLogOk $context"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus [$f.logfile subwidget entry]
}

proc Monitor:saveErrorLogOk {context} {

    set w $context.savelog
    $w.f.logfile update
    set filename [$w.f.logfile cget -value]

    if {$filename == ""} {
	tk_messageBox -parent $context \
	    -message "No log file selected" \
	    -type ok -icon error -title " "
	return
    }

    if {[file exists $filename] == 1} {
    	if {[tk_messageBox -parent $context \
		 -message "File already exists. Overwrite it?" \
		 -type yesnocancel -icon error -title " "] != "yes"} {
	    return
	}
    }

    if {[catch {open $filename w} fh]} {
	# File can't be written.
    	tk_messageBox -parent $context \
	    -message "Cannot write to file $filename" \
	    -type ok -icon error -title " "
	return
    }

    set textw [$context.log subwidget text]
    puts -nonewline $fh [$textw get 1.0 end]
    close $fh
    destroy $w
}

proc Monitor:valErrorLogFileName {path} {

    if {[catch {if {$path != ""} {
	if {[file isdirectory $path] == 1} {
	    return ""
	}
	if {[file extension $path] == {}} {
	    append path ".err"
	}
    }}] == 1} {
	return ""
    }

    return $path
}

proc Monitor:clearErrorLog {context} {

    if {[tk_messageBox -parent $context \
	     -message "Are you sure? Please confirm." \
	     -type okcancel -icon error -title " "] != "ok"} {
	return
    }

    set textw [$context.log subwidget text]
    $textw configure -state normal
    $textw delete 1.0 end
    $textw configure -state disabled
}

proc Monitor:run {context flags} {

    global Monitor:standaloneRun Project:settings

    set Monitor:standaloneRun 1
    set port [set Project:settings(ServerPort)]
    set executable [set Project:settings(Executable)]
    set args [Monitor:getMvmArgs $flags]
    pushEvent Application:event SimulationStartedEvent
    Monitor:tcpListen $context $port

    set s {}
    foreach l $args {
	foreach w $l {
	    append s " "
	    append s $w
	}
    }

    if {[catch { eval exec -- $executable $s & }] == 1} {
	Monitor:tcpTimeout $context
	tk_messageBox \
	    -message "Cannot exec \"$executable\"" \
	    -type ok -icon error -title " "
    }
}

proc Monitor:attachSimulation {context port} {

    global Monitor:standaloneRun

    set Monitor:standaloneRun 1
    pushEvent Application:event SimulationStartedEvent
    Monitor:tcpConnect $context $port
}

proc Monitor:tcpListen {context port} {

    global Monitor:server Monitor:watchdog Project:settings

    while {1} {
	if {[catch { set Monitor:server \
			 [socket -server "Monitor:tcpAccept $context" $port]}] == 0} {
	    break
	}
	after 500
    }

    if {[set Project:settings(Watchdog)] != 0} {
	set Monitor:watchdog \
	    [after [expr [set Project:settings(Watchdog)] * 1000] \
		 "Monitor:tcpTimeout $context"]
    }
}

proc Monitor:tcpTimeout {context} {
    global Monitor:watchdog
    set Monitor:watchdog {}
    Monitor:tcpDown $context
}

proc Monitor:tcpAccept {context channel addr port} {

    global Monitor:channel Monitor:server Monitor:watchdog
    global Monitor:initState

    set Monitor:initState fail

    if {${Monitor:watchdog} != {}} {
	after cancel ${Monitor:watchdog}
	set Monitor:watchdog {}
    }
    catch { close ${Monitor:server} }
    set Monitor:server {}
    set Monitor:channel $channel
    fconfigure $channel -translation binary -blocking true
    TkRequest $context RegisterChannel $channel
    fileevent $channel readable "TkRequest $context PollChannel"
    pushEvent Application:event MonitorConnectEvent
}

proc Monitor:tcpConnect {context port} {

    global Monitor:channel Monitor:initState

    set Monitor:initState fail

    if {[catch { set channel [socket localhost $port] }] == 1} {
	return -1
    }

    set Monitor:channel $channel
    fconfigure $channel -translation binary -blocking true
    TkRequest $context RegisterChannel $channel
    fileevent $channel readable "TkRequest $context PollChannel"
    pushEvent Application:event MonitorConnectEvent

    return $port
}

proc Monitor:tcpDown {context} {

    global Monitor:channel Monitor:standaloneRun
    global Monitor:simulationState Monitor:timer
    global Monitor:server Monitor:watchdog
    global Project:settings

    if {${Monitor:timer} != {}} {
	after cancel ${Monitor:timer}
	set Monitor:timer {}
    }

    if {${Monitor:server} != {}} {
	catch { close ${Monitor:server} }

	if {${Monitor:watchdog} != {}} {
	    after cancel ${Monitor:watchdog}
	    set Monitor:watchdog {}
	}
    }

    set Monitor:simulationState dead

    catch { close ${Monitor:channel} }
    TkRequest $context UnregisterChannel
    set Monitor:channel {}
    # this event warns about imminent disconnection -- current
    # runtime parameters should be saved upon receiving it given
    # that ISE objects are still alive.
    pushEvent Application:event MonitorShutdownEvent
    # house-keeping chores are done -- object deletion may be applied
    pushEvent Application:event MonitorDisconnectEvent

    if {${Monitor:standaloneRun} == 1} {
	# if the monitor started the simulation without
	# debugging support --> send the appropriate
	# event to reset the desktop actions (i.e. menus)
	set Monitor:standaloneRun 0
	pushEvent Application:event SimulationKilledEvent
    }

    if {[set Project:settings(Options,popupOnWarnings)] == 1} {
	# pop-down the error log at disconnection if the user has
	# selected the automatic-popup mode. Otherwise, let him do it
	# by hand when he wants to.
	wm withdraw $context
    }
}

proc Monitor:childDeath {context} {

    global Monitor:standaloneRun

    # save a copy of standalone flag which will be cleared
    # by the tcpDown proc.
    set alone ${Monitor:standaloneRun}
    Monitor:tcpDown $context

    # If the monitor is running alone, give the user some
    # feedback. Otherwise, expect the debugger will do it.
 
    if {$alone == 1} {
	bell
	tk_messageBox \
	    -message "Application died" \
	    -type ok -icon warning -title Warning
    }
}

proc Monitor:errorNotified {context errlog} {
 
    global Project:settings

    set textw [$context.log subwidget text]
    $textw configure -state normal
    $textw insert end [join $errlog]
    $textw configure -state disabled
    $textw see end

    if {[set Project:settings(Options,popupOnWarnings)] == 1} {
 	if {[wm state $context] != "normal"} {
 	    wm deiconify $context
 	    bell
 	}
 	raise $context
     }
}

proc Monitor:coldNotified {context} {

    pushEvent Application:event SimulationColdEvent
}

proc Monitor:warmNotified {context fatalCount} {

    if {$fatalCount == 0} {
	# tell the world...
	pushEvent Application:event SimulationWarmEvent
    }
}

proc Monitor:readyNotified {context} {

    pushEvent Application:event SimulationReadyEvent
}

proc Monitor:releaseNotified {context} {
    pushEvent Application:event SimulationReleasedEvent
}
    
proc Monitor:finishNotified {context} {
    global Monitor:simulationState
    set Monitor:simulationState zombie
    pushEvent Application:event SimulationFinishedEvent
}

proc Monitor:holdNotified {context condition} {
    global Monitor:stopCond
    set Monitor:stopCond $condition
    pushEvent Application:event SimulationHeldEvent
}

proc Monitor:timeNotified {context time} {
    global Monitor:currentTime
    set Monitor:currentTime $time
    pushEvent Application:event TimeUpdateEvent
}

proc Monitor:registerThread {context tid tname} {
    pushEvent Application:event ThreadCreatedEvent
}

proc Monitor:unregisterThread {context tid tname} {
    pushEvent Application:event ThreadDeletedEvent
}

proc Monitor:pollTime {context} {

    global Monitor:timer
    TkRequest $context PollTime
    set Monitor:timer [after 500 "Monitor:pollTime $context"]
}

proc Monitor:getState {context} {
    global Monitor:simulationState
    return ${Monitor:simulationState}
}

proc Monitor:getStopIcon {} {

    global Monitor:stopCond Monitor:stopIcons Monitor:simulationState

    if {${Monitor:simulationState} == "released"} {
	return {}
    }
    return [lindex ${Monitor:stopIcons} ${Monitor:stopCond}]
}

proc Monitor:getMvmArgs {flags} {

    global Project:settings Workspace:errorLogFile

    set args [concat "-p" [set Project:settings(ServerPort)]]

    if {[set Project:settings(WorkingDir)] != {}} {
	lappend args [concat "-d" [set Project:settings(WorkingDir)]]
    }

    file delete ${Workspace:errorLogFile}
    lappend args [concat "-l" ${Workspace:errorLogFile}]

    if {[set Project:settings(Options,breakOnWarnings)] == 1} {
	append flags w
    }
    if {[set Project:settings(Options,breakOnAlerts)] == 1} {
	append flags a
    }
    if {[set Project:settings(Options,virtualTime)] == 1} {
	append flags v
    }
    if {[set Project:settings(Options,traceKernel)] == 1} {
	append flags 0
    }
    if {[set Project:settings(Options,traceIface)] == 1} {
	append flags 1
    }
    if {[set Project:settings(Options,traceApp)] == 1} {
	append flags 2
    }

    if {$flags != {}} {
	lappend args [concat "-X" $flags]
    }

    lappend args [concat "-t" [stringMap {" " {}} [set Project:settings(SimulationTime)]]]
    lappend args [concat "-w" [stringMap {" " {}} [set Project:settings(WarmupTime)]]]
    lappend args [concat "-k" [stringMap {" " {}} [set Project:settings(DisplayTick)]]]
    lappend args [concat "-s" [set Project:settings(SampleCount)]]
    lappend args [concat "-u" [set Project:settings(TimeUnit)]]
    lappend args [concat "-W" [set Project:settings(WarpFactor)]]

    if {[set Project:settings(LocalArgs)] != {}} {
	lappend args [set Project:settings(LocalArgs)]
    }

    return $args;
}

proc Monitor:processGlobalEvent {context name1 name2 op} {

    while {[popEvent eventQueue:$context e] == "true"} {
	switch $e {

	    DebuggerAbortEvent -
	    DebuggerStoppedEvent {
		global Monitor:server Monitor:channel Monitor:watchdog
		if {${Monitor:server} != {}} {
		    catch { close ${Monitor:server} }
		    if {${Monitor:watchdog} != {}} {
			after cancel ${Monitor:watchdog}
			set Monitor:watchdog {}
		    }
		}
		if {${Monitor:channel} != {}} {
		    Monitor:tcpDown $context
		}
	    }

	    SimulationHeldEvent -
	    DebuggeeHeldEvent {
		global Monitor:timer Monitor:simulationState
		if {${Monitor:timer} != {}} {
		    after cancel ${Monitor:timer}
		    set Monitor:timer {}
		}
		if {${Monitor:simulationState} == "released"} {
		    set Monitor:simulationState held
		}
	    }

	    SimulationWarmEvent -
	    SimulationReleasedEvent -
	    DebuggeeReleasedEvent {
		global Monitor:channel Monitor:timer
		global Monitor:simulationState
		global Monitor:initState
		if {${Monitor:channel} != {}} {
		    if {${Monitor:timer} == {}} {
			set Monitor:timer [after 500 "Monitor:pollTime $context"]
		    }
		    set Monitor:simulationState released
		    set Monitor:initState ok
		}
	    }

	    MonitorConnectEvent {
		# clear error log
		set textw [$context.log subwidget text]
		$textw configure -state normal
		$textw delete 1.0 end
		$textw configure -state disabled
	    }
	}
    }
}
