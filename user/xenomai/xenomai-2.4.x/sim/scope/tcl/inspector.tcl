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

set Inspector:eventHooks {}
set Inspector:activeDashboards {}

proc Inspector:initialize {context} {

    global tkbridge_prefixdir auto_path

    # Update autopath with rt-iface plugin libs
 
    foreach dir [globDir $tkbridge_prefixdir/share/xenosim/tcl] {
	lappend auto_path $dir
    }

    ### Register trace hook to get informed of major context changes

    traceEvent Application:event \
	eventQueue:$context \
	"Inspector:processGlobalEvent $context"
}

# Note: the inspector frame can be laid on its own toplevel if running
# under the debugger control, or on the main window if not
# (i.e. direct launch from the "Simulation" menu). The boolean variable
# Monitor:standaloneRun is used to distinguish from both cases
# ("false" means under debugger control).

proc Inspector:configure {context} {

    global Application:treeSeparator Monitor:standaloneRun
    global Inspector:activeDashboards Inspector:eventHooks

    set Inspector:eventHooks {}
    set Inspector:activeDashboards {}

    if {${Monitor:standaloneRun} == 1} {
	global Workspace:statusBar
	frame $context -bd 1 -relief groove
	pack $context -before ${Workspace:statusBar} -expand yes -fill both
    } {
	toplevel $context
	wm title $context Inspector
	wm protocol $context WM_DELETE_WINDOW "wm withdraw $context"
	bind $context <Escape> "wm withdraw $context"
	wm withdraw $context
	TkRequest $context CacheWindowIn $context Inspector 
	cascadeWindow $context
    }

    tixNoteBook $context.nb -ipadx 6 -ipady 6

    if {${Monitor:standaloneRun} == 1} {
	# use h/w sizes approximating debugger's main
	# frame dimensions
	$context.nb config -height 300 -width 600
	# note: no InspectorHiddenEvent can be thrown in
	# this mode...
	pushEvent Application:event InspectorVisibleEvent
    } {
	$context.nb config -height 350 -width 450
    }

    pack $context.nb -expand yes -fill both -padx 5 -pady 5 -side top

    $context.nb add displaytab -label System
    set w [$context.nb subwidget displaytab]
    set tree [tixTree $w.t]
    $tree config -command "Inspector:displayDashboard $context $tree"

    set hlist [$tree subwidget hlist]
    $hlist configure \
	-separator ${Application:treeSeparator} \
	-drawbranch false \
	-selectmode single \
	-drawbranch false \
	-wideselect false \
	-width 30

    pack $tree -side top -fill both -expand yes -padx 5

    if {${Monitor:standaloneRun} == 0} {
	tixButtonBox $context.bbox -orientation horizontal -relief flat -bd 0
	$context.bbox add dismiss -text Close -command "wm withdraw $context"
	pack $context.bbox -side bottom -fill x
    }

    pushEvent Application:event InspectorConfigureEvent
}

proc Inspector:reset {context} {

    destroy $context
}

proc Inspector:addDashboard {context object objdesc cmdprefix} {
    
    global Application:treeSeparator

    if {![winfo exists $context.nb]} {
	# this can happen if the simulation is aborted
	# during startup
	return
    }

    set tree [$context.nb subwidget displaytab].t
    set hlist [$tree subwidget hlist]
    set n 1
    set path {}
    set objpath [lindex $objdesc 0]
    set icon [lindex $objdesc 1]
    if {$icon == {}} {
	# no icon specified -- defaults to "kobj"
	set icon kobj
    }
    set nmax [llength $objpath]

    foreach level $objpath {

	append path $level

	catch {
	    # ignore Tix complaints about multiple level
	    # definitions...
	    if {$n == $nmax} {
		set ndata [list $object $cmdprefix $level]
		$hlist add $path -itemtype imagetext -data $ndata \
		    -text $level -image [fetchImage $icon] \
		    -style leafImageStyle
		$tree setmode $path none
	    } {
		$hlist add $path -itemtype text \
		    -text $level -style rootTextStyle
		$tree setmode $path close
	    }
	}
	    
	append path ${Application:treeSeparator}
	incr n
    }
}

proc Inspector:removeDashboard {context object objdesc objprefix} {

    global Inspector:eventHooks Inspector:activeDashboards
    global Application:treeSeparator

    catch {
	# this code may fail due to an attempt
	# to wipe out objects while destroying the
	# inspector window.
	set tree [$context.nb subwidget displaytab].t
	set hlist [$tree subwidget hlist]
	set objpath [lindex $objdesc 0]
	$hlist delete entry [join $objpath ${Application:treeSeparator}]
    }

    set n [lsearch -exact $object ${Inspector:activeDashboards}]

    if {$n != -1} {
	set Inspector:activeDashboards \
	    [lreplace ${Inspector:activeDashboards} $n $n]
	set hook "$objprefix:event $object"
	set n [lsearch -exact $hook ${Inspector:eventHooks}]
	set Inspector:eventHooks \
	    [lreplace ${Inspector:eventHooks} $n $n]
    }
}

proc Inspector:displayDashboard {context tree entry} {

    global Inspector:eventHooks Inspector:activeDashboards
    global Monitor:standaloneRun

    if {${Monitor:standaloneRun} == 0} {
	global Debugger:zombieCause
	if {${Debugger:zombieCause} == "DebuggerExceptionEvent"} {
	    tk_messageBox \
		-message "Simulator is down. Cannot get this information. Sorry." \
		-type ok -icon error -title Error
	    return
	}
    }

    set hlist [$tree subwidget hlist]
    set ndata [$hlist info data $entry]

    if {$ndata == {}} {
	# not a viewable entry
	return
    }

    # ndata contains calling information of the form:
    # { context tclPrefix name }
    set object [lindex $ndata 0]
    set objprefix [lindex $ndata 1]
    set objname [lindex $ndata 2]
    set n [lsearch -exact $object ${Inspector:activeDashboards}]

    if {$n == -1} {
	# append object to the active list -- once.
	lappend Inspector:activeDashboards $object
	set hook "$objprefix:event $object"
	lappend Inspector:eventHooks $hook
    }

    $objprefix:show $object $objname
}

proc Inspector:getDashboardStatus {context objectPath} {

    global Application:treeSeparator Monitor:standaloneRun

    if {$objectPath == ""} {
	# no path means the inspector window itself
	if {${Monitor:standaloneRun} == 0} {
	    set object $context
	} {
	    # always displayed in standalone mode
	    return displayed
	}
    } {
	set tree [$context.nb subwidget displaytab].t
	set entry [join $objectPath ${Application:treeSeparator}]
	set hlist [$tree subwidget hlist]
	set ndata [$hlist info data $entry]
	set object [lindex $ndata 0]
    }
    
    if {[winfo exists $object] == 1 &&
	[wm state $object] == "normal"} {
	# we expect objects to use the name we gave them
	# as their own toplevel identifier.
	return displayed
    }

    return withdrawn
}

proc Inspector:popup {context {autoDisplay {}}} {

    if {$autoDisplay == {}} {
	# We get called this way only if running with debug support --
	# i.e. in a standalone toplevel.
	wm deiconify $context
	raise $context
    } {
	if {[winfo exists $context.nb] == 1} {
	    global Application:treeSeparator
	    set tree [$context.nb subwidget displaytab].t
	    set entry [join $autoDisplay ${Application:treeSeparator}]
	    Inspector:displayDashboard $context $tree $entry
	}
    }
}

proc Inspector:saveSettings {context} {

    global Monitor:standaloneRun

    if {${Monitor:standaloneRun} == 0 &&
	[wm state $context] == "normal"} {
	# i.e. built as a toplevel and visible
	set geometry [wm geometry $context]
    } {
	set geometry {}
    }
    Project:setResource MonitorInspector [list $geometry]
}

proc Inspector:restoreSettings {context} {

    set setup [Project:getResource MonitorInspector]
    set geometry [lindex $setup 0]

    if {$geometry != {}} {
	wm geometry $context $geometry
    }
}

proc Inspector:processGlobalEvent {context name1 name2 op} {

    global Inspector:eventHooks

    while {[popEvent eventQueue:$context e] == "true"} {
	switch $e {
	    SimulationColdEvent {
		# base initializations are done -- create the inspector window...
		Inspector:configure $context
	    }

	    SimulationHeldEvent -
	    DebuggeeHeldEvent {
		# raise the inspector windows
		global Project:settings

		if {[set Project:settings(Options,autoRaise)] == 1} {
		    if {$e == "DebuggeeHeldEvent" &&
			[winfo exists $context] &&
			[wm state $context] == "normal"} {
			raise $context
		    }
		    global Inspector:activeDashboards
		    foreach object ${Inspector:activeDashboards} {
			# "object" usually names a toplevel -- but if it
			# doesn't, never mind...
			catch { raise $object }
		    }
		}
	    }

	    InspectorConfigureEvent {
		Inspector:restoreSettings $context
	    }

	    MonitorDisconnectEvent {
		global Monitor:initState

		if {${Monitor:initState} == "ok"} {
		    # the inspector totally depends on the channel
		    # availability... thus a channel breakdown due
		    # to a program exit beget a total shutdown of
		    # the inspector. 
		    Inspector:saveSettings $context
		}
		if {[winfo exists $context]} {
		    TkRequest $context ResetAll
		}
	    }
	}

 	foreach eventHook ${Inspector:eventHooks} {
	    catch { eval $eventHook $e }
	}
      }
}
