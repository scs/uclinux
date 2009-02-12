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

# list of defined timers
set TimerManager:timers {}
# message buffer where the timer tooltips are stored
set TimerManager:toolTips {}
# kind of timer value (relative or absolute)
set TimerManager:timerType -absolute

proc TimerManager:popup {context}  {

    set w $context.timers

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	return
    }

    toplevel $w
    wm title $w Timers
    wm protocol $w WM_DELETE_WINDOW "grab release $w; wm withdraw $w"
    bind $w <Escape> "grab release $w; wm withdraw $w"
    cascadeWindow $w $context
    TkRequest $context CacheWindowIn $w Timers

    set toolbar [frame $w.toolbar -bd 1 -relief groove]
    pack $toolbar -side top -fill x

    set toggles $toolbar.toggles
    tixSelect $toggles -allowzero true -radio true
    pack $toggles -expand no -anchor w -padx 4 -pady 4 -side left

    set lbf [frame $w.lbf -relief raised -bd 1]
    pack $lbf -expand yes -fill both

    $toggles add addtm -image [fetchImage tmadd]
    Workspace:addToolTip $toggles addtm TimerManager:toolTips \
	"Add timer" "Create new timer"
    $toggles add remtm -image [fetchImage tmrem]
    Workspace:addToolTip $toggles remtm TimerManager:toolTips \
	"Remove timer(s)" "Delete selected/all timer(s)"
    $toggles add toggletm -image [fetchImage tmtoggle]
    Workspace:addToolTip $toggles toggletm TimerManager:toolTips \
	"Toggle timer(s)" "Enable/Disable selected/all timer(s)"

    tixScrolledListBox $lbf.list -scrollbar auto
    set lbox [$lbf.list subwidget listbox]
    $lbox config -height 10 -width 30 -selectmode single
    pack $lbf.list -expand yes -fill both
    $toggles config -command "TimerManager:toolbarExec $context $lbox $toggles"
    
    backmenu $lbf.popup -tearoff 0
    set menu [$lbf.popup subwidget menu]
    $menu add command -label "Enable/Disable" -command \
	 "TimerManager:toggleTimer $context $lbox $toggles"
    $menu add command -label "Remove" -command \
	 "TimerManager:removeTimer $context $lbox $toggles"
    $lbf.popup validate \
	"TimerManager:backMenu $context $lbox $menu $toggles"
    $lbf.popup bind $lbox

    TimerManager:buildDisplay $context $lbox $toggles

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "grab release $w; wm withdraw $w"
    pack $w.bbox -fill x

    set statusbar [frame $w.status -height 20 -relief sunken -bd 1]
    pack $w.status -fill x
    set TimerManager:toolTips {}
    label $statusbar.message -textvariable TimerManager:toolTips
    pack $statusbar.message -side left

    tkwait visibility $w
    grab $w
}

proc TimerManager:destroy {context}  {
    
    catch { destroy $context.timers }
}

proc TimerManager:addTimer {context lbox toggles} {

    global TimerManager:timers

    set w $context.timers.new
    toplevel $w
    wm title $w "New Timer"
    cascadeWindow $w
    bind $w <Escape> "destroy $w"

    set f1 [frame $w.lbf1 -relief sunken -bd 1]
    pack $f1 -fill both -expand yes

    tixControl $f1.time \
	-label "Stop at: " \
	-value 0 \
	-min 0 \
	-allowempty false -options {
	    entry.width 8
	}

    tixOptionMenu $f1.unit -labelside none -options {
	    menubutton.bd 0
	    menubutton.relief flat
    }
    $f1.unit add command usc -label usc
    $f1.unit add command msc -label msc
    $f1.unit add command sec -label sec
    pack $f1.time -side left -padx 5 -pady 5
    pack $f1.unit -side left -padx 0 -pady 5

    set f2 [frame $w.lbf2 -relief sunken -bd 1]
    pack $f2 -fill both -expand yes

    radiobutton $f2.abs -text absolute \
	-variable TimerManager:timerType \
	-relief flat -bd 2 -pady 0 -anchor w \
	-value -absolute

    radiobutton $f2.rel -text relative \
	-variable TimerManager:timerType \
	-relief flat -bd 2 -pady 0 -anchor w \
	-value -relative

    pack $f2.abs -side left -padx 5
    pack $f2.rel -side right -padx 5

    ## Button box

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add save -text Add -command "TimerManager:createTimer $context $lbox $toggles $f1"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    tkwait visibility $w
    grab $w
}

proc TimerManager:createTimer {context lbox toggles f} {

    global TimerManager:timers TimerManager:timerType

    set w $context.timers.new
    $f.time update

    set val [$f.time cget -value] 
    set type ${TimerManager:timerType}

    if {$val != 0} {

	# cannot set a timer to be fired at ZEROTIME -- this does not
	# make sense because the simulator *always* stops at this time
	# value. Because of this specificity, this value is used as a
	# special exception case by the MVM internals to identify an
	# idle timer.

	set unit [$f.unit cget -value]
	set itime [TkRequest $context AddTimer [concat $val $unit] $type]

	# replace any existing timer with the same internal
	# time with the new one...

	set n 0
	foreach tminfo ${TimerManager:timers} {
	    set _itime [lindex $tminfo 3]
	    if {$itime == $_itime} {
		set TimerManager:timers [lreplace ${TimerManager:timers} $n $n]
		break
	    }
	    incr n
	}

	if {$type == "-relative"} {
	    # use the translated time returned by the
	    # AddTimer service
	    set val $itime
	    set unit usc
	}
	set tminfo [list $val $unit enabled $itime]
	lappend TimerManager:timers $tminfo

	# sort timers on increasing scheduling time order
	set TimerManager:timers [lsort -real -index end ${TimerManager:timers}]
	TimerManager:buildDisplay $context $lbox $toggles
    }
    destroy $w
}

proc TimerManager:toggleTimer {context lbox toggles} {

    global TimerManager:timers

    set sel [$lbox curselection]

    if {$sel != {}} {
	set tminfo [lindex ${TimerManager:timers} $sel]
	set val [lindex $tminfo 0]
	set unit [lindex $tminfo 1]
	set state [lindex $tminfo 2]
	set itime [lindex $tminfo 3]
	if {$state == "enabled"} {
	    set nstate disabled
	} {
	    set nstate enabled
	}
	set tminfo [list $val $unit $nstate $itime]
	set TimerManager:timers [lreplace ${TimerManager:timers} $sel $sel $tminfo]
	TkRequest $context SwitchTimer [concat $val $unit]
    } {
	for {set tmnum [expr [$lbox size] - 1]} {$tmnum >= 0} {incr tmnum -1} {
	    set tminfo [lindex ${TimerManager:timers} $tmnum]
	    set val [lindex $tminfo 0]
	    set unit [lindex $tminfo 1]
	    set state [lindex $tminfo 2]
	    set itime [lindex $tminfo 3]
	    if {$state == "enabled"} {
		set nstate disabled
	    } {
		set nstate enabled
	    }
	    set tminfo [list $val $unit $nstate $itime]
	    set TimerManager:timers [lreplace ${TimerManager:timers} $tmnum $tmnum $tminfo]
	    TkRequest $context SwitchTimer [concat $val $unit]
	}
    }

    TimerManager:buildDisplay $context $lbox $toggles
}

proc TimerManager:removeTimer {context lbox toggles} {

    global TimerManager:timers

    set sel [$lbox curselection]

    if {$sel != {}} {
	set tminfo [lindex ${TimerManager:timers} $sel]
	set val [lindex $tminfo 0]
	set unit [lindex $tminfo 1]
	set TimerManager:timers [lreplace ${TimerManager:timers} $sel $sel]
	TkRequest $context KillTimer [concat $val $unit]
    } {
	set tmcount [$lbox size]

	if {$tmcount == 0} {
	    return
	}
	if {[tk_messageBox \
		 -message "About to delete all timers...\nAre you sure? Please confirm." \
		 -type yesno -icon warning -title Warning] != "yes"} {
	    return
	}
	while {$tmcount > 0} {
	    set tminfo [lindex ${TimerManager:timers} 0]
	    set val [lindex $tminfo 0]
	    set unit [lindex $tminfo 1]
	    set TimerManager:timers [lreplace ${TimerManager:timers} 0 0]
	    TkRequest $context KillTimer [concat $val $unit]
	    incr tmcount -1
	}
    }

    TimerManager:buildDisplay $context $lbox $toggles
}

proc TimerManager:buildDisplay {context lbox toggles} {

    global TimerManager:timers

    $lbox delete 0 end

    foreach tminfo ${TimerManager:timers} {
	set val [lindex $tminfo 0]
	set unit [lindex $tminfo 1]
	set state [lindex $tminfo 2]
	set s [format "%s %s" $val $unit]
	if {$state == "disabled"} {
	    append s " (disabled)"
	}
	$lbox insert end $s
    }
}

proc TimerManager:toolbarExec {context lbox toggles button state} {
    # a little trick to have the tix select widget
    # behave like a toolbar: a selected button is
    # immediately re-invoked to restore its initial
    # graphic state. This is why the button state is
    # checked to filter out "off" invocations.
    if {$state == 1} {
	global TimerManager:toolTips
	set TimerManager:toolTips {}
	$toggles invoke $button
	switch -- $button {
	    addtm {
		TimerManager:addTimer $context $lbox $toggles
	    }
	    remtm {
		TimerManager:removeTimer $context $lbox $toggles
	    }
	    toggletm {
		TimerManager:toggleTimer $context $lbox $toggles
	    }
	}
    }
}

proc TimerManager:backMenu {context lbox menu toggles rootx rooty} {

    $lbox selection clear 0 end
    # turn root coordinates into local coordinates
    set y [expr $rooty - [winfo rooty $lbox]]
    set entry [$lbox nearest $y]

    if {$entry == -1} {
	return false
    }

    $lbox selection set $entry

    return true
}

proc TimerManager:saveTimers {context} {
    global TimerManager:timers
    Project:setResource MonitorTimers ${TimerManager:timers}
}

proc TimerManager:restoreTimers {context} {

    global TimerManager:timers

    set TimerManager:timers [Project:getResource MonitorTimers]

    foreach tminfo ${TimerManager:timers} {
	set state [lindex $tminfo 2]
	if {$state == "enabled"} {
	    set val [lindex $tminfo 0]
	    set unit [lindex $tminfo 1]
	    TkRequest $context AddTimer [concat $val $unit]
	}
    }
}
