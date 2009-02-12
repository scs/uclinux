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

# The list of current watchpoints:
# a watchpoint info block is: {  state wpnum condition }
set Debugger:wplist {}
set Debugger:wpToolTips {}
set Debugger:watchfault {}

proc Debugger:editWatchpoints {debugfrm} {

    global Debugger:wplist Debugger:f2c
    global Debugger:wpToolTips Debugger:wpLocation

    set context [set Debugger:f2c($debugfrm)]

    set w $context.editwp
    toplevel $w
    wm title $w "Debug Watchpoints"
    bind $w <Escape> "destroy $w"
    cascadeWindow $w

    set toolbar [frame $w.toolbar -bd 1 -relief groove]
    pack $toolbar -side top -fill x

    set toggles $toolbar.toggles
    tixSelect $toggles -allowzero true -radio true
    pack $toggles -expand no -anchor w -padx 4 -pady 4 -side left

    set inputfield $toolbar.inputfield
    set Debugger:wpLocation {}
    tixComboBox $inputfield -dropdown true -label "Watch: " \
	-editable true \
	-grab local \
	-history true \
	-prunehistory true \
	-variable Debugger:wpLocation \
	-options {
	    listbox.height 6
	    listbox.width 6
	    label.anchor e
	}

    set e [$inputfield subwidget entry]
    $e configure -width 28
    focus $e
    pack $inputfield -pady 4 -padx 4 -side right

    set lbf [frame $w.lbf]
    pack $lbf -expand yes -fill both

    $toggles add addwp -image [fetchImage watchadd]
    Workspace:addToolTip $toggles addwp Debugger:wpToolTips \
	"Add watchpoint" "Create a new watchpoint in program"
    $toggles add remwp -image [fetchImage watchrem]
    Workspace:addToolTip $toggles remwp Debugger:wpToolTips \
	"Remove watchpoint(s)" "Remove selected/all watchpoint(s) from program"
    $toggles add togglewp -image [fetchImage watchtoggle]
    Workspace:addToolTip $toggles togglewp Debugger:wpToolTips \
	"Toggle watchpoint(s)" "Enable/Disable selected/all watchpoint(s)"

    tixScrolledHList $lbf.list -options {
	hlist.columns 2
	hlist.header true
	hlist.selectmode single
	hlist.drawbranch 0
	hlist.indent 5
	hlist.height 10
	hlist.width 60
    }

    pack $lbf.list -expand yes -fill both
    set hlist [$lbf.list subwidget hlist]
    $hlist column width 0 -char 10
    $hlist column width 1 -char 50
    $hlist header create 0 -itemtype text -text State/ID \
	-style rootTextStyle
    $hlist header create 1 -itemtype text -text Expression \
	-style rootTextStyle

    $toggles config -command "Debugger:wpToolbarExec $debugfrm $hlist $toggles $inputfield"

    backmenu $lbf.popup -tearoff 0
    set menu [$lbf.popup subwidget menu]
    $menu add command -label "Enable/Disable" -command \
	 "Debugger:toggleWP $debugfrm $hlist $toggles"
    $menu add command -label "Edit" -command \
	 "Debugger:editWP $debugfrm $hlist $toggles"
    $menu add command -label "Remove" -command \
	 "Debugger:removeWP $debugfrm $hlist $toggles"
    $lbf.popup validate \
	"Debugger:wpBackMenu $debugfrm $hlist $menu $toggles"
    $lbf.popup bind $hlist

    Debugger:buildWPDisplay $debugfrm $hlist $toggles
    bind $e <Return> "Debugger:addWatchpoint $debugfrm $hlist $toggles $inputfield"

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "destroy $w"
    pack $w.bbox -fill x

    set statusbar [frame $w.status -height 20 -relief sunken -bd 1]
    pack $w.status -fill x
    set Debugger:wpToolTips {}
    label $statusbar.message -textvariable Debugger:wpToolTips
    pack $statusbar.message -side left

    tkwait visibility $w
    grab $w
}

proc Debugger:toggleWP {debugfrm hlist toggles} {

    global Debugger:wplist

    set sel [$hlist info selection]

    if {$sel != {}} {
	# toggle the selected watchpoint
	set wpinfo [lindex ${Debugger:wplist} $sel]
	Debugger:toggleWatchpoint $debugfrm $wpinfo
    } {
	# toggle all watchpoints
	for {set wpnum [expr [llength [$hlist info children]] - 1]} {$wpnum >= 0} {incr wpnum -1} {
	    set wpinfo [lindex ${Debugger:wplist} $wpnum]
	    Debugger:toggleWatchpoint $debugfrm $wpinfo
	}
    }

    Debugger:buildWPDisplay $debugfrm $hlist $toggles
}

proc Debugger:editWP {debugfrm hlist toggles} {

    global Debugger:wplist

    set sel [$hlist info selection]

    if {$sel == {}} {
	return
    }

    set wpinfo [lindex ${Debugger:wplist} $sel]
    set condition [lindex $wpinfo 2]

    set w [winfo toplevel $hlist].editwp
    toplevel $w
    wm title $w "Edit Watchpoint"
    cascadeWindow $w [winfo toplevel $hlist]
    set lbf [frame $w.lbf -relief raised -bd 1]
    tixLabelEntry $lbf.entry -label "Stop when: " \
	-options {
	    entry.width 30
	}
    set e [$lbf.entry subwidget entry]
    $e configure -textvariable $e:value
    global $e:value
    set $e:value $condition
    bind $e <Return> "Debugger:editWPOk $debugfrm $hlist $sel"
    bind $e <Escape> "destroy $w"
    pack $lbf.entry -pady 5 -padx 15 -anchor w
    $e selection range 0 end
    $e icursor end
    pack $w.lbf -expand yes -fill both

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add ok -text OK -command \
	"Debugger:editWPOk $debugfrm $hlist $sel"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus $e
    tkwait visibility $w
    grab $w
}

proc Debugger:editWPOk {debugfrm hlist sel} {

    global Debugger:wplist Debugger:f2c
    global gdb:lastexpr

    set wpinfo [lindex ${Debugger:wplist} $sel]
    set state [lindex $wpinfo 0]
    set owpnum [lindex $wpinfo 1]
    set w [winfo toplevel $hlist].editwp
    set lbf $w.lbf
    set e [$lbf.entry subwidget entry]

    global $e:value
    set condition [set $e:value]
    set context [set Debugger:f2c($debugfrm)]

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set cmd "setwatchpoint $context [list $condition]"
    set wpnum [DataDisplay:evalWorker $context $cmd true]

    if {$wpnum != {}} {
	gdb:removewp $owpnum
	Debugger:suspend $context
	set wpid [lsearch -exact ${Debugger:wplist} $wpinfo]
	set condition [set gdb:lastexpr]
	set wpinfo [list $wpnum $state $condition]
	set Debugger:wplist [lreplace ${Debugger:wplist} $wpid $wpid $wpinfo]
	$hlist item config $sel 1 -text $condition
    } {
	Debugger:suspend $context
	global gdb:lasterror
	tk_messageBox \
	    -message [set gdb:lasterror] \
	    -type ok -icon error -title Error
	# do not raise $w -- this causes some unexpected delay under KDE...
	return
    }

    raise [winfo toplevel $hlist]
    destroy $w
}

proc Debugger:removeWP {debugfrm hlist toggles} {

    global Debugger:wplist

    set sel [$hlist info selection]

    if {$sel != {}} {
	# remove the selected watchpoint
	set wpinfo [lindex ${Debugger:wplist} $sel]
	Debugger:removeWatchpoint $debugfrm $wpinfo
    } {
	# remove all watchpoints
	set wpcount [llength [$hlist info children]]

	if {$wpcount == 0} {
	    return
	}
	if {[tk_messageBox \
		 -message "About to delete all watchpoints...\nAre you sure? Please confirm." \
		 -type yesno -icon warning -title Warning] != "yes"} {
	    return
	}
	while {$wpcount > 0} {
	    set wpinfo [lindex ${Debugger:wplist} 0]
	    Debugger:removeWatchpoint $debugfrm $wpinfo
	    incr wpcount -1
	}
    }

    Debugger:buildWPDisplay $debugfrm $hlist $toggles
}

proc Debugger:buildWPDisplay {debugfrm hlist toggles} {

    global Debugger:wplist

    $hlist delete all
    set nth 0

    foreach wpinfo ${Debugger:wplist} {
	foreach {state wpnum condition} $wpinfo {
	    if {$state == "enabled"} {
		set img stopenb
	    } {
		set img stopdis
	    }
	    $hlist add $nth -itemtype imagetext \
		-image [fetchImage $img] -text $wpnum \
		-style leafImageStyle
	    $hlist item create $nth 1 -itemtype text -text $condition \
		-style leafTextStyle
	    incr nth
	}
    }
}

proc Debugger:wpToolbarExec {debugfrm hlist toggles inputfield button state} {
    # a little trick to have the tix select widget
    # behave like a toolbar: a selected button is
    # immediately re-invoked to restore its initial
    # graphic state. This is why the button state is
    # checked to filter out "off" invocations.
    if {$state == 1} {
	global Debugger:wpToolTips
	set Debugger:wpToolTips {}
	$toggles invoke $button
	switch -- $button {
	    addwp {
		Debugger:addWatchpoint $debugfrm $hlist $toggles $inputfield
	    }
	    remwp {
		Debugger:removeWP $debugfrm $hlist $toggles
	    }
	    togglewp {
		Debugger:toggleWP $debugfrm $hlist $toggles
	    }
	}
    }
}

proc Debugger:wpBackMenu {debugfrm hlist menu toggles rootx rooty} {

    $hlist selection clear
    # turn root coordinates into local coordinates
    set y [expr $rooty - [winfo rooty $hlist]]
    set entry [$hlist nearest $y]

    if {$entry == {}} {
	return false
    }

    $hlist selection set $entry

    return true
}

proc Debugger:saveWatchpoints {context} {

    global Debugger:wplist
    Project:setResource DebuggerWatchpoints ${Debugger:wplist}
}

proc Debugger:restoreWatchpoints {context} {

    global Debugger:wplist

    set wplist [Project:getResource DebuggerWatchpoints]
    set Debugger:wplist {}

    if {$wplist == {}} {
	return
    }

    foreach wpinfo $wplist {
	foreach {state wpnum condition} $wpinfo {
	    set cmd "setwatchpoint $context [list $condition]"
	    set wpnum [DataDisplay:evalWorker $context $cmd true]
	    if {$wpnum == {}} {
		global gdb:lasterror
		$context.messages.warning configure \
		    -text [set gdb:lasterror]
		bell -displayof $context
	    } {
		lappend Debugger:wplist [list $state $wpnum $condition]
		if {$state == "disabled"} {
		    gdb:disablewp $wpnum
		}
	    }
	}
    }
}

proc Debugger:addWatchpoint {debugfrm hlist toggles inputfield} {

    global Debugger:wplist
    global Debugger:f2w Debugger:f2c
    global Debugger:wpToolTips
    global gdb:lastexpr
    global Debugger:watchfault

    set condition [$inputfield subwidget entry get]

    if {$condition == {}} {
	return
    }
    
    $inputfield subwidget entry delete 0 end
    set Debugger:watchfault {}
    set context [set Debugger:f2c($debugfrm)]
    set cmd "setwatchpoint $context [list $condition]"
    set wpnum [DataDisplay:evalWorker $debugfrm $cmd false]

    if {$wpnum == {} || ${Debugger:watchfault} == $wpnum} {
	global gdb:lasterror
	set Debugger:wpToolTips [set gdb:lasterror]
	bell -displayof $debugfrm
	return
    }

    set condition [set gdb:lastexpr]
    lappend Debugger:wplist [list enabled $wpnum $condition]
    Debugger:buildWPDisplay $debugfrm $hlist $toggles
}

proc Debugger:toggleWatchpoint {debugfrm wpinfo {status {}}} {

    global Debugger:wplist Debugger:f2c

    set context [set Debugger:f2c($debugfrm)]

    if {$status == {}} {
	# default action -- complement the current wp state
	if {[lindex $wpinfo 0] == "enabled"} {
	    set status disabled
	} {
	    set status enabled
	}
    }

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set wpnum [lindex $wpinfo 1]

    if {$status == "enabled"} {
	gdb:enablewp $wpnum
    } {
	if {[gdb:disablewp $wpnum] == "false"} {
	    # Failed to disable -- don't change status
	    set status enabled
	}
    }

    Debugger:suspend $context

    # find WP to update in the wplist
    set id [lsearch -exact ${Debugger:wplist} $wpinfo]
    # update enabled/disabled status
    set wpinfo [lreplace $wpinfo 0 0 $status]
    set Debugger:wplist [lreplace ${Debugger:wplist} $id $id $wpinfo]
}

proc Debugger:removeWatchpoint {debugfrm wpinfo} {

    global Debugger:wplist Debugger:f2c

    set context [set Debugger:f2c($debugfrm)]

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set wpnum [lindex $wpinfo 1]
    gdb:removewp $wpnum
    Debugger:suspend $context

    # remove WP from the wplist
    set rmid [lsearch -exact ${Debugger:wplist} $wpinfo]
    set Debugger:wplist [lreplace ${Debugger:wplist} $rmid $rmid]
}

proc Debugger:notifyWatchError {context wpnum} {

    global Debugger:wplist Debugger:watcherr

    set wpid [lsearch -glob ${Debugger:wplist} "enabled $wpnum *"]
    if {$wpid != -1} {
	set wpinfo [lindex ${Debugger:wplist} $wpid]
	set wpinfo [lreplace $wpinfo 0 0 disabled] 
	set Debugger:wplist [lreplace ${Debugger:wplist} $wpid $wpid $wpinfo]
	$context.messages.warning configure \
	    -text "Watchpoint $wpnum disabled on error"
	bell -displayof $context
    } {
	# watchpoint is in the process of being defined --
	# raise the error flag to warn addWatchpoint.
	global Debugger:watchfault
	set Debugger:watchfault $wpnum
    }
}
