# Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

proc psostask:attach {context name private} {

    global $context.info
    set $context.info(present) yes
    return [list [list {pSOS+ emulation} Tasks $name] thread]
}

proc psostask:detach {context} {

    global $context.info
    unset $context.info
    catch { destroy $context }
}

proc psostask:show {context name} {

    if {[winfo exists $context]} {
	wm deiconify $context
	raise $context
    }

    psostask:pollInfo $context
}

proc psostask:event {context event} {

    switch $event {
	SimulationHeldEvent {
	    if {[catch { wm state $context } state] == 0} {
		if {$state != "withdrawn"} {
		    psostask:pollInfo $context
		}
	    }
	}
    }
}

proc psostask:update {context name info} {

    global $context.info

    # the following information are transient,
    # thus do not recycle previous one.
    set $context.info(timeout) n/a

    # dispatch the information block contents
    # to the per-context data array...
    foreach e $info {
	set item [lindex $e 0]
	set value [lindex $e 1]
	set $context.info($item) $value
    }

    set $context.info(current) $info

    if {[winfo exists $context]} {
	# update signal and notepad information by hand -
	# other display updates will be triggered automatically
	# by changing cells from the data array.

	set sigfrm [$context.sw2 subwidget frame]

	for {set i 0} {$i < 32} {incr i} {
	    set state [lindex [set $context.info(signals)] $i]
	    if {$state == 1} {
		$sigfrm.$i select
	    } {
		$sigfrm.$i deselect
	    }
	}
	return
    }

    # if the task object has never been displayed before,
    # build a brand new toplevel for it...

    toplevel $context
    wm title $context "pSOS+ task: $name"
    wm resizable $context 0 0
    cascadeWindow $context
    wm protocol $context WM_DELETE_WINDOW \
	"wm withdraw $context"

    set sw1 $context.sw1
    set sw2 $context.sw2

    tixLabelFrame $sw1 -label Status \
	-labelside acrosstop -options {
	    label.padx 5
	}

    tixLabelFrame $sw2 -label Signals \
	-labelside acrosstop -options {
	    label.padx 5
	}

    pack $sw1 $sw2 -side top -fill both -expand yes

    # Status frame

    set statfrm [$sw1 subwidget frame]

    # State
    tixLabelEntry $statfrm.state -label State: -state disabled
    $statfrm.state subwidget entry configure \
	-textvariable $context.info(state)
    pack $statfrm.state -anchor e -pady 5 -padx 5

    # Timeout
    tixLabelEntry $statfrm.timeout -label Timeout: -state disabled
    $statfrm.timeout subwidget entry configure \
	-textvariable $context.info(timeout)
    pack $statfrm.timeout -anchor e -pady 5 -padx 5

    # Interrupt masking level
    tixControl $statfrm.ilevel \
	-label I-Mask: \
	-variable $context.info(ilevel) \
	-integer true \
	-min 0 \
	-max 7 \
	-allowempty false

    pack $statfrm.ilevel -anchor e -pady 5 -padx 5

    # Priority
    tixControl $statfrm.prio \
	-label Priority: \
	-variable $context.info(prio) \
	-integer true \
	-min 1 \
	-max 255 \
	-allowempty false

    pack $statfrm.prio -anchor e -pady 5 -padx 5

    # Signal frame

    set sigfrm [$sw2 subwidget frame]

    for {set i 0} {$i < 32} {incr i} {
	set state [lindex [set $context.info(signals)] $i]
	checkbutton $sigfrm.$i -text [format "#%.2d" $i] \
	    -relief flat -anchor w \
	    -variable $context.info(sigstate,$i)
	if {$state == 1} {
	    $sigfrm.$i select
	} {
	    $sigfrm.$i deselect
	}
	set col [expr $i % 4]
	set row [expr $i / 4]
	grid $sigfrm.$i -column $col -row $row
    }

    tixButtonBox $context.bbox -orientation horizontal -relief flat -bd 0
    $context.bbox add update -text Update \
	-command "psostask:pollInfo $context"
    $context.bbox add apply -text Apply \
	-command "psostask:applyChanges $context"
    $context.bbox add cancel -text Dismiss \
	-command "wm withdraw $context"
    pack $context.bbox -side bottom -fill x
}

proc psostask:pollInfo {context} {
    TkRequest $context GetDashboardInfo all
}

proc psostask:applyChanges {context} {

    global $context.info

    set oldinfo [set $context.info(current)]

    set newprio [list prio [set $context.info(prio)]]
    set newilvl [list ilevel [set $context.info(ilevel)]]
    set sigstates {}
    for {set i 0} {$i < 32} {incr i} {
	lappend sigstates [set $context.info(sigstate,$i)]
    }
    set newsigs [list signals $sigstates]

    # Spurious "round-robin" side-effect on task scheduling is
    # prevented by never reinstateing an unmodified priority level.

    foreach config {newsigs newilvl newprio} {
	if {[lsearch -exact $oldinfo [set $config]] == -1} {
	    TkRequest $context ConfigureDashboard [set $config]
	}
    }
}

proc psostask:fillWaitList {context listbox} {

    global $context.info

    set lbox [$listbox subwidget listbox]
    $lbox delete 0 end

    foreach taskinfo [set $context.info(sleepers)] {
	set name [lindex $taskinfo 1]
	$lbox insert end $name
    }
}

proc psostask:pickWaitList {context listbox} {

    global $context.info

    set lbox [$listbox subwidget listbox]
    set sel [$lbox curselection]

    if {$sel != {}} {
	set taskinfo [lindex [set $context.info(sleepers)] $sel]
	set name [lindex $taskinfo 1]
	TkRequest $context InspectDashboard [list {pSOS+ emulation} Tasks $name]
    }
}
