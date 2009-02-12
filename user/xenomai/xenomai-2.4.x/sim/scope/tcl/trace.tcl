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

set MvmTracer:simulationState none
set MvmTracer:lineCount 0

proc MvmTracer:attach {context name private} {

    global $context.info MvmTracer:lineCount

    # register trace hook to get informed of major
    # context changes

    set $context.info(present) yes
    set $context.info(changed) true
    set $context.info(automark) 0
    set $context.info(usermark) 0
    set $context.info(options) {}
    set $context.info(threads,0) {}
    set $context.info(notebook) {}
    set $context.info(tracebuffer) {}
    set MvmTracer:lineCount 0

    return [list [list System $name] {}]
}

proc MvmTracer:detach {context} {

    global $context.info
    unset $context.info

    # tracer window may have not existed at all if
    # the tracer object has never been selected for
    # display. Then be conservative: catch exceptions
    # when cleaning up...

    catch {
	forgetEvent Application:event \
	    eventQueue:$context \
	    "MvmTracer:processEvent $context"
	destroy $context
    }
}

proc MvmTracer:show {context name} {

    if {[winfo exists $context]} {
	wm deiconify $context
	raise $context
	return
    }

    # trigger an information update about
    # which calls can be traced.
    TkRequest $context GetDashboardInfo all
}

proc MvmTracer:update {context name info} {

    global $context.info

# "update" is normally called only once during the simulation
# lifetime: when the trace object is first requested for display.

    if {[winfo exists $context]} {
	return
    }
    
    set $context.info(definition) $info

    toplevel $context
    wm title $context Traces
    cascadeWindow $context
    wm protocol $context WM_DELETE_WINDOW \
	"MvmTracer:withdraw $context"
    bind $context <Escape> "MvmTracer:withdraw $context"

    # make this window appear in the workspace's "Windows" menu for fast access
    TkRequest $context CacheWindowIn $context "Call traces"

    ## Menubar

    set mbar [frame $context.mbar -relief groove]
    pack $mbar -side top -fill x

    ### File

    menubutton $mbar.file -text File \
	-menu $mbar.file.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.file.m -tearoff false

    $mbar.file.m add command -label "Save Log..." \
	-command "MvmTracer:saveLog $context" \
	-underline 0

    $mbar.file.m add command -label "Clear Log" \
	-command "MvmTracer:clearLog $context" \
	-underline 0

    $mbar.file.m add sep

    $mbar.file.m add command -label Close \
	-command "MvmTracer:withdraw $context" \
	-underline 0

    menubutton $mbar.select -text Selection \
	-menu $mbar.select.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.select.m -tearoff false

    $mbar.select.m add command -label "Select All" \
	-command "MvmTracer:selectAll $context" \
	-underline 7

    $mbar.select.m add command -label "Select None" \
	-command "MvmTracer:selectNone $context" \
	-underline 7

    menubutton $mbar.options -text Options \
	-menu $mbar.options.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.options.m -tearoff false

    $mbar.options.m add checkbutton -label " Trace callouts" \
	-indicatoron true \
	-variable $context.info(callouts) \
	-command "MvmTracer:optionChanged $context"

    $mbar.options.m add checkbutton -label " Break on error" \
	-indicatoron true \
	-variable $context.info(errorbrk) \
	-command "MvmTracer:optionChanged $context"

    $mbar.options.m add checkbutton -label " No filtering" \
	-indicatoron true \
	-variable $context.info(nofiltering) \
	-command "MvmTracer:optionChanged $context"

    $mbar.options.m add separator

    $mbar.options.m add checkbutton -label " Hide selectors" \
	-indicatoron true \
	-variable $context.info(hideselectors) \
	-command "MvmTracer:optionChanged $context hideselectors"

    ##

    pack $mbar.file $mbar.select $mbar.options -side left

    ## Paned Window

    tixPanedWindow $context.panew -orientation vertical -panerelief sunken
    pack $context.panew -side top -expand yes -fill both
    set p1 [$context.panew add p1 -min 200 -expand 0.40]
    set p2 [$context.panew add p2 -min 70 -max 70]
    set p3 [$context.panew add p3 -min 70 -expand 0.60]

    # o/s services notebook

    set $context.info(notebook) [tixNoteBook $p1.nb -ipadx 6 -ipady 6]
    pack $p1.nb -expand yes -fill both -padx 5 -pady 5 -side top
    set npage 0

    foreach callint $info {

	# add new tab for each call interface in notebook
	set tab [lindex $callint 0]
	set interface [lindex $callint 1]
	set $context.info(tracelist,$tab) {}

	$p1.nb add $npage -label $tab
	set w [$p1.nb subwidget $npage]
	incr npage

	tixCheckList $w.c -scrollbar auto -options {
	    hlist.indicator 1
	    hlist.indent 20
	}

	pack $w.c -expand yes -fill both -padx 4 -pady 4

	set $context.info(checklist,$tab) $w.c
	set hlist [$w.c subwidget hlist]
	set fnum 0

	foreach group $interface {
	    set family [lindex $group 0]
	    set services [lindex $group 1]
	    $hlist add $fnum -itemtype imagetext -text $family
	    $w.c setstatus $fnum on
	    set cnum 0
	    foreach call $services {
		$hlist add $fnum.$cnum -itemtype imagetext -text $call
		$w.c setstatus $fnum.$cnum off
		incr cnum
	    }
	    incr fnum
	}

	$w.c autosetmode
	$w.c config -browsecmd "MvmTracer:toggleTrace $context $w.c $tab"
	$w.c config -command "MvmTracer:toggleTrace $context $w.c $tab"

	set $context.info($w.c,disabled) [tixDisplayStyle imagetext -fg gray48 \
					      -refwindow [$w.c subwidget hlist]]
	set $context.info($w.c,normal) [tixDisplayStyle imagetext -fg black \
					    -refwindow [$w.c subwidget hlist]]
    }

    # button frames

    frame $p2.buttons -relief groove
    pack $p2.buttons -fill x -expand true
    set bf1 [frame $p2.buttons.f1]
    pack $bf1 -side left -padx 4
    set bf2 [frame $p2.buttons.f2]
    pack $bf2 -side right -padx 16
    set $context.info(buttons) $bf2

    ## focus combo

    set $context.info(focus) system
    set $context.info(focusname) {}

    tixComboBox $bf1.focus -label "Focus: " -dropdown true \
	-command "MvmTracer:setFocus $context" \
	-labelside top \
	-editable false \
	-variable $context.info(focusname) \
	-grab local \
	-history false \
	-options {
	    slistbox.scrollbar auto
	    listbox.height 12
	    listbox.width 25
	    label.width 7
	    label.anchor c
	}

    $bf1.focus subwidget entry configure -width 15
    $bf1.focus insert end system
    pack $bf1.focus -side right -padx 8
    set $context.info(focuscombo) $bf1.focus

     set img [fetchImage stepover]
     button $bf2.step -command "MvmTracer:step $context" -width 90
     set stepimg [makeCompoundImage Step $img]
     $bf2.step config -image $stepimg
     grid $bf2.step -column 0 -row 0

     set img [fetchImage cont]
     button $bf2.release -command "MvmTracer:release $context" -width 90
     set releaseimg [makeCompoundImage Cont $img]
     $bf2.release config -image $releaseimg
     grid $bf2.release -column 0 -row 1

     set img [fetchImage break]
     button $bf2.hold -command "MvmTracer:hold $context" -width 90
     set holdimg [makeCompoundImage Stop $img]
     $bf2.hold config -image $holdimg
     grid $bf2.hold -column 1 -row 0

     set img [fetchImage mark]
     button $bf2.mark -command "MvmTracer:mark $context yellow" -width 90
     set markimg [makeCompoundImage Mark $img]
     $bf2.mark config -image $markimg
     grid $bf2.mark -column 1 -row 1

    # trace buffer

    tixScrolledText $p3.traces -options {
	text.spacing1 0
	text.spacing3 0
	text.state disabled
	text.height 10
	text.wrap none
    }
    pack $p3.traces -expand yes -fill both
    set $context.info(tracebuffer) $p3.traces
    # force focus on the text widget upon Mouse-click 1. Having it disabled
    # seems to prevent the defaut binding to be applied. So help ourselves.
    set text [$p3.traces subwidget text]
    bind $text <1> "+ focus $text"

    set popup $p3.popup
    backmenu $popup -tearoff 0
    set menu [$popup subwidget menu]
    $menu add command -label "Search string" -command \
	"MvmTracer:searchText $context [$p3.traces subwidget text]"
    $popup bind [$p3.traces subwidget text]

    traceEvent Application:event \
	eventQueue:$context \
	"MvmTracer:processEvent $context"

    pushEvent Application:event TracerInitEvent
}

proc MvmTracer:toggleTrace {context chklist interface entry} {

    global $context.info

    set $context.info(changed) true

    if {[$chklist getstatus $entry] == "on"} {
	set state normal
    } else {
	set state disabled
    }

    if {[regexp -- "^\[^\.\]$" $entry] == 0} {
	# not a call family entry -- update the trace
	# list and return...

	set n [lsearch -exact [set $context.info(tracelist,$interface)] $entry]

	if {$state == "normal"} {
	    # trace enabled
	    if {$n == -1} {
		lappend $context.info(tracelist,$interface) $entry
	    }
	} {
	    # trace disabled
	    if {$n != -1} {
		set $context.info(tracelist,$interface) \
		    [lreplace [set $context.info(tracelist,$interface)] $n $n]
	    }
	}

	return
    }
    
    set hlist [$chklist subwidget hlist]

    foreach call [$hlist info children $entry] {
	$hlist entryconfig $call -state $state \
	    -style [set $context.info($chklist,$state)]
	set n [lsearch -exact [set $context.info(tracelist,$interface)] $call]
	if {$n != -1} {
	    if {$state == "disabled"} {
		# trace globally disabled
		set $context.info(tracelist,$interface) \
		    [lreplace [set $context.info(tracelist,$interface)] $n $n]
	    }
	} {
	    if {$state == "normal" && [$chklist getstatus $call] == "on"} {
		# trace globally re-enabled
		lappend $context.info(tracelist,$interface) $call
	    }
	}
    }
}

proc MvmTracer:updateThreads {context {reset true}} {

    global $context.info Project:settings

    set w [set $context.info(focuscombo)]

    # reset thread list
    set lbox [$w subwidget listbox]
    $lbox delete 0 end
    $lbox insert end system
    set threadlist [TkRequest $context GetThreads]
    set $context.info(threads) $threadlist

    foreach threaddef $threadlist {
	set name [lindex $threaddef 1]
	set body [lindex $threaddef 2]
	if {[set Project:settings(Options,threadQualify)] == 0 || $body == {}} {
	    set idstring $name
	} {
	    set idstring [format "%s(%s)" $body $name]
	}
	$w insert end $idstring
    }

    if {$reset == "true"} {
	# reset focus on system
	$w pick 0
    }
}

proc MvmTracer:setFocus {context focus} {

    global $context.info

    if {$focus == {}} {
	return
    }

    switch -- $focus {
	system {
	    set $context.info(focus) system
	}
	default {
	    set lbox [[set $context.info(focuscombo)] subwidget listbox]
	    set sel [$lbox curselection]
	    set threadlist [set $context.info(threads)]
	    set id [lindex [lindex $threadlist [expr $sel - 2]] 0]
	    set $context.info(focus) $id
	}
    }
}

proc MvmTracer:getConfiguration {context} {

    global $context.info

    set settings [array get $context.info tracelist,*]
    set n -1
    set conflist {}

    while {1} {
	set s [lindex $settings [incr n]]

	if {$s == {}} {
	    break
	}

	regexp -- "tracelist,(.*)" $s mvar iname

	set traces [lindex $settings [incr n]]
	set tracelist {}

	foreach call $traces {
	    set l [split $call .]
	    set grank [lindex $l 0]
	    set crank [lindex $l 1]

	    foreach interface [set $context.info(definition)] {
		if {[lindex $interface 0] == $iname} {
		    set callid $crank
		    foreach group [lindex $interface 1] {
			if {[incr grank -1] >= 0} {
			    incr callid [llength [lindex $group 1]]
			} {
			    lappend tracelist $callid
			    break
			}
		    }
		    break
		}
	    }
	}

	lappend conflist [list $iname $tracelist]
    }

    return $conflist
}

proc MvmTracer:setUpTraces {context} {

    global $context.info

    if {[set $context.info(changed)] == "false"} {
	# last setup remains valid -- no need to update
	# the traces at the simulator's level
	return
    }
    
    # "null" configurations must be sent too in order to
    # disable the previous settings at the simulator's level.
    set conflist [MvmTracer:getConfiguration $context]

    # build the trace option list
    set options {}
    foreach opt {callouts errorbrk nofiltering} {
	if {[set $context.info($opt)] == 1} {
	    lappend options $opt
	}
    }
    if {$options == {}} {
	set options {none}
    }

    TkRequest $context ConfigureDashboard "configure [list $options] $conflist"
    set $context.info(changed) false
}

proc MvmTracer:step {context} {

    global $context.info

    MvmTracer:setUpTraces $context
    set focus [set $context.info(focus)]
    TkRequest $context ConfigureDashboard [list step $focus]
    TkRequest $context ReleaseSimulation
}

proc MvmTracer:release {context} {

    global $context.info

    MvmTracer:setUpTraces $context
    set focus [set $context.info(focus)]
    TkRequest $context ConfigureDashboard [list release $focus]
    TkRequest $context ReleaseSimulation
}

proc MvmTracer:hold {context} {

    TkRequest $context HoldSimulation
}

proc MvmTracer:mark {context color {marker {}}} {

    global $context.info
    global Application:visualType

    set textw [[set $context.info(tracebuffer)] subwidget text]
    $textw configure -state normal
    set som [expr [$textw index end] - 1]
    if {$marker == {}} {
	set mark [incr $context.info(automark)]
	set marker [format "<<< %.3d >>>\n" $mark]
    } {
	set mark [incr $context.info(usermark)]
    }
    $textw insert end $marker

    if {${Application:visualType} == "color"} {
	set eom [lindex [split $som .] 0].end
	$textw tag add mrk${mark} $som $eom
	$textw tag configure mrk${mark} -background $color
    }
    $textw configure -state disabled
    $textw see end
}

proc MvmTracer:output {context name msg attribute} {

    global Monitor:traceLogSize $context.info

    set tracebuf [set $context.info(tracebuffer)]
    if {$tracebuf == {}} {
	# tracer is not displayed -- discard traces
	return
    }
    set textw [$tracebuf subwidget text]

    if {${Monitor:traceLogSize} != 0} {
	# enforce log size limitation

	global MvmTracer:lineCount

	if {${Monitor:traceLogSize} <= ${MvmTracer:lineCount}} {
	    $textw configure -state normal
	    $textw delete 1.0 1.0+1line
	} {
	    # assume that an output is always done for a single line --
	    # this may be false! FIXME
	    incr MvmTracer:lineCount
	}
    }

    if {$attribute != {}} {
	# client has provided for an output attribute -- consider this
	# message as a mark. A color can be appended to the attribute
	# type, separated from it by a dash.

	foreach {type color} [split $attribute -] {
	    switch -- $type {
		callout {
		    if {$color == {}} {
			set color green
		    }
		    MvmTracer:mark $context $color $msg
		    return
		}
		alert {
		    if {$color == {}} {
			set color red
		    }
		    MvmTracer:mark $context $color $msg
		    return
		}
		highlight {
		    if {$color == {}} {
			set color yellow
		    }
		    MvmTracer:mark $context $color $msg
		    return
		}
	    }
	}
    }

    $textw configure -state normal
    $textw insert end $msg
    $textw configure -state disabled
    $textw see end
}

proc MvmTracer:saveLog {context} {

    global $context.info

    set w $context.savelog

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	return
    }

    toplevel $w
    wm title $w "Save Trace Log"
    cascadeWindow $w $context
    
    set f [frame $w.f -relief sunken -bd 1]
    pack $f
    set $context.info(logfile) ""

    tixFileEntry $f.logfile -label "To file: " \
 	-variable $context.info(logfile) \
	-validatecmd "MvmTracer:valLogFileName" \
	-dialogtype tixFileSelectDialog \
 	-options {
 	    entry.width 25
 	    label.anchor e
	}
    pack $f.logfile -side top -anchor e -padx 10 -pady 10

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add update -text Save \
 	-command "MvmTracer:saveLogOk $context"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus [$f.logfile subwidget entry]
}

proc MvmTracer:saveLogOk {context} {

    global $context.info

    set w $context.savelog
    $w.f.logfile update
    set filename [set $context.info(logfile)]

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

    set textw [[set $context.info(tracebuffer)] subwidget text]
    puts -nonewline $fh [$textw get 1.0 end]
    close $fh
    destroy $w
}

proc MvmTracer:valLogFileName {path} {

    if {$path != ""} {
	if {[file isdirectory $path] == 1} {
	    return ""
	}
	if {[file extension $path] == {}} {
	    append path ".trk"
	}
    }

    return $path
}

proc MvmTracer:clearLog {context} {

    if {[tk_messageBox -parent $context \
	     -message "Are you sure? Please confirm." \
	     -type okcancel -icon error -title " "] != "ok"} {
	return
    }

    global $context.info MvmTracer:lineCount

    set $context.info(searchindex) @0,0
    set textw [[set $context.info(tracebuffer)] subwidget text]
    $textw configure -state normal
    $textw delete 1.0 end
    $textw configure -state disabled
    set MvmTracer:lineCount 0
}

proc MvmTracer:optionChanged {context {localopt {}}} {

    global $context.info

    if {$localopt != {}} {
	switch -- $localopt {
	    hideselectors {
		if {[set $context.info(hideselectors)] == 1} {
		    $context.panew forget p1
		} {
		    $context.panew manage p1 -before p2 -min 200 -expand 0.40
		}
	    }
	}
	return
    }

    set $context.info(changed) true
}

proc MvmTracer:processEvent {context name1 name2 op} {

    global $context.info

    set buttons [set $context.info(buttons)]

    while {[popEvent eventQueue:$context e] == "true"} {
	switch -- $e {

	    TracerInitEvent {
		global MvmTracer:simulationState

		set MvmTracer:simulationState \
		    [TkRequest $context GetSimulationState]

		switch -- ${MvmTracer:simulationState} {
		    released {
			# may not release/step simulation
			$buttons.release config -state disabled
			$buttons.step config -state disabled
			# may hold simulation
			$buttons.hold config -state normal
		    }
		    held {
			# may release/step simulation
			$buttons.release config -state normal
			$buttons.step config -state normal
			# may not hold simulation
			$buttons.hold config -state disabled
		    }
		    zombie {
			# may not release/step simulation
			$buttons.release config -state disabled
			$buttons.step config -state disabled
			# may not hold simulation
			$buttons.hold config -state disabled
			# cannot switch focuses
			[set $context.info(focuscombo)] config -state disabled
		    }
		}
		MvmTracer:restoreSettings $context
	    }

	    ThreadCreatedEvent -
	    ThreadDeletedEvent {
		MvmTracer:updateThreads $context false
	    }

	    DebuggeeReleasedEvent -
	    SimulationReleasedEvent {
		global MvmTracer:simulationState
		set MvmTracer:simulationState released
		# may not release/step simulation
		$buttons.release config -state disabled
		$buttons.step config -state disabled
		# may hold simulation
		$buttons.hold config -state normal
	    }

	    DebuggeeHeldEvent -
	    SimulationHeldEvent {
		global MvmTracer:simulationState
		if {${MvmTracer:simulationState} == "released"} {
		    # may release/step simulation
		    $buttons.release config -state normal
		    $buttons.step config -state normal
		    set MvmTracer:simulationState held
		}
		# may not hold simulation
		$buttons.hold config -state disabled
	    }

	    SimulationFinishedEvent {
		global MvmTracer:simulationState
		set MvmTracer:simulationState zombie
		# may not hold simulation
		$buttons.hold config -state disabled
		global $context.info
		# cannot switch focuses
		[set $context.info(focuscombo)] config -state disabled
	    }

	    ConfigurationChanged {
		# reload thread selector
		MvmTracer:updateThreads $context
 	    }

	    MonitorShutdownEvent {
		MvmTracer:saveSettings $context
	    }
	}
    }
}

proc MvmTracer:saveSettings {context} {

    global $context.info

    set entries [array get $context.info tracelist,*]
    set n -1
    set settings {}

    while {1} {
	set s [lindex $entries [incr n]]

	if {$s == {}} {
	    break
	}

	regexp -- "tracelist,(.*)" $s mvar iname
	set traces [lindex $entries [incr n]]
	lappend settings [list $iname $traces]
    }

    set options {}

    foreach opt {callouts errorbrk nofiltering hideselectors} {
	if {[set $context.info($opt)] == 1} {
	    lappend options $opt
	}
    }
    if {$options == {}} {
	set options {none}
    }

    set geometry [wm geometry $context]

    Project:setResource MonitorTraces [list $options $settings $geometry]
}

proc MvmTracer:restoreSettings {context} {

    global $context.info

    set setup [Project:getResource MonitorTraces]
    set options [lindex $setup 0]
    set settings [lindex $setup 1]
    set geometry [lindex $setup 2]

    # restore trace options
    foreach opt $options {
	set $context.info($opt) 1
    }

    # apply local options now
    if {[set $context.info(hideselectors)] == 1} {
	MvmTracer:optionChanged $context hideselectors
    }

    # restore trace settings
    foreach interface $settings {
	set tab [lindex $interface 0]
	set c [set $context.info(checklist,$tab)]
	foreach entry [lindex $interface 1] {
	    catch {
		$c setstatus $entry on
		MvmTracer:toggleTrace $context $c $tab $entry
	    }
	}
    }

    if {$geometry != {}} {
	wm geometry $context $geometry
    } {
	wm geometry $context 750x600
    }
}

proc MvmTracer:searchText {context textw} {

    global $context.info

    if {[catch {set sel [$textw get sel.first sel.last]}] == 0} {
	set pretyped $sel
    } {
	set pretyped {}
    }

    set w $context.rewin

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	set e [$w.f.re subwidget entry]
	if {$pretyped != {}} {
	    $e delete 0 end
	    $e insert end $pretyped
	}
	focus $e
	return
    }

    toplevel $w
    wm protocol $w WM_DELETE_WINDOW "wm withdraw $w"
    wm title $w "Search String"
    wm resizable $w 0 0
    cascadeWindow $w $context

    set f [frame $w.f -bd 1 -relief sunken]
    pack $f -side top -fill both -expand yes

    tixLabelEntry $f.re -label "Find:" \
	-options {
	    label.anchor w
	    entry.width 22
	}

    set e [$f.re subwidget entry]
    pack $f.re -pady 5 -anchor w -padx 5
    bind $e <Return> "MvmTracer:findString $context $textw"
    bind $e <Escape> "wm withdraw $w"
    $e insert end $pretyped

    set f2 [frame $f.opt -relief flat -bd 0]
    pack $f2 -fill both -expand yes

    set $context.info(searchwhence) -forward
    set $context.info(searchindex) @0,0

    radiobutton $f2.bck -text backward \
	-variable $context.info(searchwhence) \
	-relief flat -bd 2 -pady 0 -anchor w \
	-value -backward

    radiobutton $f2.fwd -text forward \
	-variable $context.info(searchwhence) \
	-relief flat -bd 2 -pady 0 -anchor w \
	-value -forward

    pack $f2.fwd $f2.bck -side right -padx 5

    set status [frame $w.status -height 20 -relief sunken -bd 1]
    pack $w.status -fill x -expand no
    label $w.status.msg
    pack $w.status.msg -side left

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add search -text Search -command "MvmTracer:findString $context $textw"
    $w.bbox add clear -text Clear -command "$e delete 0 end"
    $w.bbox add dismiss -text Close -command "wm withdraw $w"
    pack $w.bbox -expand no -fill x

    focus $e
}

proc MvmTracer:findString {context textw} {

    global $context.info

    set w $context.rewin
    set e [$w.f.re subwidget entry]
    set whence [set $context.info(searchwhence)]
    set sow [set $context.info(searchindex)]
    set s [$e get]

    if {$s == {}} {
	return
    }

    if {[catch { set sow \
 		     [$textw search $whence -exact -count n -- $s $sow] }] == 0} {
	if {$sow != {}} {
	    set eow [lindex [split $sow .] 0].[expr [lindex [split $sow .] 1] + $n]
	    $textw tag remove sel 1.0 end
	    $textw tag add sel $sow $eow
	    $textw see $sow
	    if {$whence == "-forward"} {
		set $context.info(searchindex) $eow
	    } {
		set $context.info(searchindex) $sow
	    }
	    $w.status.msg config -text {}
	    return
	}
    }

    $w.status.msg config -text "\"[$e get]\" not found."
    bell
}

proc MvmTracer:withdraw {context} {

    if {[winfo exists $context.rewin]} {
	wm withdraw $context.rewin
    }

    wm withdraw $context
}

proc MvmTracer:selectAll {context} {

    global $context.info

    set nb [set $context.info(notebook)]
    set cpage [$nb raised]
    set tab [$nb pagecget $cpage -label]
    set c [set $context.info(checklist,$tab)]
    set callint [lindex [set $context.info(definition)] $cpage]
    set interface [lindex $callint 1]
    set fnum 0

    foreach group $interface {
	set services [lindex $group 1]
	set cnum 0
	foreach call $services {
	    set entry $fnum.$cnum
	    $c setstatus $entry on
	    MvmTracer:toggleTrace $context $c $tab $entry
	    incr cnum
	}
	incr fnum
    }
}

proc MvmTracer:selectNone {context} {

    global $context.info

    set nb [set $context.info(notebook)]
    set cpage [$nb raised]
    set tab [$nb pagecget $cpage -label]
    set c [set $context.info(checklist,$tab)]
    set callint [lindex [set $context.info(definition)] $cpage]
    set interface [lindex $callint 1]
    set fnum 0

    foreach group $interface {
	set services [lindex $group 1]
	set cnum 0
	foreach call $services {
	    set entry $fnum.$cnum
	    $c setstatus $entry off
	    MvmTracer:toggleTrace $context $c $tab $entry
	    incr cnum
	}
	incr fnum
    }
}
