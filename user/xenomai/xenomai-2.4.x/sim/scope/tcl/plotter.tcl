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
#  Author(s): rwestrel
#  Contributor(s):
#
#  Adapted to XENOMAI by Philippe Gerum.

# global tcl_traceExec
# set tcl_traceExec 1

# name of hosting tool
set plotter:toolname "Plotter"

# borders
set plotter:leftb 60
set plotter:rightb 30
set plotter:topb 30
set plotter:bottomb 40

# colors
set plotter:axisColor black

# reticle color for histograms and time graphs
if {$tcl_platform(platform) != "windows"} {
    set plotter:reticleHistoColor white
    set plotter:reticleTimeColor black
} else {
    set plotter:reticleHistoColor red
    set plotter:reticleTimeColor red
}

# *** toolbar ***
# Calls the right user defined command when a button is pressed.
# Shouldn't be called directly.

proc toolbar:command {context button selected} {
    upvar #0 toolbar:$context:command cmdArray
    upvar #0 toolbar:c2w c2w
    upvar #0 toolbar:itsSide itsSide

    set master $c2w($context)

    if {$itsSide($button) == "left"} {
	set toolbar $master.tb.ltoolbar
    } else {
	set toolbar $master.tb.rtoolbar
    }

    if {$selected} {
	$toolbar invoke $button
	eval $cmdArray($button)
    }
}

# Builds a toolbar with a status bar to display help messages
# command: a list of commands to call when button is pressed
# icons: a list of icons (one for each button)
# help: a list of help messages
# gridToolbar & gridStatus: arguments for the grid geometry manager
proc toolbar:addToolBar {context master gridToolbar gridStatus} {

    global toolbar:$context:command
    global toolbar:var
    global toolbar:c2w 
    global toolbar:bs 

    set toolbar:c2w($context) $master

    set toolbar:var($context) ""
    label $master.status  -textvariable toolbar:var($context) -relief groove -borderwidth 2
    frame $master.tb -relief raised -borderwidth 2
    tixSelect $master.tb.ltoolbar -allowzero true -radio true -command "toolbar:command $context"
    tixSelect $master.tb.rtoolbar -allowzero true -radio true -command "toolbar:command $context"
    
    eval grid $master.tb $gridToolbar
    eval grid $master.status $gridStatus
    pack $master.tb.ltoolbar -pady 5 -side left -anchor w
    pack $master.tb.rtoolbar -pady 5 -side right -anchor e
    set toolbar:bs ""
}

proc toolbar:addButton {context name command help icon state side} {
    global toolbar:$context:command
    global toolbar:var
    upvar #0 toolbar:c2w c2w
    upvar #0 toolbar:itsSide itsSide

    set master $c2w($context)

    if {$side == "left"} {
	set toolbar $master.tb.ltoolbar
    } else {
	set toolbar $master.tb.rtoolbar
    }

    set itsSide($name) $side
    set shorthelp [lindex $help 0]
    set longhelp [lindex $help 1]

    set toolbar:$context:command($name) $command
    if {[string index $icon 0] == "@"} {
	$toolbar add $name -bitmap $icon
    } else {
	$toolbar add $name -image [fetchImage $icon]
    }
    set button [$toolbar subwidget $name]
    setStaticTooltip $button $shorthelp
    pack $button -expand false -side left
    $button configure -state $state
    # here, I build my own balloon since the tixBalloon widget is pretty f**ked up
    bind $button <Enter> \
	"+ set toolbar:bs $name; set toolbar:var($context) \"$longhelp\""
    bind $button <Leave> \
	"+ set toolbar:bs \"\"; set toolbar:var($context) \"\""
}

proc toolbar:modifyButton {context name command help icon state} {
    global toolbar:$context:command
    upvar #0 toolbar:var var
    upvar #0 toolbar:c2w c2w
    upvar #0 toolbar:bs bs
    upvar #0 toolbar:itsSide itsSide

    set master $c2w($context)

    if {$itsSide($name) == "left"} {
	set toolbar $master.tb.ltoolbar
    } else {
	set toolbar $master.tb.rtoolbar
    }

    set toolbar:$context:command($name) $command
    set button [$toolbar subwidget $name]
    set shorthelp [lindex $help 0]
    set longhelp [lindex $help 1]

    if {[string index $icon 0] == "@"} {
	$button configure -bitmap $icon
    } else {
	$button configure -image [fetchImage $icon]
    }

    setStaticTooltip $button $shorthelp
    bind $button <Enter> "+ set toolbar:bs $name; set toolbar:var($context) \"$longhelp\""
    bind $button <Leave> "+ set toolbar:bs \"\"; set toolbar:var($context) \"\""
    
    if {$bs == $name} {
	set var($context) $longhelp
    }
    $button configure -state $state
}

proc toolbar:destroy {context} {
    upvar #0 toolbar:$context:command command
    
    destroy $context.status
    destroy $context.tb.ltoolbar
}

# *** chklist ***
proc chklist:getSelection {chkListId} {
    upvar #0 chklist:selection2context s2c
    
    set selected [$chkListId getselection]
    
    set selectedContext {}
    foreach i $selected {
	lappend selectedContext $s2c($i)
    }
    
    return $selectedContext
}


proc chklist:addInHList {list chkListId level contextList onList} {
    upvar #0 chklist:selection2context s2c

    set hlistId [$chkListId subwidget hlist]
    set size [llength $list]
    if {$level == ""} {
	set level ""
    } else {
	set level $level.
    }
    set j 0
    set subtree 0
    set entry {}
    for {set i 0} {$i < $size} {incr i} {
	set sublist [lindex $list $i]
	if {$subtree} {
	    incr j
	    set contextList [chklist:addInHList $sublist $chkListId $level[expr $i -$j] $contextList $onList]
	    set subtree 0
	} else {
	    if {[llength $sublist] != 0 } {
		set entry $level[expr $i - $j]
		$hlistId add $entry -itemtype imagetext -text $sublist -style leafImageStyle
		set el [FIFOget contextList]
		if {[plotter:lremove onList $el]} {
		    $chkListId setstatus $level[expr $i -$j] on
		    chklist:selectAll $chkListId $level[expr $i -$j]
		} else {
		    $chkListId setstatus $level[expr $i -$j] off
		    chklist:selectAll $chkListId $level[expr $i -$j]
		}
		set s2c($level[expr $i -$j]) $el
	    } else {
		set sublist [lindex $list [expr $i + 1]]
		if {[llength $sublist] != 0 } {
		    if {$entry != {}} {
			$hlistId entryconfig $entry -style rootImageStyle
		    }
		    set subtree 1
		} else {
		    $hlistId add $level[expr $i - $j] -itemtype imagetext 
		    set el [FIFOget contextList]
		    if {[plotter:lremove onList $el]} {
			$chkListId setstatus $level[expr $i -$j] on
			chklist:selectAll $chkListId $level[expr $i -$j]
		    } else {
			$chkListId setstatus $level[expr $i -$j] off
			chklist:selectAll $chkListId $level[expr $i -$j]
		    }
		    set s2c($level[expr $i -$j]) $el 
		    incr i 
		}
		incr j
	    }
	}
    }
    return $contextList
}

proc chklist:changeChildrenState {chkListId level newState first} {
    set hListId [$chkListId subwidget hlist]

    set nextfirst 0
    if {$level == ""} {
	set nextlevel [$hListId info children]
    } else {
	if {! $first} {
	    $chkListId setstatus $level $newState
	    set nextfirst 0
	}
	set nextlevel [$hListId info children $level]
    }
    foreach i $nextlevel {
	chklist:changeChildrenState $chkListId $i $newState $nextfirst
    }
}

proc chklist:changeParentState {chkListId entry} {
    set status [$chkListId getstatus $entry]
    
    
    set isoff 0
    if {$status == "on"} {
	set hListId [$chkListId subwidget hlist]
	set parent [$hListId info parent $entry]
	if {$parent != ""} {
	    set nextlevel [$hListId info children $parent]
	    foreach i $nextlevel {
		if {[$chkListId getstatus $i] == "off"} {
		    incr isoff
		}
	    }
	    if {! $isoff} {
		$chkListId setstatus $parent on
		chklist:changeParentState $chkListId $parent
	    }
	}
    }
}

proc chklist:selectAll {chkListId entry} {

    set status [$chkListId getstatus $entry]

    # change the state of the parent nodes if the current one is on and all its brothers are on
    chklist:changeParentState $chkListId $entry

    # change the state of all the children nodes 
    chklist:changeChildrenState $chkListId $entry $status 1
    
    # change the state of the parent nodes if the current one is off
    if {$status == "off"} {
	set hListId [$chkListId subwidget hlist]
	set parent [$hListId info parent $entry]
	while {$parent != ""} {
	    $chkListId setstatus $parent $status
	    set parent [$hListId info parent $parent]
	}
    }
}

# *** layout ***

# The following procedures are used to display the group in the display layout.
# The code for the display layout was designed to use context (one context per node)
# so here I add "dummy contexts" (for each group) in order to make sure that each node 
# is equivalent to a context. That's quite heavy and not very smart.
proc layout:addInArray {arrayName element val} {
    upvar 1 $arrayName array
    if {![plotter:lempty [array names array $element]]} {
	plotter:ladd array($element) $val
    } else {
	set array($element) $val
    }
}

proc layout:buildModifiedHierarchy {context} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:modifiedHierarchy modifiedHierarchy
    upvar #0 plotter:nameArray nameArray
    upvar #0 plotter:properties properties

    set id [array startsearch hierarchy]

    while {[array anymore hierarchy $id]} {
	set el [array nextelement hierarchy $id]
	if {[plotter:pathDepth $el] == 3} {
	    
	    set inv $invertedHierarchy($el)	    
	    set nameList [lindex $properties($el) 0]
	    set s [llength $nameList]
	    set last $inv
	    
	    for {set i 1} {$i < $s} {incr i} {
		set name [lindex $nameList $i]
		set dummyContext [plotter:removeSpaces $name]
		layout:addInArray modifiedHierarchy $last $last-$dummyContext 
		set nameArray($last-$dummyContext) $name
		set last $last-$dummyContext
	    }
	    layout:addInArray modifiedHierarchy $last $el
	    set nameArray($el) [lindex [lindex $properties($el) 0] 0]
	    set modifiedHierarchy($el) {}
	} else {
	    if {[plotter:pathDepth $el] != 2} {
		set modifiedHierarchy($el) $hierarchy($el)
	    }
	    set nameArray($el) [lindex [lindex $properties($el) 0] 0]
	}
    }
    layout:sortModifiedHierarchy $context 0 ;# don't sort the first level
}

proc layout:sortCmd {el1 el2} {
    upvar #0 plotter:nameArray nameArray

    return [string compare $nameArray($el1) $nameArray($el2)]
}

proc layout:sortModifiedHierarchy {context sortThisLevel} {
    upvar #0 plotter:modifiedHierarchy modifiedHierarchy
  
    if {! [plotter:lempty $modifiedHierarchy($context)]} {
	if {$sortThisLevel} {
	    set sortedList [lsort -command layout:sortCmd $modifiedHierarchy($context)]
	    set modifiedHierarchy($context) $sortedList
	}
	
	foreach i $modifiedHierarchy($context) {
	    layout:sortModifiedHierarchy $i 1
	}
    }
}

proc layout:modifiedHierarchyCleanUp {contextList} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:modifiedHierarchy modifiedHierarchy
    upvar #0 plotter:nameArray nameArray

    set res {}
    foreach i $contextList {
	if {![plotter:lempty [array names hierarchy $i]]} {
	    lappend res $i
	}
    }
    unset modifiedHierarchy
    unset nameArray
    return $res
    
}

proc layout:buildChklistArg {level contextList} {
    upvar #0 plotter:nameArray nameArray
    upvar #0 plotter:modifiedHierarchy hierarchy
    upvar 1 $contextList list
    
    foreach i $level {
	lappend list $i
	if {$nameArray($i) == ""} {
	    lappend result {} {}
	} else {
	    lappend result $nameArray($i)
	}
	
	if {[llength $hierarchy($i)] != 0} {
	    lappend result {}
	    lappend result [layout:buildChklistArg $hierarchy($i) list]
	}
    }
    return $result
}

proc layout:onOk {context cmd} {
    global mainContext
    upvar #0 layout:displayed displayed
    plotter:startIsBusy $mainContext

    set displayed [eval $cmd]
    set displayed [layout:modifiedHierarchyCleanUp $displayed]
    plotter:display $context [plotter:setDisplayedContext $context $displayed]
    destroy $context.layout
    plotter:stopIsBusy $mainContext

    if {[TkRequest $mainContext GetBackendState] == "running"} {
	plotter:simRunning $context
    }
}

proc plotter:menuHack {context} {
    if {[plotter:pathDepth $context] == 1} {
	return [plotter:getVisiblePlotter $context]
    } else {
	return $context
    }
}

proc layout:display {context} {
    global mainContext
    upvar #0 layout:displayed displayed

    if { [winfo exists $mainContext.layout]} {
	wm deiconify $mainContext.layout
	raise $mainContext.layout
	return;
    }
    
    if {![info exists displayed]} {
	set displayed {}
    }

    set layout [toplevel $mainContext.layout]
    wm title $layout "Graph Selector"
    bind $layout <Escape> "destroy  $layout"
    cascadeWindow $layout
    
    plotter:sortContext $mainContext
    layout:buildModifiedHierarchy $mainContext
    set item [layout:buildChklistArg $mainContext contextList]
    set myDisplayed [layout:buildDisplayedList]

    set chk $layout.chk
    tixCheckList $chk -scrollbar auto \
	-options {hlist.indicator 1} -width 350 -height 450
    chklist:addInHList $item $chk "" $contextList $myDisplayed
    $chk config -browsecmd "chklist:selectAll $chk"
    $chk config -command "chklist:selectAll $chk"
    $chk autosetmode
    focus [$chk subwidget hlist]
    pack $chk -fill both -expand yes

    set box [tixButtonBox $layout.box -relief flat -bd 0]
    set cmd "chklist:getSelection $chk"
    $box add ok -text OK -command "layout:onOk $mainContext \"$cmd\"" -width 6
    $box add cancel -text Cancel -command "destroy $layout"
    pack $box -fill x -expand no
}

proc layout:buildDisplayedList {} {
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects     
    
    set list {}
    foreach i $plotters {
	foreach j $objects($i) {
	    lappend list $j
	}
    }
    return $list
}

# *** FIXME ***
# this doesn't work.
proc plotter:pixel2point {pixel} {
    set point2pixel [tk scaling]
    
    set point [expr $pixel / $point2pixel]
    return [expr round($point)] 
}

proc plotter:point2pixel {points} {
    set pixelsPerPoint [tk scaling]
    return [expr $points * $pixelsPerPoint]
}

proc plotter:initFont {} {
    if {[lsearch -exact [font names] "plotter:axis"] == -1} {
	# regular font for axises
	eval font create plotter:axis [font actual -*-helvetica-medium-r-normal--8-*-*-*-*-*-*-*]
    }
    if {[lsearch -exact [font names] "plotter:vAxisComp"] == -1} {
	# font used when the display is vertically compressed
	eval font create plotter:vAxisComp [font actual -*-helvetica-medium-r-normal--8-*-*-*-*-*-*-*]
    }
    if {[lsearch -exact [font names] "plotter:vAxis"] == -1} {
	# font used for vertical axis text (starts as a copy of plotter:axis)
	eval font create plotter:vAxis [font configure plotter:axis]
    }
}

# a descritpion of what the toolbars/menus must contain
proc plotter:initFunction {} {
    upvar #0 plotter:functionnalitiesListCurve fListC
    upvar #0 plotter:functionnalitiesListHisto fListH
    upvar #0 plotter:functionnalitiesLocalTimeGraph fLocalTG
    upvar #0 plotter:functionnalitiesLocalTimeState fLocalTS
    upvar #0 plotter:functionnalitiesLocalHisto fLocalH
    upvar #0 plotter:functionnalitiesLocalCMPD fLocalCMPD
    upvar #0 plotter:functionnalitiesDescription fDes
    upvar #0 plotter:mainMenu mainMenu

    # a list of the ids of the functionnalities (ie buttons or fields in a menu)
    set fListC [list displayed printAll compress zoomIn zoomOut session vcompress \
		    globalBreak simCont simStop]
    set fListH [list displayed printAll histoPoll session vcompress] 
    set fLocalTG [list modeTime color printOnePlot seek localTimeG remove]
    set fLocalTS [list modeTime color printOnePlot seek remove]
    set fLocalH [list color histoDisplay histoView printOnePlot localHisto remove]
    set fLocalCMPD [list modeTime multiPlotColor multiPlotContext seek localCMPD]
    set mainMenu [list {"File" {mdisplayed mprintAll msession msep mquit} plotter:noop} \
		      {"View" {mhistoPoll msep mcompress mzoomIn mzoomOut mvcompress msep mglobalBreak} \
			   plotter:preProcessCurrentState} \
		      {"Options" {mxadjust mscrollLock mcolorChoice mautoSession} plotter:getGlobalTConf}]
    
    # and an array giving a description of the functionnalities (to be used to build a
    # toolbar or a menu): the command to call, a help message, an icon bitmap (a file), the state 
    # Of the field and possibly additionnal informations for menus
    set fDes(displayed-1) [list layout:display {"Select" "Select graphs to display"} select normal left]
    set fDes(compress-1) [list plotter:compress {"X-compress" "Compress time scale"} compress normal left]
    set fDes(compress-2) [list plotter:uncompress {"X-uncompress" "Uncompress time scale"} uncompress normal left]
    set fDes(vcompress-1) [list plotter:verticalCompress {"Y-compress" "Pack graphs vertically"}  ycompress normal left]
    set fDes(vcompress-2) [list plotter:verticalUncompress {"Y-uncompress" "Unpack graphs vertically"} yuncompress normal left]
    set fDes(vcompress-3) [list plotter:noop {"Y-compress" "Pack graphs vertically"} ycompress disabled left]
    set fDes(zoomIn-2) [list plotter:zoomIn {"Zoom in" "Zoom in 200%%"} zoomin normal left]
    set fDes(zoomIn-1) [list plotter:zoomIn {"Zoom in" "Zoom in 200%%"} zoomin disabled left]
    set fDes(zoomOut-2) [list plotter:zoomOut {"Zoom out" "Zoom out 50%%"} zoomout normal left]
    set fDes(zoomOut-1) [list plotter:zoomOut {"Zoom out" "Zoom out 50%%"} zoomout disabled left]
    set fDes(histoPoll-1) [list plotter:histoPoll {"Update" "Actualize histograms"} update normal left]
    set fDes(printAll-1) [list plotter:printAll {"Print" "Print all graphs"} print normal left]
    set fDes(simCont-1) [list plotter:simCont {"Continue" "Continue execution"} cont normal right]
    set fDes(simStop-1) [list plotter:simStop {"Stop" "Suspend execution"} break disabled right]
    set fDes(simCont-2) [list plotter:simCont {"Continue" "Resume execution"} cont disabled right]
    set fDes(simStop-2) [list plotter:simStop {"Stop" "Suspend execution"} break normal right]
    set fDes(session-1) [list plotter:saveSession {"Save" "Save current session"} save normal left]
    set fDes(globalBreak-1) [list plotter:globalBreakpointStart {"Breakpoints" "Edit breakpoints"} plotbrk normal left]

    set fDes(mquit-1) [list plotter:dismiss "Close" "" normal command \
			   {-underline 0}]
    set fDes(mdisplayed-1) [list layout:display "Select" "" normal command \
				"-underline 0"]
    set fDes(mcompress-1) [list plotter:compress "X-compress" "" normal command \
			       "-underline 0"]
    set fDes(mcompress-2) [list plotter:uncompress "X-uncompress" "" normal command \
			      "-underline 0"]
    set fDes(mcompress-3) [list plotter:uncompress "X-uncompress" "" disabled command \
			       "-underline 0"]
    set fDes(mvcompress-1) [list plotter:verticalCompress "Y-compress" "" normal command \
				"-underline 0"]
    set fDes(mvcompress-2) [list plotter:verticalUncompress "Y-uncompress" "" normal command \
				"-underline 0"]
    set fDes(mvcompress-3) [list plotter:noop "Y-compress" "" disabled command \
				"-underline 0"]
    set fDes(mzoomIn-2) [list plotter:zoomIn "Zoom In 200%" "" normal command \
			    "-underline 5"]
    set fDes(mzoomIn-1) [list plotter:zoomIn "Zoom In 200%" "" disabled command \
			    "-underline 5"]
    set fDes(mzoomOut-2) [list plotter:zoomOut "Zoom Out 50%" "" normal command \
			     "-underline 5"]
    set fDes(mzoomOut-1) [list plotter:zoomOut "Zoom Out 50%" "" disabled command \
			     "-underline 5"]
    set fDes(mhistoPoll-1) [list plotter:histoPoll "Update" "" disabled command \
			       "-underline 0"]
    set fDes(mhistoPoll-2) [list plotter:histoPoll "Update" "" normal command \
			       "-underline 0"]
    set fDes(mprintAll-1) [list plotter:printAll "Print" "" normal command \
			      "-underline 0" ]
    set fDes(msession-1) [list plotter:saveSession "Save" "" normal command \
			     "-underline 0"]
    set fDes(mxadjust-1) [list "plotter:setGlobalTConf xadjust" "X-adjust" "" normal checkbutton \
					 {-onvalue 1  -variable mainMenu:xadjust}]
    set fDes(mscrollLock-1) [list "plotter:setGlobalTConf linked" "Scroll lock" "" normal checkbutton \
					 {-onvalue 1  -variable mainMenu:linked}]
    set fDes(mcolorChoice-1) [list "plotter:setGlobalTConf colorAuto"  "Auto-select color" "" normal checkbutton \
					 {-onvalue 1  -variable mainMenu:colorAuto}]
    set fDes(mxadjust-2) [list plotter:noop "X adjust" "" disabled checkbutton \
					 {-onvalue 1  -variable mainMenu:xadjust}]
    set fDes(mscrollLock-2) [list plotter:noop  "Scroll lock" "" disabled checkbutton \
					 {-onvalue 1  -variable mainMenu:linked}]
    set fDes(mcolorChoice-2) [list plotter:noop "Auto-select color" "" disabled checkbutton \
					 {-onvalue 1  -variable mainMenu:colorAuto}]
    set fDes(mautoSession-1) [list "plotter:setGlobalTConf autoSaveSession"  \
				  "Auto-save session" "" normal checkbutton \
				  {-onvalue 1  -variable mainMenu:autoSaveSession}]
    set fDes(mglobalBreak-1) [list plotter:globalBreakpointStart "Breakpoints" \
				  "" normal command "-underline 0"]
    set fDes(mglobalBreak-2) [list plotter:noop "Breakpoints" \
				  "" disabled command "-underline 0"]
    set fDes(msep-1) [list plotter:noop "" "" normal separator]

    # procedure to call, menu entry label, "" (no icon), state, type 
    # optionnal arg 1: additionnal arguments for the menu entry (as expected by tcl)
    # optionnal arg 2: for a cascade, the list of the children menu entry
    set fDes(modeTime-1) [list plotter:noop "Mode" "" normal cascade "" {modeNormal modeSelection modeBreakpts}]
    set fDes(modeHisto-1) [list plotter:noop "Mode" "" normal cascade "" {modeNormal modeSelection}]
    set fDes(modeNormal-1) [list plotter:modeNormal "Normal" "" normal radiobutton \
				{-value normal -variable plotter:mode($context)}]
    set fDes(modeSelection-1) [list selection:beforeDrag "Selection" "" normal radiobutton \
				   {-value sel  -variable plotter:mode($context)}]
    set fDes(modeBreakpts-1) [list breakpoint:beforeDrag "Breakpoint" "" normal radiobutton \
				  {-value break -variable plotter:mode($context)}]
    set fDes(color-1) [list plotter:setPlotColor "Colors" "" normal command]
    set fDes(poll-1) [list plotter:localHistoPoll  "Poll" "" normal command]

    set fDes(histoDisplay-1) [list plotter:noop  "Display" "" normal cascade "" \
				  {histoDisplayDensity histoDisplayRep}]
    set fDes(histoDisplayDensity-1) [list plotter:setHistoDisplay "Density" "" normal radiobutton \
					 {-value density -variable plotter:histoDisplay($context)}]
    set fDes(histoDisplayRep-1) [list plotter:setHistoDisplay "Repartition" "" normal radiobutton \
					 {-value rep -variable plotter:histoDisplay($context)}]

    set fDes(histoView-1) [list plotter:noop  "View" "" normal cascade "" \
			       {histoViewRel histoViewAbs}]
    set fDes(histoViewRel-1) [list plotter:setHistoView "Relative" "" normal radiobutton \
				  {-value rel -variable plotter:histoView($context)}]
    set fDes(histoViewAbs-1) [list plotter:setHistoView "Absolute" "" normal radiobutton \
				  {-value abs -variable plotter:histoView($context)}]
    set fDes(printOnePlot-1) [list plotter:printThis  "Print" "" normal command]
    set fDes(localTimeG-1) [list plotter:localTimeMenu "Advanced" "" normal command]
    set fDes(localHisto-1) [list plotter:localHistoMenu "Advanced" "" normal command]

    set fDes(seek-2) [list plotter:noop "Seek" "" disabled cascade "" {seekFw seekBw}]
    set fDes(seek-1) [list plotter:noop "Seek" "" normal cascade "" {seekFw seekBw}]
    set fDes(seekBw-1) [list plotter:seekBw "Backward" "" normal command]
    set fDes(seekFw-1) [list plotter:seekFw "Forward" "" normal command]
    set fDes(remove-1) [list plotter:removeThisGraph "Remove" "" normal command]
}

proc plotter:setHierarchy {context masterContext} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    if {$masterContext != ""} {
	if {[info exists hierarchy($masterContext)] == 1} {
	    if {[lsearch -exact [set hierarchy($masterContext)] $context] != -1} {
		return
	    }
	}
	lappend hierarchy($masterContext) $context
    }

    set invertedHierarchy($context) $masterContext

    if {[array names hierarchy $context] == ""} {
	set hierarchy($context) {}
    }

    if {[array names invertedHierarchy $masterContext] == "" } {
	if {$masterContext != ""} {
	    set invertedHierarchy($masterContext) ""
	}
    }

    global mainContext
    upvar #0 plotter:properties properties    
    set properties($context) [TkRequest $context GetProperties]

    if {[plotter:pathDepth $context] == 3} {
	plotter:getGraphSession $mainContext $context
	plotter:dynamicGraphSession $mainContext $context
    } else {
	if {[plotter:pathDepth $context] == 2} {
	    plotter:getPlottersSession $mainContext $context
	}
    }
}

proc plotter:unSetHierarchy {context masterContext} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    if {[info exists hierarchy($masterContext)]} {
	plotter:lremove hierarchy($masterContext) $context
    }
    if {[info exists hierarchy($context)]} {
	unset hierarchy($context)
    }
}

proc plotter:setProperties {context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:hierarchy hierarchy

    set properties($context) [TkRequest $context GetProperties]
    
    foreach i $hierarchy($context) {
	plotter:setProperties $i
    }
}

proc plotter:unmap {w} {
    upvar #0 plotter:toplevels toplevels
    global mainContext
    foreach i $toplevels {
	wm withdraw $i
    }
}

proc plotter:map {w} {
    upvar #0 plotter:toplevels toplevels
    global mainContext
    foreach i $toplevels {
	wm deiconify $i
    }
}

proc plotter:addTopLevel {w} {
    upvar #0 plotter:toplevels toplevels
    global mainContext
    if {[plotter:isInApp $w] && $mainContext != $w} {
	plotter:ladd toplevels $w
    }
}

proc plotter:rmTopLevel {w} {
    upvar #0 plotter:toplevels toplevels
    global mainContext
    if {[plotter:isInApp $w] && $mainContext != $w} {
	plotter:lremove toplevels $w
    }
}

proc plotter:isInApp {w} {
    global mainContext
    regexp {(\.[^/.]+)(\.[^/.]+)*} $w dummy simpleName
    if {$mainContext == $simpleName} {
	return 1
    }
    return 0
}

proc plotter:initialize {context title toolname} {
    global mainContext
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects
    upvar #0 plotter:compound compound
    upvar #0 plotter:compressDone compressDone

    plotter:initFont
    plotter:initFunction
    
    set mainContext $context
    set plotters {}
    set compound {}
    # Tell Tcl that plotter:objects is an array variable
    set objects(0) {}
    unset objects(0)
    
    upvar #0 plotter:toplevels toplevels
    set toplevels {} 
    toplevel $context
    bind Toplevel <Map> "+ plotter:addTopLevel %W"
    bind Toplevel <Destroy> "+ plotter:rmTopLevel %W"
    bind $context <Unmap> "+ plotter:unmap %W"
    bind $context <Map> "+ plotter:map %W"
        
    if {$title != {}} {
	wm title $context $title
    }
    wm withdraw $context

    wm protocol $context WM_DELETE_WINDOW \
	"plotter:popdown $context"

    plotter:setPrecision 3
    upvar #0 plotter:isInConf isInConf
    # allow only one configuration at a time
    set isInConf 0
    set compressDone 0
    
    global tcl_precision
    set tcl_precision 17

    if {$toolname != {}} {
	global plotter:toolname
	set plotter:toolname $toolname
    }
}

proc plotter:popup {context} {
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects     

    if {[plotter:lempty $plotters]} {
	set todisplay ""
	global plotter:started plotter:reloaded
	if {! [info exists plotter:started]} {
	    set todisplay [plotter:getGraphListSession $context]
	    if {$todisplay != {}} {
		set plotter:reloaded true
	    } {
		set plotter:reloaded false
	    }
	    plotter:getMainContextSession $context
	}
	if {$todisplay != ""} {
	    plotter:display $context $todisplay
	} else {
	    layout:display $context
	}
    } else {
	if {! [winfo ismapped $context]} {
	    foreach i $plotters {
		foreach j $objects($i) {
		    TkRequest $j ProtoSetDisplay
		}
	    }
	    wm deiconify $context
	}
    }
    # FIXME: for MS windows, the $context widget appears below the main window
    # when the selection is done for the first time (call to layout:display
    # in this procedure). One possible reason may be that layout:display creates
    # a toplevel  widget; when the selection is done the $context widget is deiconified
    # and the layout's toplevel widget is destroyed. This destruction seems to cause
    # a raise.

    raise $context
}

proc plotter:dismiss {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    
    plotter:popdown $invertedHierarchy($context)
}

proc plotter:saveSession {context} {
    
    global mainContext
    set context $mainContext

    plotter:setGeometrySession $context [winfo width $context] [winfo height $context]
    plotter:setMainContextSession $context
    plotter:setGraphListSession $context 
    plotter:setPlottersSession $context
    plotter:setGraphSession $context
}

proc plotter:setMainContextSession {context} {
    upvar #0 plotter:autoSaveSession autoSaveSession
    Project:setResource PlotterGlobalConfAutoSaveSession $autoSaveSession
}

proc plotter:getMainContextSession {context} {
    global plotter:autoSaveSession
    set autoSave [Project:getResource PlotterGlobalConfAutoSaveSession]
    if {$autoSave == 1 || $autoSave == 2} {
	set plotter:autoSaveSession $autoSave
    }     
}

proc plotter:setGeometrySession {context w h} {
    if {$w > 1 && $h > 1} {
	Project:setResource PlotterGeometry [list $w $h]
    }
}

proc plotter:getGeometrySession {context} {
    set geometry [Project:getResource PlotterGeometry]
    if {$geometry == ""} {
	set geometry [list 670 720]
    }
    return $geometry
}

proc plotter:setGraphListSession {context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:plotters plotters
    
    set clist {}
    foreach i $plotters {
	set paneList [$i.panedw panes]
	foreach j $paneList {
	    lappend clist $i [plotter:addDots $j $i]
	}
    }
    
    set graphList {}
    
    foreach {i j} $clist {
	set name [list [lindex $properties($i) 0] [lindex $properties($j) 0]]
	if {([lindex $properties($j) 4] == "") || ([lindex $properties($j) 2] != "time")}  {
	    set key Plotter${name}Compound
	    Project:setResource $key ""
	    lappend graphList $name
	} else {
	    foreach k [lindex $properties($j) 4] {
		set thisName [list [lindex $properties($i) 0] [lindex $properties($k) 0]]
		set key Plotter${thisName}Compound
		Project:setResource $key $name
		lappend graphList $thisName
	    }
	}
    }
    Project:setResource PlotterGraphList $graphList
}

proc plotter:getGraphListSession {context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    upvar #0 plotter:eltOfCmpd eltOfCmpd
    upvar #0 plotter:eltName2CmpdName eltName2CmpdName
    upvar #0 plotter:cmpdName2Cont cmpdName2Cont
    
    upvar #0 plotter:compound compound
    upvar #0 plotter:color color
    
    
    set graphList [Project:getResource PlotterGraphList]

    if {$graphList == ""} {
	return ""
    }

    set nameList {}
    set id [array startsearch hierarchy]
    while {[array anymore hierarchy $id]} {
	set el [array nextelement hierarchy $id]
	if {[plotter:pathDepth $el] == 3} {
	    set name [list [lindex $properties($invertedHierarchy($el)) 0] \
			  [lindex $properties($el) 0]]
	    set name2Cont($name) $el
	    lappend nameList $name
	}
    }
    array donesearch hierarchy $id
    
    set eltOfCmpd {}
    foreach i $graphList {
	set key Plotter${i}Compound
	set cmpd [Project:getResource $key]
	if {$cmpd != ""} {
	    lappend eltOfCmpd $i
	    set eltName2CmpdName($i) $cmpd 
	    set cmpdName2Cont($cmpd) "" 
	}
    }

    set contList {}
    set parentList {}

    foreach i $graphList {
	if {[lsearch -exact $nameList $i] != -1} {
	    set parent $invertedHierarchy($name2Cont($i))
	    if {[lsearch -exact $eltOfCmpd $i] != -1} {
		set cmpd $eltName2CmpdName($i)
		if {$cmpdName2Cont($cmpd) == ""} {
		    set cmpdName2Cont($cmpd) [TkRequest $parent BuildCompound]
		    lappend compound $cmpdName2Cont($cmpd)
		    set cont $cmpdName2Cont($cmpd)
		    TkRequest $cont AddToCmpd $name2Cont($i)
		    TkRequest $cont SetCompoundTitle [lindex [lindex $cmpd 1] 0]
		    set properties($cont) \
			[TkRequest $cont GetProperties]
		    lappend contList $cont
		    plotter:updateFunctionForCmpd $cont
		} else {
		    TkRequest $cmpdName2Cont($cmpd) AddToCmpd $name2Cont($i)
		    set properties($cmpdName2Cont($cmpd)) \
			[TkRequest $cmpdName2Cont($cmpd) GetProperties]
		    plotter:updateFunctionForCmpd $cmpdName2Cont($cmpd)
		}
	    } else {
		lappend contList $name2Cont($i)
	    }
	    plotter:ladd parentList $parent
	}
    }
    return [concat $parentList $contList]
}

proc plotter:dynamicGraphSession {context newCont} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    upvar #0 plotter:eltOfCmpd eltOfCmpd
    upvar #0 plotter:eltName2CmpdName eltName2CmpdName
    upvar #0 plotter:cmpdName2Cont cmpdName2Cont

    upvar #0 plotter:color color
    upvar #0 plotter:compound compound

    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects 
    
    if {! [info exists eltOfCmpd]} {
	return
    }
    
    set parent $invertedHierarchy($newCont)
    set name [list [lindex $properties($parent) 0] [lindex $properties($newCont) 0]]

    if {[lsearch -exact $eltOfCmpd $name] != -1} {
	set cmpd $eltName2CmpdName($name)
	if {$cmpdName2Cont($cmpd) == ""} {
	    set cmpdName2Cont($cmpd) [TkRequest $parent BuildCompound]
	    lappend compound $cmpdName2Cont($cmpd)
	    set cont $cmpdName2Cont($cmpd)
	    TkRequest $cont AddToCmpd $newCont
	    TkRequest $cont SetCompoundTitle [lindex [lindex $cmpd 1] 0]
	    set properties($cont) \
		[TkRequest $cont GetProperties]
	    plotter:updateFunctionForCmpd $cont
	    
	    set parentList {}
	    set cList {}
	    foreach i $plotters {
		lappend parentList $i
		foreach j $objects($i) {
		    lappend cList $j
		}
	    }
	    lappend cList $cont
	    plotter:ladd parentList $parent
	    plotter:display $context [concat $parentList $cList]
	} else {
	    if {[lsearch -exact $compound $cmpdName2Cont($cmpd)] != -1} {
		TkRequest $newCont FakeSetDisplay
		TkRequest $cmpdName2Cont($cmpd) AddToCmpd $newCont
		set properties($cmpdName2Cont($cmpd)) \
		    [TkRequest $cmpdName2Cont($cmpd) GetProperties]
		plotter:updateFunctionForCmpd $cmpdName2Cont($cmpd)
	    }
	}
    }
}

proc plotter:setPlottersSession {context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    global mainContext
    
    set plotterList {}

    foreach i $hierarchy($mainContext) {
	set name [lindex $properties($i) 0]
	set el [lindex $hierarchy($i) 0]
	if {[lindex $properties($el) 2] == "time"} {
	    set key Plotter${name}TimeBounds
	    Project:setResource $key [list $tMin($i) $tMax($i)]
	    set key Plotter${name}GlobalConfiguration
	    upvar #0 hbar:linked linked \
		plotter:colorAuto colorAuto
	    set confList [list [TkRequest $i GetConf] $linked($i) $colorAuto($i)]
	    Project:setResource $key $confList
	}
    }
}

proc plotter:getPlottersSession {context newCont} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:hierarchy hierarchy
    
    set name [lindex $properties($newCont) 0]
    set key Plotter${name}TimeBounds
    
    set timeBounds [Project:getResource $key]
    if {$timeBounds != ""} {
	if {[lindex $properties($newCont) 1] == "time"} {
	    set tMax($newCont) [expr $tMin($newCont) + [lindex $timeBounds 1] - [lindex $timeBounds 0]]
	}
    }

    set key Plotter${name}GlobalConfiguration
    set confList [Project:getResource $key]
    if {[lindex $properties($newCont) 1] == "time"} {
	upvar #0 hbar:linked linked \
	    plotter:colorAuto colorAuto
	if {$confList != ""} {
	    set linked($newCont) [lindex $confList 1]
	    set colorAuto($newCont) [lindex $confList 2]
	    TkRequest $newCont SetConf [lindex $confList 0]
	    if {[lindex $confList 0]} {
		upvar #0 plotter:plotterState state
		set state($newCont,compress) 1
	    }
	} else {
	    set linked($newCont) 0
	    set colorAuto($newCont) 1
	}
    }
}

proc plotter:setGraphSession {context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:color color
    global mainContext
    
    foreach i $hierarchy($mainContext) {
	foreach j $hierarchy($i) {
	    # ignore compounds
	    if {([lindex $properties($j) 4] == "") || ([lindex $properties($j) 2] != "time")}  {
		set name [list [lindex $properties($i) 0] [lindex $properties($j) 0]]
		# color
		set key Plotter${name}Color
		Project:setResource $key $color($j)

		# breakpoints 
		set key Plotter${name}Breakpoints
		Project:setResource $key [TkRequest $j GetBreakpointList]
		
		#local conf
		set confList [TkRequest $j GetConf]
		set key Plotter${name}LocalConfiguration
		Project:setResource $key $confList
	    }
	}
    }
}

proc plotter:getGraphSession {context newCont} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:color color    

    set name [list [lindex $properties($invertedHierarchy($newCont)) 0] \
		  [lindex $properties($newCont) 0]]
    set key Plotter${name}Color
    
    set thisColor [Project:getResource $key]
    
    if {$thisColor != ""} {
	set color($newCont) $thisColor
    } else {
	set color($newCont) #000080
    }

    set key Plotter${name}Breakpoints
    set breakList [Project:getResource $key]
    foreach i $breakList {
	set list [TkRequest $newCont SetBreakpoint $i]
    }

    set key Plotter${name}LocalConfiguration
    set confList [Project:getResource $key]
    if {$confList != ""} {
	eval TkRequest $newCont SetConf $confList    
    }
}

proc plotter:popdown {context} {
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects 
    
    wm withdraw $context

    pushEvent Application:event PlotterHiddenEvent
    foreach i $plotters {
	foreach j $objects($i) {
	    TkRequest $j ProtoSetTempConceal
	}
    }
}

proc plotter:destroy {context} {
    # perform cleanup actions here
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects 
    upvar #0 plotter:hierarchy hierarchy

    set objectsToDestroy {}
    foreach i $plotters {
	foreach j $objects($i) {
	    lappend objectsToDestroy $j
	}
    }
    
    plotter:cleanUp $context $objectsToDestroy $plotters

    catch "unset objects"
    catch "unset hierarchy"

    global plotter:started
    if {[info exists plotter:started]} {
	unset plotter:started
    }

    global plotter:tCur
    if {[info exists plotter:tCur]} {
	unset plotter:tCur
    }
    
    destroy $context
    font delete plotter:axis \
	plotter:vAxis \
	plotter:vAxisComp
}

# TODO: heavy, very heavy...
proc plotter:setDisplayedContext {context contextList} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    set display $contextList
    # adds the parent contexts
    foreach i $contextList {
	if {[lsearch -exact $display $invertedHierarchy($i)] == -1} {
	    if {$invertedHierarchy($i) != ""} {
		set display [linsert $display 0 $invertedHierarchy($i)]
	    }
	}
    }

    if {[lsearch -exact $display $context] == -1 && $display != ""} {
	set display [linsert $display 0 $context]
    }

    return $display
}

proc plotter:pathDepth {path} {
    set i 0
    set index [string first "." $path]
    while {$index != -1} {
	incr i
	set path [string range $path [expr $index + 1] end]
	set index [string first "." $path]
    }
    return $i
}

proc plotter:removeDots {path} {
    regsub -all "\\." $path "" result
    return $result
}

proc plotter:removeSpaces {string} {
    regsub -all "\\ " $string "" result
    return $result
}

proc plotter:lempty {list} {
    if {[llength $list] == 0} {
	return 1
    }
    return 0
}

proc plotter:lremove {listName element} {
    upvar 1 $listName list
    
    set index [lsearch -exact $list $element]
    
    if {$index == -1} {
	return 0
    }
    
    set i 0
    while {$index != -1} {
	set list [lreplace $list $index $index]
	set index [lsearch -exact $list $element]
	incr i
    }

    return $i
}

proc plotter:ladd {listName element} {
    upvar 1 $listName list
    set index [lsearch -exact $list $element]
    
    if {$index == -1} {
	lappend list $element
	return 0
    }

    set nextlist [lreplace $list $index $index]
    set index [lsearch -exact $nextlist $element]
    while {$index != -1} {
	set list $nextlist
	set nextlist [lreplace $nextlist $index $index]
	set index [lsearch -exact $nextlist $element]
    }
    return 1
}

proc plotter:panedResize {context wcanvas hcanvas} {
    upvar #0 plotter:vComp vComp

    set hpanedw [winfo height $context.panedw]
    if {$hcanvas > $hpanedw || $vComp($context)} {
	$context itemconfigure plotter:$context -width $wcanvas -height $hcanvas
	update idletasks
	$context configure -scrollregion \
	    [list 0 0 [winfo width $context.panedw] [winfo height $context.panedw]]
    } else {
	$context itemconfigure plotter:$context -width $wcanvas
    }
    plotter:manageVerticalCompress $context
}

proc plotter:panedSetSize {context} {
    set wcanvas [winfo width $context]
    set hcanvas [winfo height $context]

    set height [winfo height $context.panedw]
    if {$hcanvas >= $height} {
	set height $hcanvas
    }
    $context itemconfigure plotter:$context -height $height -width $wcanvas
    update idletasks
    $context configure -scrollregion [list 0 0 [winfo width $context.panedw] $height]
}

proc plotter:panedSetSizeWhenMapped {context} {
    upvar #0 plotter:vComp vComp \
	plotter:objects objects
    
    plotter:manageVerticalCompress $context
	
    set panesList [$context.panedw panes]
    set nbpanes [llength $panesList]

    if {$vComp($context)} {
	#	set paneSize [expr [winfo height $context.panedw] / $nbpanes]
	set paneSize [plotter:getItsMinHeight $context]
	set allPaneSize [plotter:getAllMinHeight $context]
    } else {
	set paneSize 250
	set allPaneSize [expr $paneSize * $nbpanes]
	$context yview moveto 0
    }
    $context itemconfigure plotter:$context -height $allPaneSize
    update idletasks
    
    foreach i $objects($context) {
	set pane [plotter:removeDots $i]
	set paneSize [plotter:getItsMinHeight $i]
	$context.panedw paneconfigure $pane -min $paneSize -max $paneSize
    }
    
    foreach i $objects($context) {
	set pane [plotter:removeDots $i]
	set paneSize [plotter:getItsMinHeight $i]
	$context.panedw setsize $pane $paneSize next
    }
    
    foreach i $objects($context) {
	set pane [plotter:removeDots $i]
	$context.panedw paneconfigure $pane -min 0 -max 10000
    }

    plotter:panedSetSize $context
    bind $context <Map> ""
}

proc plotter:displayPreProcess {context display} {
    upvar #0 plotter:compound compound
    upvar #0 plotter:properties properties
    

    set error "Error during the selection:"
    set nb 0
    foreach i $compound {
	if {[lsearch -exact $display $i] != -1} {
	    foreach j [lindex $properties($i) 4] {
		if {[plotter:lremove display $j]} {
		    set error "$error\n [lindex [lindex $properties($j) 0] 0] is already displayed in [lindex [lindex $properties($i) 0] 0]"
		    incr nb
		}
	    }
	}
    }
    if {$nb} {
	if {$nb > 1} {
	    set error "$error\n\n These objects won't be displayed"
	} else {
	    set error "$error\n\n This object won't be displayed"
	}
	
	tk_messageBox -default ok -icon error \
	    -message $error \
	    -parent . -title Error -type ok
    }
    return $display
}

proc plotter:getVisiblePlotter {context} {
    upvar #0 plotter:nbPageName2Context p2c

    set pageName [$context.nb raised]
    return $p2c($pageName)
}

proc plotter:menuUpdate {context} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:properties properties

    set thisContext [plotter:getVisiblePlotter $context]
    
    if {$thisContext == ""} {
	return
    }
    
    if {[lindex $hierarchy($thisContext) 0] == ""} {
	return
    }

    if {[lindex $properties([lindex $hierarchy($thisContext) 0]) 2] == "time"} {  
	plotter:modifyEntry $context mhistoPoll-1
	plotter:modifyEntry $context mxadjust-1
	plotter:modifyEntry $context mscrollLock-1
	plotter:modifyEntry $context mcolorChoice-1
	plotter:modifyEntry $context mglobalBreak-1
    } else {
	plotter:modifyEntry $context mhistoPoll-2
	plotter:modifyEntry $context mxadjust-2
	plotter:modifyEntry $context mscrollLock-2
	plotter:modifyEntry $context mcolorChoice-2
	plotter:modifyEntry $context mcompress-3
	plotter:modifyEntry $context mzoomIn-1
	plotter:modifyEntry $context mzoomOut-1
	plotter:modifyEntry $context mglobalBreak-2
    }
    plotter:processCurrentState $thisContext
}

proc plotter:slowScroll {context amount} {
    set cont [plotter:getVisiblePlotter $context]
    $cont yview scroll $amount units
}

proc plotter:fastScroll {context amount} {
    set cont [plotter:getVisiblePlotter $context]
    $cont yview scroll $amount pages
}


proc plotter:display {context display} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:objects objects
    global plotter:xAxisManage 
    upvar #0 plotter:functionnalitiesListCurve fListC
    upvar #0 plotter:functionnalitiesListHisto fListH
    upvar #0 plotter:functionnalitiesLocalTimeGraph fLocalTG
    upvar #0 plotter:functionnalitiesLocalTimeState fLocalTS
    upvar #0 plotter:functionnalitiesLocalHisto fLocalH
    upvar #0 plotter:functionnalitiesDescription fDes
    upvar #0 plotter:functionnalitiesLocalCMPD fLocalCMPD
    global plotter:isMapped
    upvar #0 plotter:tMax tMax  
    global plotter:mode
    global plotter:histoDisplay
    global plotter:histoView
    upvar #0 plotter:colorAuto colorAuto
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:mainMenu mainMenu
    upvar #0 plotter:nbPageName2Context p2c
    upvar #0 plotter:tCur tCur
    global plotter:vComp

    # plotter:display can be called from the main context and from one of the 
    # sub-context
    if {[plotter:pathDepth $context] == 2} {
	set context $invertedHierarchy($context)
    }
    
  
    set oldPlotters $plotters
    set plotters {}
    set waitForMap {}
    
    global plotter:started
    if {! [info exists plotter:started]} {
	# retrieve the previous session geometry
	set geometry [plotter:getGeometrySession $context]
	wm geometry $context =[lindex $geometry 0]x[lindex $geometry 1]
	set plotter:started 1
	TkRequest $context StartDisplay
    }
  

    set display [plotter:displayPreProcess $context $display]
    
    set oldObjectsList {}
    set newObjectsList {}
    set newPlottersList {}

    if {! [winfo exists $context.nb]} { 
	frame $context.menubar -relief raised -borderwidth 2
	tixNoteBook $context.nb
	pack $context.menubar -fill x
	pack $context.nb -expand yes -fill both -side top
	set k 0
	foreach m $mainMenu {
	    set title [lindex $m 0]
	    set entries [lindex $m 1]
	    set cmd [lindex $m 2]
	    menubutton $context.menubar.$k -text $title \
		-menu $context.menubar.$k.m -underline 0 \
		-takefocus 0
	    set menu [menu $context.menubar.$k.m -tearoff 0 -postcommand "$cmd $context"]
	    pack $context.menubar.$k -side left
	    foreach name $entries {
		set arg [plotter:argConfigForMenu $context $name]
		localsettings:addEntry $context $menu $name [lindex $arg 0] [lindex $arg 1] \
		    [lindex $arg 2] [lindex $arg 3] [lindex $arg 4] [lindex $arg 5] [lindex $arg 6]
	    }
	    incr k
	}
    } else {
	set id [array startsearch objects]
	while {[array anymore objects $id]} {
	    set el [array nextelement objects $id]
	    set oldObjectsList [concat $oldObjectsList $objects($el)]
	    set objects($el) {} 
	}
	array donesearch objects $id
    }
    
    set toResize {}
    set prevPane ""
    foreach i $display {
	# first deal with the "containers"
	if {[plotter:pathDepth $i] == 2} {
	    # this container is already displayed?
	    if {![plotter:lremove oldPlotters $i]} {
		set plotter:isMapped($i) 0

 		# vertical compression mode
		set plotter:vComp($i) 0

		$context.nb add [plotter:removeDots $i] -label [lindex [lindex $properties($i) 0] 0] \
		    -raisecmd "plotter:menuUpdate $context"
		set p2c([plotter:removeDots $i]) $i
		set master [$context.nb subwidget [plotter:removeDots $i]]
		scrollbar $master.vbar -command "$i yview" 
		canvas $i -yscrollcommand "$master.vbar set"

		bind $context <Up> "plotter:slowScroll $context -1"
		bind $context <Down> "plotter:slowScroll $context 1"
		bind $context <Prior> "plotter:fastScroll $context -1"
		bind $context <Next> "plotter:fastScroll $context 1"

		bind $i <Configure> "plotter:panedResize $i %w %h"
		tixPanedWindow $i.panedw -dynamicgeometry true 

		$i create window 0 0 -window $i.panedw -anchor nw -tags plotter:$i
		toolbar:addToolBar $i $master "-column 0 -row 0 -sticky news -columnspan 2" \
		    "-column 0 -row 4 -sticky news -columnspan 2"

		if {[lindex $properties([lindex $hierarchy($i) 0]) 2] == "time"} {  
		    canvas $master.xaxis -height 32 -relief sunken -borderwidth 1
		    canvas $master.xaxis.x -width 1 -height 32

		    canvas $master.xaxis.display

		    scrollbar $master.hbar -orient horizontal
		    hbar:add $i $master.hbar
		    bind $master.xaxis <Map> "plotter:initDrawXAxis $i %W"
		    
		    grid $master.hbar -column 0 -row 3 -sticky news
		    grid $master.xaxis -column 0 -row 2 -sticky news
		    
		    grid rowconfig $master 3 -weight 0 -minsize 0
		    grid rowconfig    $master 2 -weight 0 -minsize 0
		    
		    set rowspan ""
		    
		    foreach name $fListC {
			toolbar:addButton $i $name "[lindex $fDes($name-1) 0] $i"\
			    [lindex $fDes($name-1) 1] [lindex $fDes($name-1) 2]  \
			    [lindex $fDes($name-1) 3] [lindex $fDes($name-1) 4] 
			
		    }

		    plotter:setMax $i [lindex $properties($i) 3] $tMax($i)
		} else {
		    grid rowconfig $master 3 -weight 1 -minsize 0
		    grid rowconfig    $master 2 -weight 1 -minsize 0
		    set rowspan "-rowspan 3"
		    foreach name $fListH {
			toolbar:addButton $i $name "[lindex $fDes($name-1) 0] $i" \
			    [lindex $fDes($name-1) 1] [lindex $fDes($name-1) 2] \
			    [lindex $fDes($name-1) 3] [lindex $fDes($name-1) 4] 
		    }
		}	

		plotter:initStates $i
		
		eval grid $master.vbar -column 1 -row 1 -sticky news $rowspan
		eval grid $i -column 0 -row 1 -sticky news -in $master $rowspan

		grid rowconfig    $master 0 -weight 0 -minsize 0
		grid rowconfig    $master 4 -weight 0 -minsize 0
		grid rowconfig $master 1 -weight 1 -minsize 0
		
		grid columnconfig $master 0 -weight 1
		grid columnconfig $master 1 -weight 0 -minsize 0
		lappend newPlottersList $i
	    }
	    lappend plotters $i
	    set currentPaneList($i) [$i.panedw panes]
	}
	# then deal with the canvases
	if {[plotter:pathDepth $i] == 3} {
	    if {! [plotter:lremove oldObjectsList $i]} {
		set plotter:isMapped($i) 0
		
		if {$prevPane != ""} {
		    set pos [lsearch -exact $currentPaneList($invertedHierarchy($i)) $prevPane]
		    incr pos
		} else {
		    set pos 0
		}

		set p [$invertedHierarchy($i).panedw add [plotter:removeDots $i] \
			   -at $pos -expand 1] 
		
		canvas $p.canvas -height 250

		pack configure $p.canvas  -fill both -expand yes
		bind $p.canvas <Map> "plotter:initDrawPlot $i %W"

		button $p.canvas.title -relief flat
		set popup [localsettings:addPopUp $i $p.canvas]
		set plotter:mode($i) normal
		
		if {[lindex $properties($i) 2] == "histo" } {
		    TkRequest $i HistoPolling
		    foreach name $fLocalH {
			set arg [plotter:argConfigForMenu $i $name]
			localsettings:addEntry $i $popup $name [lindex $arg 0] [lindex $arg 1] \
			    [lindex $arg 2] [lindex $arg 3] [lindex $arg 4] [lindex $arg 5] [lindex $arg 6]
		    }

		    set plotter:histoDisplay($i) [lindex $properties($i) 3]
		    set plotter:histoView($i) [lindex $properties($i) 4]

		    set img [fetchImage histo]

		} else {
		    if { ![plotter:lempty [lindex $properties($i) 4]] } {
			set local $fLocalCMPD
			if {[lindex $properties($i) 1] == "state"} {
			    set img [fetchImage sdiagrams]
			} else {
			    set img [fetchImage tgraphes]
			}
		    } else {
			if {[lindex $properties($i) 1] == "float" } {
			    set local $fLocalTG
			    set img [fetchImage tgraph]
			} else {
			    set local $fLocalTS
			    set img [fetchImage sdiagram]
			}	
		    }	 
		    foreach name $local {
			set arg [plotter:argConfigForMenu $i $name]
			if {[string length $arg] != 0} {
			    localsettings:addEntry $i $popup $name [lindex $arg 0] [lindex $arg 1] \
				[lindex $arg 2] [lindex $arg 3] [lindex $arg 4] [lindex $arg 5] [lindex $arg 6]
			}
		    }
		}

		set title [makeCompoundImage [plotter:titleFormat $i] $img]
		$p.canvas.title configure -image $title
		lappend newObjectsList $i
		
		set currentPaneList($invertedHierarchy($i)) \
		    [$invertedHierarchy($i).panedw panes]
	    }
    
	    plotter:ladd toResize $invertedHierarchy($i)
	    lappend objects($invertedHierarchy($i)) $i

	    set prevPane [plotter:removeDots $i]
	}
    }

    upvar #0 selection:fastContext fastContext \
	selection:fastStarted fastStarted

    if {[info exists fastStarted]} {
	if {$fastStarted} {
	    if {[lsearch -exact $oldObjectsList $fastContext] != -1} {
		selection:fastStop $fastContext \
		    [plotter:getWidgetFromContext $fastContext localCanvas]
	    }
	}
    }
    
    
    # remove all the widgets that shouldn't be displayed anymore
    # you'd better do the clean up by yourself and not let tix handle the 
    # destruction of all the children widgets.
    plotter:cleanUp $context $oldObjectsList $oldPlotters

    upvar #0 plotter:compound compound
    foreach i $oldObjectsList {
	set plotter:isMapped($i) 0
	if {[lindex $properties($i) 2] != "histo"} {
	    TkRequest $i ProtoSetConceal
	    if {[lsearch -exact $compound $i] != -1} {
		plotter:lremove compound $i
	    }
	}
    }

    foreach i $newObjectsList {
	if {[lindex $properties($i) 2] != "histo"} {
	    TkRequest $i ProtoSetDisplay
	}
    }
    foreach i $plotters {
	foreach j $objects($i) {
	    TkRequest $j ForceSetDisplay
	}
    }

    foreach i $oldPlotters {
	set plotter:isMapped($i) 0
    }
	    
    foreach i $newPlottersList {
	if {[lindex $properties($i) 2] == "time"} {
	    plotter:setMax $i [TkRequest $i SetCurrentTime] $tMax($i)
	}
    }
    
    # make sure all the canvases are visible
    while {![plotter:lempty $toResize]} { 
	set c [FIFOget toResize]

	if {! [winfo ismapped $c]} {
	    bind $c <Map> "plotter:panedSetSizeWhenMapped $c"
	} else {
	    plotter:panedSetSizeWhenMapped $c
	}
    }	    
    
    if {[llength $oldPlotters] == 0} {
	wm deiconify $context
    }

    if {[plotter:lempty $display]} {
	global plotter:reloaded
	if {${plotter:reloaded} == "true"} {
	    # perhaps the user wants to discard the currently saved
	    # session -- we should ask him now because he will not
	    # be able to do it after we have popped the plotter down
	    # (unless using the auto-save mode, but this is a non-obvious
	    # trick)
	    set answer [tk_messageBox -parent $context \
			    -message "Do you want to discard the previously saved session information?" \
			    -type yesno -icon warning -title Warning]
	    if {$answer == "yes"} {
		plotter:saveSession $context
	    }
	}
	plotter:popdown $context
    }

    # useful only to see the windows before the points are added. 
    # Can be removed (it speeds up the treatment)
    #update
    global plotter:readyForPoints
    set plotter:readyForPoints 1

}

proc plotter:cleanUp {context objects plotters} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    
    foreach i $objects {
	destroy [$invertedHierarchy($i).panedw subwidget [plotter:removeDots $i]].canvas
	$invertedHierarchy($i).panedw delete [plotter:removeDots $i] 
    }
    foreach i $plotters { 
	set master [$context.nb subwidget [plotter:removeDots $i]] 
	destroy $i 
	destroy $master.vbar 
	destroy $master.hbar 
	toolbar:destroy $master 
	$context.nb delete [plotter:removeDots $i] 
    }
}

proc plotter:initDrawPlot {context canvas} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:color color

    panesdragndrop:init $context $canvas
    reticle:init $context $canvas
    selection:init $context $canvas
    breakpoint:init $context $canvas

    global mainContext 
    bind $canvas <ButtonPress-2> \
	"selection:end $context $canvas ; selection:fastStop $context $canvas ; breakpoint:end $context $canvas"
    bind $mainContext <Escape> \
	"selection:end $context $canvas ; selection:fastStop $context $canvas ; breakpoint:end $context $canvas"
    
    bind $canvas <Map> ""
    bind $canvas <Configure> "plotter:reDrawPlot $context %W"

    global plotter:isMapped
    set plotter:isMapped($context) 1
    
    plotter:drawPlot $context $canvas {}
    hbar:linkToCanvas $context $canvas

    set width [winfo width $canvas]
    set height [winfo height $canvas]
    $canvas create window [expr $width / 2] [expr $height - 5] -window $canvas.title \
	-anchor s -tags $context:title 

    breakpoint:initAll $context $canvas
}

proc plotter:reDrawPlot {context canvas} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    $canvas delete $context:all
    plotter:drawPlot $context $canvas {}
    breakpoint:updateAll $context $canvas
    selection:updateAll $context $canvas
    set width [winfo width $canvas]
    set height [winfo height $canvas]
    $canvas coords $context:dnd $width 0
    $canvas coords $context:title [expr $width / 2] [expr $height - 5]
}

proc plotter:reDrawPlotWithPts {context pointsList} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    
    if {[plotter:lempty $pointsList]} {
	return
    }

    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    $canvas delete $context:all
    plotter:drawPlot $context $canvas $pointsList
    set width [winfo width $canvas]
    $canvas coords $context:dnd $width 0
}

proc plotter:drawPlot {context canvas pointsList} {
    global plotter:isMapped
    
    if {![set plotter:isMapped($context)]} {
	return
    }

    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:bottomb bottomb
    upvar #0 plotter:properties properties
    upvar #0 plotter:color color
    upvar #0 plotter:xleft xleft
    upvar #0 plotter:xright xright
    upvar #0 plotter:roundedXMax roundedXMax
    upvar #0 plotter:axisColor axisColor
    
    set width [winfo width $canvas]
    set height [winfo height $canvas]

    set xmax [expr $width - ($rightb + $leftb)]
    set ymax [expr $height - ($bottomb + $topb)]

    # if pointsList is empty request the points
    if {[plotter:lempty $pointsList]} {
	set pointsList [TkRequest $context GetPointsToDisplay $xmax $ymax $leftb $topb]
    }

    set xleft($context) 0
    set xright($context) 0
    if {[llength $pointsList] > 0} {
	if {[lindex $properties($context) 2] == "histo"} {
	    set xleft($context) [FIFOget pointsList]
	    set xright($context) [FIFOget pointsList]
	    if {[llength $pointsList] > 1} {
		eval $canvas create polygon $pointsList \
		    -tags \[list $context:all $context:plot\] \
		    -fill $color($context) -outline $color($context)
	    }
	} else {
	    if {[plotter:lempty [lindex $properties($context) 4]]} {
		set pointsList [lindex $pointsList 0]
		foreach {x0 y0 x1 y1} $pointsList {
		    $canvas create line $x0 $y0 $x1 $y1 -tags [list $context:all $context:plot] \
			-fill $color($context) 
		}
	    } else {
		set cList [lindex $properties($context) 4]
		if {[llength $cList] != [llength $pointsList]} {
		    set pointsList [TkRequest $context GetPointsToDisplay $xmax $ymax $leftb $topb]
		}
		foreach plot $pointsList {
		    set cont [FIFOget cList]
		    if {[llength $plot] > 0} {
			foreach {x0 y0 x1 y1} $plot {
			    $canvas create line $x0 $y0 $x1 $y1 -tags [list $context:all $cont:plot] \
				-fill $color($cont) 
			}
		    }
		}
	    }
	}
    }

    # axis
    $canvas create line [expr $leftb + $xleft($context)] [expr $topb + $ymax] \
	[expr $leftb + $xleft($context)] \
	[expr $topb - 15] -arrow last -tags $context:all -width 3 -fill $axisColor
    $canvas create line [expr $xleft($context) + $leftb] [expr $topb + $ymax - 1] \
	[expr $roundedXMax($context) + $leftb - $xright($context)] \
	[expr $topb + $ymax - 1] -tags $context:all -width 3 -fill $axisColor

    $canvas create line [expr $roundedXMax($context) + $leftb - $xright($context)] \
	[expr $topb + $ymax - 1] [expr $width - 10 - $xright($context) ] \
	[expr $topb + $ymax - 1] -tags $context:all -width 3 -arrow last \
	-stipple gray50 -fill $axisColor

    set yAxisInfo [TkRequest $context GetYAxisInfo]
    foreach {name y} $yAxisInfo {
	$canvas create text [expr $leftb - 4 + $xleft($context)] $y -text $name\
	    -tags [list $context:all $context:yaxis]\
	    -font plotter:vAxis -anchor e \
	    -fill $axisColor
    }

    if {[lindex $properties($context) 2] == "histo"} {
	set xAxisInfo [TkRequest $context GetXAxisHisto]
	$canvas create text [expr $leftb + $xleft($context)] \
	    [expr $height - $bottomb + 7] \
	    -text [lindex $xAxisInfo 0] \
	    -tags $context:all -font plotter:axis -anchor nw \
	    -fill $axisColor
	$canvas create text [expr $width - $rightb - $xright($context)] \
	    [expr $height - $bottomb + 7] \
	    -text [lindex $xAxisInfo 1] \
	    -tags $context:all -font plotter:axis -anchor ne \
	    -fill $axisColor
    }

}

proc plotter:addToPlot {context pointsList args} {
    global plotter:isMapped
    if {![set plotter:isMapped($context)]} {
	return
    }

    if {[plotter:lempty $pointsList]} {
	return
    }

    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:color color

    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas

    if {[lindex $properties($context) 2] == "histo"} {
	eval $canvas create polygon $pointsList -tags \[list $context:all $context:plot\] \
	    -outline $color($context)
    } else {
	if {[plotter:lempty [lindex $properties($context) 4]]} {
	    foreach {x0 y0 x1 y1} $pointsList {
		$canvas create line $x0 $y0 $x1 $y1 -tags [list $context:all $context:plot] \
		    -fill $color($context) 
	    }
	} else {
	    set cont [lindex $args 0]
	    foreach {x0 y0 x1 y1} $pointsList {
		$canvas create line $x0 $y0 $x1 $y1 -tags [list $context:all $cont:plot] \
		    -fill $color($cont) 
	    }
	}

    }
}

proc plotter:initDrawXAxis {context canvas} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:tMaxDisplay tMaxDisplay  
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax \
	plotter:axisColor axisColor

    #make sure that canvases are mapped
    update idletasks 

    $canvas create window $leftb 3 -window $canvas.x -anchor nw -tags $context:axis \
	-width [expr [winfo width $canvas] - $leftb - $rightb] \
	-height [expr [winfo height $canvas] - 6]

    $canvas create window $leftb 3 -window $canvas.display -anchor nw -tags $context:displayAxis \
	-width [expr [winfo width $canvas] - $leftb - $rightb] \
	-height [expr [winfo height $canvas] - 6]

    update idletasks 

    bind $canvas <Map> ""
    bind $canvas <Configure> "plotter:reDrawXAxis $context %W 1"

    global plotter:isMapped
    set plotter:isMapped($context) 1

    $canvas.display create line 0 14 [expr [winfo width $canvas] - $leftb - $rightb] 14 \
	-tags [list $context:xaxis $context:xaxisLine]  -width 3 -fill $axisColor

    plotter:drawXAxis $context $canvas 0 \
	[expr 1 - (($tMax($context) - $tMin($context)) / $tMaxDisplay($context))]
}

proc plotter:reDrawXAxis {context canvas isResize} {

    upvar #0 plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:tMin tMin \
	plotter:tMaxDisplay tMaxDisplay \
	plotter:axisColor axisColor

    $canvas.display delete $context:xaxis

    $canvas itemconfigure $context:displayAxis -width [expr [winfo width $canvas] - $leftb - $rightb]
    raise $canvas.display $canvas.x

    $canvas.display create line 0 14 [expr [winfo width $canvas] - $leftb - $rightb] 14 \
	-tags [list $context:xaxis $context:xaxisLine]  -width 3 -fill $axisColor

    plotter:simpleReDrawXAxis $context $canvas $isResize
}

proc plotter:simpleReDrawXAxis {context canvas isResize} {
    upvar #0 plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:tMin tMin \
	plotter:tMaxDisplay tMaxDisplay 
    
    $canvas itemconfigure $context:axis -width [expr [winfo width $canvas] - $leftb - $rightb]
    
    plotter:drawXAxis $context $canvas $isResize [expr $tMin($context) / $tMaxDisplay($context)]
}

proc plotter:drawXAxis {context canvas isResize args} {
    global plotter:isMapped
    if {![set plotter:isMapped($context)]} {
	return
    }

    upvar #0 plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:objects objects \
	hbar:hBar hBar \
	plotter:xScrollMax xScrollMax \
	plotter:tMaxDisplay tMaxDisplay \
	plotter:tMin tMin \
	plotter:tMax tMax 


    set width [winfo width $canvas]
    set height [winfo height $canvas]

    set ratio [expr $tMaxDisplay($context) / ($tMax($context) - $tMin($context))]

    set xScrollMax [expr $ratio * [expr $width - $rightb -$leftb]]
    set scrollList [list 0 0 $xScrollMax $height] 
    
    $canvas.x configure -scrollregion $scrollList -xscrollcommand "$hBar($context) set"
    
    
    if {! [plotter:lempty $args]} {
	# Here, the behaviour of tk is quite weird: when the scroll region is changed, it computes
	# the new bounds for the xview but using the old width of the canvas (I think). When the canvas
	# is reduced and you want to shift the view to the right, problems arise.
	update idletasks
	$canvas.x xview moveto [lindex $args 0]
    }
    
    plotter:updateXAxis $context $canvas 
}

proc plotter:updateXAxis {context canvas} {
    upvar #0 plotter:xScrollMax xScrollMax \
	plotter:tCur tCur \
	plotter:tMin tMin \
	plotter:tMax tMax \
	plotter:tMaxDisplay tMaxDisplay \
	plotter:axisColor axisColor \
	plotter:properties properties
    
    set beg [expr $tMin($context) / $tMaxDisplay($context)]
    set end [expr $tMax($context) / $tMaxDisplay($context)]

    $canvas.display delete $context:xaxisMark
    
    set val [TkRequest $context GetXAxisInfo]

    $canvas.display create text 2 16 -text [lindex $val 0] \
	-tags [list $context:xaxis $context:xaxisMark] \
	-font plotter:axis -anchor nw -fill $axisColor
    $canvas.display create text [expr [winfo width $canvas.display] - 2] 16 -text [lindex $val 1] \
	-tags [list $context:xaxis $context:xaxisMark] \
	-font plotter:axis -anchor ne -fill $axisColor

    if {[expr abs($tMax($context) - $tMaxDisplay($context))] < [lindex $properties($context) 4] } {
	$canvas.display itemconfigure $context:xaxisLine -arrow last
    } else {
	$canvas.display itemconfigure $context:xaxisLine -arrow none
    }

    if {$tMax($context) >= $tCur && $tMin($context) <= $tCur} {
	set w [font measure plotter:axis $tCur] 
	set xb 0
	set xe [winfo width $canvas.display]
	set ratio [expr ($tCur - $tMin($context)) / ($tMax($context) - $tMin($context))]
	set x [expr $ratio * ($xe - $xb)]

	if {[expr $x - $xb - 2] > [expr $w / 2]} {
	    if {[expr $xe -$x - 2] > [expr $w / 2]} {
		set anc c
	    } else {
		set anc e
		set x [expr $xe - 2]
	    }
	} else {
	    set anc w
	    set x [expr $xb + 2]
	}
	
	eval set text [TkRequest $context getRoundedDate $tCur]
	$canvas.display create text $x 8 -text $text \
	    -tags [list $context:xaxis $context:xaxisMark] \
	    -font plotter:axis -anchor $anc -fill $axisColor
    }
}

proc hbar:config {context} {
    upvar #0 hbar:linked linked
    upvar #0 hbar:hBar hBar

    if {$linked($context)} {
	$hBar($context) configure -command "hbar:moveAll $context"
	bind $hBar($context) <ButtonRelease-1> ""
    } else {
	$hBar($context) configure -command "hbar:command $context"
	bind $hBar($context) <ButtonRelease-1> "plotter:refreshGraph $context"
    }
}


proc hbar:add {context hbarName} {
    upvar #0 hbar:hBar hBar
    upvar #0 hbar:prevtMin prevtMin
    upvar #0 hbar:canvasList canvasList
    upvar #0 hbar:linked linked

    set hBar($context) $hbarName
    set prevtMin($context) 0
    set canvasList($context) {}
    hbar:config $context
}

proc hbar:linkToCanvas {context canvas} {
    upvar #0 hbar:canvasList canvasList
    upvar #0 plotter:invertedHierarchy invertedHierarchy    
    
    set i $invertedHierarchy($context)
    if {[array names hBar $i] == "" } {
	return
    }

    lappend canvasList($i) $canvas
}

proc hbar:moveAll {context args} {
    eval hbar:command $context $args
    plotter:refreshGraph $context
}


proc hbar:command {context args} {
    upvar #0 hbar:hBar hBar

    set master [winfo parent $hBar($context)]

    eval plotter:$args $context 
     plotter:updateXAxis $context $master.xaxis
}

proc plotter:refreshGraph {context} {
    upvar #0 plotter:objects objects

    foreach i $objects($context) {
	set canvas [$context.panedw subwidget [plotter:removeDots $i]].canvas
	plotter:reDrawPlot $i $canvas
    }
}

proc plotter:modifyButton {context name} {
    upvar #0 plotter:functionnalitiesDescription fDes

    regexp (.+)-.+ $name dummy simpleName
    toolbar:modifyButton $context $simpleName "[lindex $fDes($name) 0] $context" \
	[lindex $fDes($name) 1] [lindex $fDes($name) 2] [lindex $fDes($name) 3]
}

proc plotter:pushEntry {context args} {
    upvar #0 plotter:entryPushed entryPushed    
    foreach i $args {
	set entryPushed($context,$i) 1
    }
}

proc plotter:popEntry {context args} {
    upvar #0 plotter:entryPushed entryPushed    
    upvar #0 plotter:entryState state
    
    foreach i $args {
	set entryPushed($context,$i) 0
	plotter:modifyEntry $context $state($context,$i)
    }
}

proc plotter:modifyEntry {context name} {
    upvar #0 plotter:functionnalitiesDescription fDes
    upvar #0 plotter:entryLocked entryLocked
    upvar #0 plotter:entryState state
    upvar #0 plotter:entryPushed entryPushed    
    
    regexp (.+)-.+ $name dummy simpleName
    
    if {$entryLocked($context,$simpleName)} {
	set state($context,$simpleName) $name
	return
    }

    if {!$entryPushed($context,$simpleName)} {
	set state($context,$simpleName) $name
    }
    
    localsettings:modifyEntry $context $simpleName [lindex $fDes($name) 0] \
	[lindex $fDes($name) 1] [lindex $fDes($name) 2] [lindex $fDes($name) 3] \
	[lindex $fDes($name) 4] [lindex $fDes($name) 5]
}

proc plotter:lockEntry {context args} {
    upvar #0 plotter:entryLocked entryLocked
    
    foreach i $args {
	set entryLocked($context,$i) 1
    }
}

proc plotter:UnlockEntry {context args} {
    upvar #0 plotter:entryLocked entryLocked
    
    foreach i $args {
	set entryLocked($context,$i) 0
    }
}


proc plotter:compress {context} {
    upvar #0 hbar:hBar hBar
    upvar #0 hbar:hBar hBar
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy    
    upvar #0 plotter:plotterState state
    upvar #0 plotter:compressDone compressDone

    plotter:startIsBusy $invertedHierarchy($context)

    # toolbar management
    set state($context,compress) 1
    plotter:modifyButton $context compress-2 ;# can uncompress

    if {$tCur == 0} {
	TkRequest $context SetConf {1}
	plotter:stopIsBusy $invertedHierarchy($context)
	return
    }
    
    set master [winfo parent $hBar($context)]
    TkRequest $context Compress
    set compressDone 1
    plotter:setMax $context $tCur $tMax($context)
    
    plotter:drawXAxis $context $master.xaxis 0 
    plotter:refreshGraph $context
    plotter:stopIsBusy $invertedHierarchy($context)
}

proc plotter:uncompress {context} {
    upvar #0 hbar:hBar hBar
    upvar #0 hbar:hBar hBar
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tMaxDisplay tMaxDisplay
    upvar #0 plotter:invertedHierarchy invertedHierarchy    
    upvar #0 plotter:plotterState state
    upvar #0 plotter:compressDone compressDone

    # toolbar management
    set state($context,compress) 0
    plotter:modifyButton $context compress-1 ;# can compress

    if {$tCur == 0} {
	TkRequest $context SetConf {0}
	return
    }

    if {!$compressDone} {
	return
    }

    set master [winfo parent $hBar($context)]
    TkRequest $context UnCompress
    plotter:setMax $context $tCur $tMax($context)
    
    plotter:drawXAxis $context $master.xaxis 0 [expr $tMin($context) / $tMaxDisplay($context)]
    plotter:refreshGraph $context
}

proc plotter:zoomIn {context} {
    plotter:zoomCenter $context 0.5
}

proc plotter:zoomOut {context} {
    plotter:zoomCenter $context 2
}

# zoom in and out
proc plotter:zoomCenter {context zoom} { 
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tCur tCur


    set x1 [expr (1 - $zoom) / 2.0]
    set x2 [expr (1 + $zoom) / 2.0]
    
    if {$tMax($context) > $tCur} {
	set t $tCur
    } else {
	set t $tMax($context)
    }
    set newtMin [expr ($t * $x1) + ($tMin($context) * $x2)]
    set newtMax [expr ($tMin($context) * $x1) + ($t * $x2)]

    if {$newtMin < 0} {
	set newtMin 0
    }
    if {$newtMax > $tCur} {
	set newtMax $tCur
    }
    
    plotter:zoom $context $newtMin $newtMax
}

proc plotter:zoom {context newtMin newtMax} { 
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:tMaxDisplay tMaxDisplay
    upvar #0 hbar:hBar hBar
    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy    

    if {$newtMin > $newtMax} {
	set intertMax $newtMax
	set newtMax $newtMin
	set newtMin $intertMax
    }

    set master [winfo parent $hBar($context)]
    
    plotter:setBounds $context $newtMin $newtMax 1

    plotter:drawXAxis $context $master.xaxis 0 [expr $tMin($context) / $tMaxDisplay($context)]
    plotter:refreshGraph $context
}

proc plotter:zoomY {context canvas newyMin newyMax} {
    if {$newyMin > $newyMax} {
	set inter $newyMax
	set newyMax $newyMin
	set newyMin $inter
    }
    
    set realBounds [TkRequest $context SetYBounds $newyMin $newyMax]
    plotter:reDrawPlot $context $canvas
    return $realBounds
}

proc plotter:setMax {context max maxdisplay} {
    upvar #0 plotter:tCur tCur 
    upvar #0 plotter:tMaxDisplay tMaxDisplay 
    upvar #0 plotter:invertedHierarchy invertedHierarchy    

    set tCur $max
    if {[string first "." $tCur] == -1} {
	set tCur $tCur.0
    }

    set tMaxDisplay($context) $maxdisplay

    if {[string first "." $tMaxDisplay($context)] == -1} {
	set tMaxDisplay($context) $tMaxDisplay($context).0
    }
}    

proc plotter:setBounds {context _tMin _tMax isZoom} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:objects objects
    upvar #0 plotter:invertedHierarchy invertedHierarchy    

    # rounding is done by the C++ part of the code
    set times [TkRequest $context SetTimeBounds \
		   $_tMin $_tMax]
    
    if {$isZoom} {
	if {[expr floor($tMax($context) - $tMin($context))] >= [expr floor($tCur)]} {
	    set tMax($context) [lindex $times 0]
	}
	plotter:setMax $context $tCur [lindex $times 0]
    }

    # selection update
    foreach j $objects($context) {
	set p [$context.panedw subwidget [plotter:removeDots $j]]
	selection:updateAll $j $p.canvas
    }
}

# canvas scrolling commands are redefined here for an accurate control of the 
# scrolling
proc plotter:scroll {number what context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:tMaxDisplay tMaxDisplay
    upvar #0 hbar:hBar hBar

    if {$what == "units"} {
	set delta [lindex $properties($context) 4]
    } else {
	set delta [expr $tMax($context) - $tMin($context)]
    }
    
    set oldtMin $tMin($context)
    set oldtMax $tMax($context)
    set newtMin [expr $tMin($context) + ($number * $delta)] 
    set newtMax [expr $tMax($context) + ($number * $delta)]

    if {$newtMin < 0} {
	set newtMin 0
	set newtMax [expr $tMax($context) - $tMin($context)]
    }
    if {$newtMax > $tMaxDisplay($context)} {
	set newtMax $tMaxDisplay($context)
	set newtMin [expr $newtMax - [expr $tMax($context) - $tMin($context)]]
    }

    plotter:setBounds $context $newtMin $newtMax 0

    if {($tMin($context) == 0) && ($tMax($context) == $tCur)} {
	return
    }

    set master [winfo parent $hBar($context)]

    set left [expr $tMin($context) / $tMaxDisplay($context)]
    $master.xaxis.x xview moveto $left
    
}

proc plotter:moveto {fraction context}  {
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:tMaxDisplay tMaxDisplay
    upvar #0 hbar:hBar hBar
    
    set newtMin [expr $fraction * $tMaxDisplay($context)]
    set newtMax [expr $newtMin + [expr $tMax($context) - $tMin($context)]]

    if {$newtMin < 0} {
	set newtMin 0
	set newtMax [expr $tMax($context) - $tMin($context)]
    }
    if {$newtMax > $tMaxDisplay($context)} {
	set newtMax $tMaxDisplay($context)
	set newtMin [expr $newtMax - [expr $tMax($context) - $tMin($context)]]
    }

    plotter:setBounds $context $newtMin $newtMax 0

    if {($tMin($context) == 0) && ($tMax($context) == $tCur)} {
	return
    }

    set master [winfo parent $hBar($context)]
    set left [expr $tMin($context) / $tMaxDisplay($context)]
    $master.xaxis.x xview moveto $left
}


proc panesdragndrop:init {context canvas} {
    upvar #0 panesdragndrop:started started \
	plotter:properties properties

    set started 0
    
    set w [winfo width $canvas]

    button $canvas.dnd -relief flat -image [fetchImage drag]
    pack $canvas.dnd

    bind $canvas.dnd <ButtonPress-1> "panesdragndrop:start $context %X %Y"
    bind $canvas.dnd <ButtonRelease-1> "panesdragndrop:end %X %Y"
    bind $canvas.dnd <B1-Motion> "panesdragndrop:cursor %X %Y"
    
    if {[lindex $properties($context) 2] == "time"} {
	bind $canvas.title <ButtonPress-1> "panesdragndrop:start $context %X %Y"
	bind $canvas.title <ButtonRelease-1> "panesdragndrop:end %X %Y"
	bind $canvas.title <B1-Motion> "panesdragndrop:cursor %X %Y"
    }

    rearrangeBindings $canvas.title
    $canvas create window $w 0 -anchor ne -window $canvas.dnd -tags $context:dnd
}

proc panesdragndrop:initScroll {context x y} {
    upvar #0 panesdragndrop:started started
    upvar #0 panesdragndrop:timerId timerId
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    global mainContext

    if {!$started} {
	return
    }
    
    set mainCanvas $invertedHierarchy($context)
    set ytop [winfo rooty $mainCanvas]
    set ybottom [expr $ytop + [winfo height $mainCanvas]]

    if {$y >= $ybottom && $y <= [expr $ybottom + 20]} {
	bind $mainContext <B1-Motion> "panesdragndrop:stopScroll $context %X %Y"
	panesdragndrop:scroll $context 1
	return
    }
    if {$y <= $ytop && $y >= [expr $ytop - 20]} {
	bind $mainContext <B1-Motion> "panesdragndrop:stopScroll $context %X %Y"
	panesdragndrop:scroll $context -1
	return
    }
}

proc panesdragndrop:scroll {context unit} {
    upvar #0 panesdragndrop:started started
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 panesdragndrop:timerId timerId

    if {!$started} {
	return
    }

    set mainCanvas $invertedHierarchy($context)
    $mainCanvas yview scroll $unit units
    set timerId [after 100 "panesdragndrop:scroll $context $unit"]
}

proc panesdragndrop:stopScroll {context x y} {
    upvar #0 panesdragndrop:started started
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 panesdragndrop:timerId timerId
    global mainContext

    if {!$started} {
	return
    }
    
    set mainCanvas $invertedHierarchy($context)
    set ytop [winfo rooty $mainCanvas]
    set ybottom [expr $ytop + [winfo height $mainCanvas]]

    if {$y < $ybottom || $y > [expr $ybottom + 20]} {
	after cancel $timerId
	bind $mainContext <B1-Motion> "panesdragndrop:initScroll $context %X %Y"
	return
    }
    if {$y > $ytop || $y < [expr $ytop - 20]} {
	after cancel $timerId
	bind $mainContext <B1-Motion> "panesdragndrop:initScroll $context %X %Y"
	return
    }
}

proc panesdragndrop:start {context x y} {
    upvar #0 panesdragndrop:cutw cutw
    upvar #0 panesdragndrop:cuty cuty 
    upvar #0 panesdragndrop:started started
    upvar #0 panesdragndrop:cursor cursor
    upvar #0 panesdragndrop:mode mode
    
    global mainContext
    
    set cursor {}
    set started 1
    set w [winfo containing $x $y]

    if {[winfo name $w] == "dnd"} {
	set mode move
    } else {
	set mode cmpd
    }

    set cutw $w
    set cuty $y

    bind $mainContext <B1-Motion> "panesdragndrop:initScroll $context %X %Y"
}

proc panesdragndrop:end {x y} {
    upvar #0 panesdragndrop:cutw cutw
    upvar #0 panesdragndrop:cuty cuty
    upvar #0 panesdragndrop:started started
    upvar #0 panesdragndrop:cursor cursor
    upvar #0 panesdragndrop:oldCursor oldCursor
    upvar #0 panesdragndrop:mode mode
    global mainContext

    if {! $started} {
	return
    }
    
    set started 0

    foreach w $cursor {
	$w configure -cursor $oldCursor($w)
    }

    if {! [info exists cutw]} {
	return
    }
    
    if {$cutw == ""} {  
	return
    }

    set pastew [winfo containing $x $y]
    
    if {$pastew == ""} {
	return
    }

    if {[winfo name $pastew] != "dnd"} {
	if {[winfo name $pastew] != "title"} {
	    return
	}
    }
    
    if {$cutw == $pastew} {
	return
    }
    
    if {[winfo name $pastew] != [winfo name $cutw]} {
	return
    }

    set cutw_p [winfo parent [winfo parent $cutw]]
    set pastew_p [winfo parent [winfo parent $pastew]]
    set panedw [winfo parent $cutw_p]
    
    if {$mode == "move"} { 
	$panedw forget [winfo name $cutw_p]
	if {$cuty > $y} {
	    $panedw manage [winfo name $cutw_p] -before [winfo name $pastew_p]
	} else {
	    $panedw manage [winfo name $cutw_p] -after [winfo name $pastew_p]
	}
    } else {
	plotter:buildCompound [plotter:addDots [winfo name $cutw_p] [winfo parent $panedw]] \
	    [plotter:addDots [winfo name $pastew_p] [winfo parent $panedw]]
    }

    # restore cursor
    foreach w $cursor {
	if {[winfo exists $w]} {
	    $w configure -cursor $oldCursor($w)
	}
    }
    bind $mainContext <B1-Motion> ""
}

proc panesdragndrop:cursor {x y} {
    upvar #0 panesdragndrop:started started
    upvar #0 panesdragndrop:cursor cursor
    upvar #0 panesdragndrop:oldCursor oldCursor
    
    if {! $started} {
	return
    }

    set cursorw [winfo containing $x $y]

    if {$cursorw == ""} {
	return
    }
    
    set old [$cursorw cget -cursor]
    $cursorw configure -cursor target

    lappend cursor $cursorw
    if {[array names oldCursor $cursorw] == ""} {
	set oldCursor($cursorw) $old
    }
}

proc reticle:init {context canvas} {
    upvar #0 reticle:started started

    set started 0
    reticle:activate $context $canvas
}

proc reticle:activate {context canvas} {
    bind $canvas <ButtonPress-1> "reticle:start $context $canvas %X %Y"
    bind $canvas <ButtonRelease-1> "reticle:end $context $canvas %X %Y"
    bind $canvas <B1-Motion> "reticle:drag $context $canvas %X %Y"
}

proc reticle:deactivate {context canvas} {
    bind $canvas <ButtonPress-1> ""
    bind $canvas <ButtonRelease-1> ""
    bind $canvas <B1-Motion> ""
}


proc reticle:start {context canvas X Y} {
    upvar #0 reticle:started started
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:bottomb bottomb
    upvar #0 reticle:prevX prevX
    upvar #0 reticle:prevY prevY
    upvar #0 reticle:prevXtext prevXtext
    upvar #0 selection:started selStarted
    upvar #0 breakpoint:started brkStarted
    upvar #0 plotter:xleft xleft
    upvar #0 plotter:xright xright
    upvar #0 plotter:roundedXMax roundedXMax

    if {$selStarted} {
	selection:end $context $canvas
	return
    }

    if {$brkStarted} {
	breakpoint:end $context $canvas
	return
    }

    set x0 [winfo rootx $canvas]
    set y0 [winfo rooty $canvas]
    set x [expr $X - $x0]
    set y [expr $Y - $y0]

    set xmin [expr $leftb + $xleft($context)] 
    set xmax [expr $roundedXMax($context) + $leftb - $xright($context)]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
    if {! ($x > $xmin && $x < $xmax && $y > [expr $ymin -1] && $y < [expr $ymax - 1])} {
	return
    }
    
    set started 1
    
    set realBounds [TkRequest $context GetXYValuesString [expr $x - $xmin] \
			[expr $ymax - $y]]

    if {[llength $realBounds] == 0} {
	reticle:end $context $canvas $X $Y
	return
    }

    upvar #0 plotter:objects objects \
	plotter:invertedHierarchy invertedHierarchy \
	plotter:properties properties \
	plotter:reticleHistoColor histoColor \
	plotter:reticleTimeColor timeColor

	global tcl_platform
	    
    if {[lindex $properties($context) 2] == "time"} {

	if {$tcl_platform(platform) != "windows"} {
	    $canvas create line $xmin $y $xmax $y -stipple gray50 -tags [list reticle:all reticle:h] -fill $timeColor

	    foreach k $objects($invertedHierarchy($context)) {
		set kcanvas [plotter:getWidgetFromContext $k localCanvas]
		set kymin $topb
		set kymax [expr [winfo height $kcanvas] - $bottomb]

		$kcanvas create line $x [expr $kymin - 1] $x $kymax \
		    -stipple gray50 -tags [list reticle:all reticle:v] \
		    -fill $timeColor
	    }
	} else {
	    $canvas create line $xmin $y $xmax $y -fill $timeColor -tags [list reticle:all reticle:h] 

	    foreach k $objects($invertedHierarchy($context)) {
		set kcanvas [plotter:getWidgetFromContext $k localCanvas]
		set kymin $topb
		set kymax [expr [winfo height $kcanvas] - $bottomb]

		$kcanvas create line $x [expr $kymin - 1] $x $kymax \
		    -fill $timeColor -tags [list reticle:all reticle:v]
	    }
	}
    } else {
	if {$tcl_platform(platform) == "windows"} {
	    $canvas create line $xmin $y $xmax $y -fill $histoColor -tags [list reticle:all reticle:h] 
	    $canvas create line $x [expr $ymin - 1] $x $ymax \
		-fill $histoColor -tags [list reticle:all reticle:v]
	} else {
	    $canvas create line $xmin $y $xmax $y -stipple gray50 -tags [list reticle:all reticle:h] -fill $histoColor
	    $canvas create line $x [expr $ymin - 1] $x $ymax \
		-stipple gray50 -tags [list reticle:all reticle:v] \
		-fill $histoColor
	}
    }

    set prevX $x
    set prevY $y

    set realBoundsText "([lindex $realBounds 0] , [lindex $realBounds 1])"
    
    set textWidth [expr [font measure plotter:axis $realBoundsText] / 2]
    
    if {[expr $x - $textWidth] < 1} {
	set x $textWidth
    } 
    
    set max [expr [winfo width $canvas] - [winfo width $canvas.dnd]]
    if {[expr $x + $textWidth] > $max} {
	set x [expr $max - $textWidth]
    } 
    set prevXtext $x
    $canvas create text $x  [expr $topb - 17] -text $realBoundsText -anchor s \
	-font plotter:axis -tags [list reticle:all reticle:info]
}

proc reticle:drag {context canvas X Y} {
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:bottomb bottomb
    upvar #0 reticle:prevX prevX
    upvar #0 reticle:prevY prevY
    upvar #0 reticle:prevXtext prevXtext
    upvar #0 reticle:started started
    upvar #0 plotter:xleft xleft
    upvar #0 plotter:xright xright
    upvar #0 plotter:roundedXMax roundedXMax

    if {! $started} {
	return
    }

    set x0 [winfo rootx $canvas]
    set y0 [winfo rooty $canvas]
    set x [expr $X - $x0]
    set y [expr $Y - $y0]

    set xmin [expr $leftb + $xleft($context)]
    set xmax [expr $roundedXMax($context) + $leftb - $xright($context)]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
    if {$x < $xmin} {
	set x $xmin
    }
    if {$x > $xmax} {
	set x $xmax
    }
    if {$y < [expr $ymin - 1]} {
	set y [expr $ymin - 1]
    }
    if {$y > [expr $ymax - 1]} {
	set y [expr $ymax -1]
    }

    $canvas move reticle:h 0 [expr $y - $prevY]

    upvar #0 plotter:objects objects \
	plotter:invertedHierarchy invertedHierarchy 
    
    foreach k $objects($invertedHierarchy($context)) {
	set kcanvas [plotter:getWidgetFromContext $k localCanvas]
	$kcanvas move reticle:v [expr $x - $prevX] 0
    }

    set prevX $x
    set prevY $y

    set realBounds [TkRequest $context GetXYValuesString [expr $x - $xmin] \
			[expr $ymax - $y]]
    
    set realBoundsText "([lindex $realBounds 0] , [lindex $realBounds 1])"

    set textWidth [expr [font measure plotter:axis $realBoundsText] / 2]
    if {[expr $x - $textWidth] < 1} {
	set x $textWidth
    } 
    
    set max [expr [winfo width $canvas] - [winfo width $canvas.dnd]]
    if {[expr $x + $textWidth] > $max} {
	set x [expr $max - $textWidth]
    } 
    
    $canvas move reticle:info [expr $x - $prevXtext] 0
    set prevXtext $x

    $canvas itemconfigure reticle:info -text $realBoundsText

}

proc reticle:end {context canvas X Y} {
    upvar #0 reticle:started started
    
    set started 0

    upvar #0 plotter:objects objects \
	plotter:invertedHierarchy invertedHierarchy 
    
    foreach k $objects($invertedHierarchy($context)) {
	set kcanvas [plotter:getWidgetFromContext $k localCanvas]
	$kcanvas delete reticle:all
    }
}


proc selection:init {context canvas} {
    upvar #0 selection:started started
    upvar #0 selection:currentCanvas currentCanvas
    upvar #0 selection:isDragging isDragging \
	plotter:invertedHierarchy invertedHierarchy 
    
    set isDragging 0
    set started 0
    set currentCanvas ""
    selection:fastEnable $invertedHierarchy($context)

    backmenu $canvas.fastSelect -tearoff 0
    $canvas.fastSelect bind $canvas
    $canvas.fastSelect add command -label "X-Apply" \
	-command "selection:zoomX $context $canvas $canvas.select"
    $canvas.fastSelect add command -label "Y-Apply" \
	-command "selection:zoomY $context $canvas $canvas.select"
    $canvas.fastSelect validate "selection:selectionIsOn $context $canvas"
}

proc selection:selectionIsOn {context canvas x y} {
    upvar #0 selection:started started \
	selection:fastStarted fastStarted \
	selection:fastContext fastContext

    if {$started} {
       return "true"
    } else {
	if {$fastStarted} {
	    if {$fastContext == $context} {
		return "true"
	    }
	}
    }
    return "false"
}

proc selection:start {context canvas X Y} {
    upvar #0 plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:topb topb \
	plotter:bottomb bottomb \
	selection:startx startx \
	selection:starty starty \
	selection:firstCornerX firstCornerX \
	selection:firstCornerY firstCornerY \
	plotter:xleft xleft \
	plotter:xright xright

    set x0 [winfo rootx $canvas]
    set y0 [winfo rooty $canvas]
    set x [expr $X - $x0]
    set y [expr $Y - $y0]

    set xmin [expr $leftb + $xleft($context)]
    set xmax [expr [winfo width $canvas] - $rightb - $xright($context)]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
#     if {! ($x > $xmin && $x < $xmax && $y > [expr $ymin -1] && $y < [expr $ymax - 1])} {
# 	return
#     }

    if {$x < $xmin} {
	set x $xmin
    }
    if {$x > $xmax} {
	set x $xmax
    }
    if {$y < [expr $ymin -1]} {
	set y [expr $ymin -1]
    }
    if {$y > [expr $ymax - 1]} {
	set y [expr $ymax - 1]
    }

    set startx $x
    set starty $y

    set realBounds [TkRequest $context GetXYValues [expr $x - $xmin] \
			[expr $ymax - $y]]

    set firstCornerX [lindex $realBounds 0]
    set firstCornerY [lindex $realBounds 1]
}


proc selection:restart {context canvas X Y} {
    upvar #0 selection:started started \
	selection:currentCanvas currentCanvas \
	selection:isDragging isDragging \
	plotter:mode mode \
	selection:lastx lastx \
	selection:lasty lasty \
	selection:startx startx \
	selection:starty starty 


    if {$mode($context) != "sel"} {
	return
    }

    set isDragging 1
    if {$currentCanvas != ""} {
	if {$currentCanvas != $canvas} {
	    return
	}
    }

    if {! $started} {
	return
    }
    
    selection:start $context $canvas $X $Y
    set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
    eval $canvas coords selection:all $coordlist
    set isDragging 0
}

proc selection:commonDrag {context canvas X Y} {
    upvar #0 plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:topb topb \
	plotter:bottomb bottomb \
	selection:startx startx \
	selection:starty starty \
	selection:lastx lastx \
	selection:lasty lasty \
	selection:lastCornerX lastCornerX \
	selection:lastCornerY lastCornerY \
	plotter:invertedHierarchy invertedHierarchy \
	selection:lastCornerXUnit lastCornerXUnit \
	plotter:properties properties \
	plotter:xleft xleft \
	plotter:xright xright

    set x0 [winfo rootx $canvas]
    set y0 [winfo rooty $canvas]
    set x [expr $X - $x0]
    set y [expr $Y - $y0]

    set xmin [expr $leftb + $xleft($context)]
    set xmax [expr [winfo width $canvas] - $rightb - $xright($context)]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
    if {$x < $xmin} {
	set x $xmin
    }
    if {$x > $xmax} {
	set x $xmax
    }
    if {$y < [expr $ymin - 1]} {
	set y [expr $ymin - 1]
    }
    if {$y > [expr $ymax - 1]} {
	set y [expr $ymax -1]
    }
    
    set realBounds [TkRequest $context GetXYValues [expr $x - $xmin] \
			[expr $ymax - $y]]
    
    set lastCornerX [lindex $realBounds 0]
    set lastCornerY [lindex $realBounds 1]
    set lastCornerXUnit [lindex $properties($invertedHierarchy($context)) 6] 

    set lastx $x
    set lasty $y
    
    set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
    return $coordlist
}

proc selection:drag {context canvas X Y} {
    upvar #0 selection:started started \
	selection:currentCanvas currentCanvas \
	selection:isDragging isDragging \
	plotter:mode mode 

    if {$mode($context) != "sel"} {
	return
    }

    set isDragging 1

    if {! $started} {
	return
    }

    if {$currentCanvas != ""} {
	if {$currentCanvas != $canvas} {
	    return
	}
    }

    set coordlist [selection:commonDrag $context $canvas $X $Y]
    eval $canvas coords selection:all $coordlist

    set isDragging 0
}

proc selection:end {context canvas} {
    upvar #0 selection:started started
    upvar #0 selection:currentCanvas currentCanvas
    upvar #0 plotter:mode mode \
	plotter:invertedHierarchy invertedHierarchy 
    global mainContext
    
    if {$started} {
	if {$currentCanvas == $canvas} {
	    
	    set started 0
	    set currentCanvas ""
	    $canvas delete selection:all
	    destroy $canvas.select
	    if {$mode($context) == "sel"} {
		set mode($context) normal
	    }
	    reticle:activate $context $canvas
	    selection:fastEnable $invertedHierarchy($context)
	}
    }
}

proc selection:displayInfo {context canvas name} {
    upvar #0 selection:firstCornerX firstCornerX
    upvar #0 selection:firstCornerY firstCornerY
    upvar #0 selection:lastCornerX lastCornerX
    upvar #0 selection:lastCornerY lastCornerY
    upvar #0 plotter:properties properties
    upvar #0 selection:valOk valOk
    upvar #0 plotter:invertedHierarchy invertedHierarchy    
    upvar #0 selection:firstCornerXUnit firstCornerXUnit
    upvar #0 selection:lastCornerXUnit lastCornerXUnit

    set unitList [lindex $properties($invertedHierarchy($context)) 5] 

    if {[winfo exist $name.xview]} {
	return
    }

    tixLabelFrame $name.xview -label "X View" \
	-labelside acrosstop -options {
	    label.padX 5
	}
    
    set xview [$name.xview subwidget frame]
    
    tixLabelFrame $name.yview -label "Y View" \
	-labelside acrosstop -options {
	    label.padX 5
	}
    
    set yview [$name.yview subwidget frame]


    set valOk 0

    tixControl $xview.fromvaluex  -variable selection:firstCornerX \
	-incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	-validatecmd "plotter:validateTime $context $name selection:valOk"

    [$xview.fromvaluex subwidget entry] configure -width 8
    label $xview.fromlabel -text "From:" -anchor e

    if {! [plotter:lempty $unitList]} {
	tixOptionMenu $xview.fromunit -dynamicgeometry false -options {
	    menubutton.bd 0
	    menubutton.relief flat
	}
	tixOptionMenu $xview.tounit -dynamicgeometry false -options {
	    menubutton.bd 0
	    menubutton.relief flat
	}
	
	set k 0
	set width 0
	foreach val $unitList {
	    $xview.fromunit add command $k -label $val 
	    $xview.tounit add command $k -label $val 
	    incr k
	    set thisLabel [string length $val]
	    if {$thisLabel > $width} {
		set width $thisLabel
	    }
	}
	incr width
	$xview.fromunit configure -variable selection:firstCornerXUnit
	$xview.tounit configure -variable selection:lastCornerXUnit
	[$xview.fromunit subwidget menubutton] configure -width $width
	[$xview.tounit subwidget menubutton] configure -width $width
    } else {
	frame $xview.fromunit -width 0
	frame $xview.tounit -width 0
    }

    tixControl $xview.tovaluex -variable selection:lastCornerX \
	-incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	-validatecmd "plotter:validateTime $context $name selection:valOk"

    label $xview.tolabel -text "To:" -anchor e
    [$xview.tovaluex subwidget entry] configure -width 8

    tixControl $xview.timePpixel -variable selection:timePpixel \
	-incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	-validatecmd "selection:validateTPP $context $name selection:valOk" \
	-command "selection:UpdateXValuesWithTPP $context $canvas"

    [$xview.timePpixel subwidget entry] configure -width 8
    label $xview.timelabel -text "Time/Pixel:" -anchor e
    
    frame $xview.zoomx -relief flat -borderwidth 2
    button $xview.zoomx.app -text "Apply" \
	-command "selection:zoomX $context $canvas $name"

    # act differently depending on the type of the data on the y axis: floating point
    # numbers or states
    if {[lindex $properties($context) 1] == "float"} { 
	tixControl $yview.fromvaluey -variable selection:firstCornerY \
	    -command "selection:update $context $canvas selection:firstCorner" \
	    -incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	    -validatecmd "plotter:validateYAxis $context $name selection:valOk"
	[$yview.fromvaluey subwidget entry] configure -width 8
		
	tixControl $yview.tovaluey -variable selection:lastCornerY \
	    -command "selection:update $context $canvas selection:lastCorner" \
	    -incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	    -validatecmd "plotter:validateYAxis $context $name selection:valOk"
	[$yview.tovaluey subwidget entry] configure -width 8
    } else {
	tixOptionMenu $yview.fromvaluey -dynamicgeometry false
	tixOptionMenu $yview.tovaluey -dynamicgeometry false

	set width 0
	set entry 0
	foreach val [lindex $properties($context) 3] {
	    set thisLabel [string length $val]
	    if {$thisLabel > $width} {
		set width $thisLabel
	    }
	    $yview.fromvaluey add command $entry \
		-label $val
	    $yview.tovaluey add command $entry \
		-label $val
	    incr entry
	}
	incr width
	[$yview.fromvaluey subwidget menubutton] configure -width $width
	[$yview.tovaluey subwidget menubutton] configure -width $width

	$yview.fromvaluey configure -variable selection:firstCornerY \
	    -command "selection:update $context $canvas selection:firstCorner"
	$yview.tovaluey configure -variable selection:lastCornerY \
	    -command "selection:update $context $canvas selection:lastCorner"
    }
    label $yview.fromlabel -text "From:" -anchor e
    label $yview.tolabel -text "To:" -anchor e

    frame $yview.zoomy -relief flat -borderwidth 2
    button $yview.zoomy.app -text "Apply"  \
	-command "selection:zoomY $context $canvas $name"

    set box [tixButtonBox $name.box -relief flat -bd 0]

    $box add dismiss -text Close \
	-command "selection:end $context $canvas"
    $box add revert -text Revert \
	-command "selection:revert $context $canvas $name"

    grid $name.xview -column 0 -row 0 -sticky news 
    grid $name.yview -column 1 -row 0 -sticky news 
    grid $box -column 0 -row 1 -sticky news -columnspan 2 -pady 5
    grid rowconfigure $name 0 -weight 1
    grid rowconfigure $name 1 -weight 1
    grid columnconfigure $name 0 -weight 1
    grid columnconfigure $name 1 -weight 1 

    grid $xview.fromlabel -column 0 -row 0 -sticky news -padx 5
    grid $xview.fromvaluex -column 1 -row 0 -sticky ew 
    grid $xview.fromunit -column 2 -row 0 -sticky news -padx 5
    grid $xview.tovaluex -column 1 -row 1 -sticky ew 
    grid $xview.tolabel -column 0 -row 1 -sticky news -padx 5
    grid $xview.tounit -column 2 -row 1 -sticky news -padx 5
    grid $xview.timelabel -column 0 -row 2 -sticky news -padx 5
    grid $xview.timePpixel -column 1 -row 2 -sticky ew 
    grid $xview.zoomx -column 0 -row 3 -sticky news -columnspan 3 -ipady 5 -pady 5 -padx 5
    grid rowconfigure $xview 0 -weight 1 
    grid rowconfigure $xview 1 -weight 1 
    grid rowconfigure $xview 2 -weight 1 
    grid rowconfigure $xview 3 -weight 1 
    grid columnconfigure $xview 0 -weight 1 
    grid columnconfigure $xview 1 -weight 1 
    grid columnconfigure $xview 2 -weight 1 
    pack $xview.zoomx.app -expand 1
    
    grid $yview.fromlabel -column 0 -row 0 -sticky news -padx 5
    grid $yview.fromvaluey -column 1 -row 0 -sticky ew -padx 5
    grid $yview.tovaluey -column 1 -row 1 -sticky ew -padx 5
    grid $yview.tolabel -column 0 -row 1 -sticky news -padx 5
    grid $yview.zoomy -column 0 -row 3 -sticky news -columnspan 3 -ipady 5 -pady 5 -padx 5
    grid rowconfigure $yview 0 -weight 1 
    grid rowconfigure $yview 1 -weight 1 
    grid columnconfigure $yview 0 -weight 1 
    pack $yview.zoomy.app -expand 1
    
    wm protocol $name WM_DELETE_WINDOW \
	"selection:end $context $canvas"
}    

proc plotter:buildToplevel {context canvas name cmd title} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy    
    global mainContext
    if {[winfo exists $name]} {
	wm deiconify $name
	raise $name
	return
    }

    set yMain [winfo rooty $mainContext]
    set ytop [winfo rooty $invertedHierarchy($context)]

    set xCanvas [winfo rootx $canvas]
    set yCanvas [winfo rooty $canvas]
    set h [expr $ytop - $yMain]

    toplevel $name -width 300 -height $h
    wm title $name $title
    eval $cmd
    wm resizable $name 0 0
    cascadeWindow $name
}

proc selection:update {context canvas var dummy} {
    upvar #0 selection:startx startx
    upvar #0 selection:starty starty
    upvar #0 selection:lastx lastx
    upvar #0 selection:lasty lasty
    upvar #0 [set var]X cornerX
    upvar #0 [set var]XUnit cornerXUnit
    upvar #0 [set var]Y cornerY
    upvar #0 selection:isDragging isDragging
    upvar #0 plotter:bottomb bottomb 
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:properties properties
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:invertedHierarchy invertedHierarchy    
    upvar #0 selection:valOk valOk
    
    
    if {$isDragging} {
	selection:updateTPP $context $canvas
	return
    }

    if {$valOk} {
	set valOk 0
	return
    }

    if {[lindex $properties($context) 1] == "float"} { 
	set newBounds [TkRequest $context FromXYValuesToPix $cornerX $cornerY 1 1 $cornerXUnit]

	set cornerXUnit [lindex $properties($invertedHierarchy($context)) 6] 
	set cornerX [lindex $newBounds 2]
	set cornerY [lindex $newBounds 3]
    } else {
	set nX $cornerX
	set nY $cornerY
	
	set newBounds [TkRequest $context FromXYValuesToPix $nX $nY 1 1 $cornerXUnit]
	set cornerXUnit [lindex $properties($invertedHierarchy($context)) 6] 
	set cornerX [lindex $newBounds 2]
	set cornerY [lindex $newBounds 3]
    }
    set h [winfo height $canvas]
    if {$var == "selection:firstCorner"} {
	set startx [expr [lindex $newBounds 0] + $leftb]
	set starty [expr $h - [lindex $newBounds 1] - $bottomb - 1]
	if {[info exists lasty]} {
	    set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
	} {
	    set coordlist "$startx $starty $startx $starty $startx $starty $startx $starty $startx $starty"
	}
	eval $canvas coords selection:all $coordlist
    } else {
	set lastx [expr [lindex $newBounds 0] + $leftb]
	set lasty [expr $h - [lindex $newBounds 1] - $bottomb - 1]
	set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
	eval $canvas coords selection:all $coordlist
    }

    selection:updateTPP $context $canvas
}


proc selection:updateAll {context canvas} {
    upvar #0 selection:startx startx \
	selection:starty starty \
	selection:lastx lastx \
	selection:lasty lasty \
	selection:firstCornerX firstCornerX \
	selection:firstCornerY firstCornerY \
	selection:lastCornerX lastCornerX \
	selection:lastCornerY lastCornerY \
	plotter:bottomb bottomb \
	plotter:leftb leftb \
	selection:currentCanvas currentCanvas \
	plotter:properties properties \
	selection:fastStarted fastStarted \
	selection:fastContext fastContext \
	selection:started started

    if {$fastStarted} {
	if {$fastContext != $context} {
	    return
	}
    } else {
	if {$started} {
	    if {$currentCanvas != $canvas} {
		return
	    }
	} else {
	    return
	}
    }

    if {[lindex $properties($context) 1] == "float"} { 
	set newBoundsFirst [TkRequest $context FromXYValuesToPix $firstCornerX $firstCornerY 1 1]
	set newBoundsLast [TkRequest $context FromXYValuesToPix $lastCornerX $lastCornerY 1 1]
	
	set firstCornerX [lindex $newBoundsFirst 2]
	set firstCornerY [lindex $newBoundsFirst 3]
	set lastCornerX [lindex $newBoundsLast 2]
	set lastCornerY [lindex $newBoundsLast 3]
	
    } else {
	
	set nX $firstCornerX
	set nY $firstCornerY
	set newBoundsFirst [TkRequest $context FromXYValuesToPix $nX $nY 1 1]

	set nX $lastCornerX
	set nY $lastCornerY
	set newBoundsLast [TkRequest $context FromXYValuesToPix $nX $nY 1 1]

	set firstCornerX [lindex $newBoundsFirst 2]
	set firstCornerY [lindex $newBoundsFirst 3]
	set lastCornerX [lindex $newBoundsLast 2]
	set lastCornerY [lindex $newBoundsLast 3]
    }


    set h [winfo height $canvas]
    
    set startx [expr [lindex $newBoundsFirst 0] + $leftb]
    set starty [expr $h - [lindex $newBoundsFirst 1] - $bottomb - 1]
    set lastx [expr [lindex $newBoundsLast 0] + $leftb]
    set lasty [expr $h - [lindex $newBoundsLast 1] - $bottomb - 1]
    set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
    eval $canvas coords selection:all $coordlist
}

proc selection:zoomX {context canvas name} {
    upvar #0 selection:firstCornerX firstCornerX \
	selection:lastCornerX lastCornerX \
	plotter:invertedHierarchy invertedHierarchy \
	plotter:tMin tMin \
	plotter:tMax tMax \
	selection:valOk valOk \
	selection:started started
    
    if {$started} {
	set valOk 0
	
	set xview [$name.xview subwidget frame]    
	
	$xview.fromvaluex update
	selection:update $context $canvas selection:firstCorner dummy
	$xview.tovaluex update 
	selection:update $context $canvas selection:lastCorner dummy
	
	if {$valOk} {
	    return
	}
    }

    plotter:zoom $invertedHierarchy($context) $firstCornerX $lastCornerX

    # let the possibility to the C++ part to do some rounding
    set firstCornerX $tMin($invertedHierarchy($context))
    set lastCornerX $tMax($invertedHierarchy($context))

    selection:updateAll $context $canvas
}

proc selection:zoomY {context canvas name} {
    upvar #0 selection:firstCornerY firstCornerY \
	selection:lastCornerY lastCornerY \
	plotter:properties properties \
	selection:valOk valOk \
	selection:started started
    
    if {[lindex $properties($context) 1] == "float"} { 
	if {$started} {
	    set valOk 0
	    
	    set yview [$name.yview subwidget frame]
	    
	    $yview.fromvaluey update
	$yview.tovaluey update
	    
	    if {$valOk} {
		return
	    }
	}
	set realBounds [plotter:zoomY $context $canvas $firstCornerY $lastCornerY]
	
	# let the possibility to the C++ part to do some rounding
	set firstCornerY [lindex $realBounds 0]
	set lastCornerY [lindex $realBounds 1]
    } else {
	set first $firstCornerY
	set last $lastCornerY
	plotter:zoomY $context $canvas $first $last
    }

    selection:updateAll $context $canvas
    
}

proc selection:beforeDrag {context} {

    upvar #0 selection:firstCornerX firstCornerX \
	selection:firstCornerY firstCornerY \
	selection:lastCornerX lastCornerX \
	selection:lastCornerY lastCornerY \
	plotter:invertedHierarchy invertedHierarchy \
	selection:currentCanvas currentCanvas \
	plotter:mode mode \
	plotter:properties properties \
	selection:startx startx \
	selection:starty starty \
	selection:lastx lastx \
	selection:lasty lasty \
	plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:bottomb bottomb \
	plotter:topb topb \
	selection:firstCornerXUnit firstCornerXUnit \
	selection:lastCornerXUnit lastCornerXUnit \
	selection:valOk valOk \
	selection:started started \
	plotter:tMin tMin \
	plotter:tMax tMax \
	selection:fastStarted fastStarted \
	selection:fastContext fastContext

    global breakpoint:started
    global breakpoint:currentCanvas
    if {[set breakpoint:started]} {
	set canvas [set breakpoint:currentCanvas]
	set parent [winfo parent $canvas]
	set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	breakpoint:end $c $canvas
    }

    set valOk 0

    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas

    if {$started} {
	if {$currentCanvas == $canvas} {
	    wm deiconify $canvas.select
	    raise $canvas.select
	    return 
	} else {
	    set parent [winfo parent $currentCanvas]
	    set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	    selection:end $c $currentCanvas
	}
    }

    reticle:deactivate $context $canvas
    bind $canvas <ButtonPress-1> "selection:restart $context $canvas %X %Y"
    bind $canvas <B1-Motion> "selection:drag $context $canvas %X %Y"
    bind $canvas <Control-ButtonPress-1> break

    
    set currentCanvas $canvas
    
    global selection:xMin selection:xMax selection:yMin selection:yMax
    set selection:xMin $tMin($invertedHierarchy($context))
    set selection:xMax $tMax($invertedHierarchy($context))
    set yBounds [TkRequest $context getYBounds]
    
    set selection:yMin [lindex $yBounds 0]
    set selection:yMax [lindex $yBounds 1]

    if {! $fastStarted} {
	set firstCornerY [lindex $yBounds 0]
	set lastCornerY [lindex $yBounds 1]
	set firstCornerX $tMin($invertedHierarchy($context))
	set lastCornerX $tMax($invertedHierarchy($context))
	set firstCornerXUnit [lindex $properties($invertedHierarchy($context)) 6] 
	set lastCornerXUnit $firstCornerXUnit

	if {[lindex $properties($context) 1] == "float"} { 
	    set newBoundsFirst [TkRequest $context FromXYValuesToPix $firstCornerX $firstCornerY 1 1]
	    set newBoundsLast [TkRequest $context FromXYValuesToPix $lastCornerX $lastCornerY 1 1]
	    
	    set firstCornerX [lindex $newBoundsFirst 2]
	    set firstCornerY [lindex $newBoundsFirst 3]
	    set lastCornerX [lindex $newBoundsLast 2]
	    set lastCornerY [lindex $newBoundsLast 3]
	    
	} else {
	    
	    set nX $firstCornerX
	    set nY $firstCornerY
	    set newBoundsFirst [TkRequest $context FromXYValuesToPix $nX $nY 1 1]

	    set nX $lastCornerX
	    set nY $lastCornerY
	    set newBoundsLast [TkRequest $context FromXYValuesToPix $nX $nY 1 1]

	    set firstCornerX [lindex $newBoundsFirst 2]
	    set firstCornerY [lindex $newBoundsFirst 3]
	    set lastCornerX [lindex $newBoundsLast 2]
	    set lastCornerY [lindex $newBoundsLast 3]
	}
	set h [winfo height $canvas]
	
	set startx [expr [lindex $newBoundsFirst 0] + $leftb]
	set starty [expr $h - [lindex $newBoundsFirst 1] - $bottomb - 1]
	set lastx [expr [lindex $newBoundsLast 0] + $leftb]
	set lasty [expr $h - [lindex $newBoundsLast 1] - $bottomb - 1]

	set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
	# use line and not rectangle for the -stipple option 
	global tcl_platform
	if {$tcl_platform(platform) != "windows"} {
	    eval $canvas create line $coordlist -stipple gray50 -tags selection:all
	} else {
	    eval $canvas create line $coordlist -fill red -tags selection:all
	}
    }

    plotter:buildToplevel $context $canvas $canvas.select \
	"selection:displayInfo $context $canvas $canvas.select" [lindex [lindex $properties($context) 0] 0]
    
    set currentCanvas $canvas
    set started 1
    
    if {$fastStarted} {
	if {$fastContext != $context} {
	    selection:fastStop $fastContext \
		[plotter:getWidgetFromContext $fastContext localCanvas]
	}
    }


    selection:fastDisable $invertedHierarchy($context)

    selection:updateTPP $context $canvas
}

proc selection:updateTPP {context canvas} {
    upvar #0 selection:timePpixel tpp
    upvar #0 selection:firstCornerX fX
    upvar #0 selection:lastCornerX lX
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    set w [winfo width $canvas]

    set name $canvas.select
    set xview [$name.xview subwidget frame]

    $xview.timePpixel configure -disablecallback 1

    set tpp [plotter:round [expr abs($lX - $fX) / ($w.0 - $leftb - $rightb)]]

    $xview.timePpixel configure -disablecallback 0
    return $tpp
}

proc selection:UpdateXValuesWithTPP {context canvas dummy} {
    upvar #0 selection:timePpixel tpp
    upvar #0 selection:firstCornerX fX
    upvar #0 selection:lastCornerX lX
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:tCur tCur

    set w [winfo width $canvas]
    set xwidth [expr ($w - $rightb - $leftb)  * $tpp]
    
    set off [expr $xwidth / 2.0]
    set center [expr abs($lX + $fX) / 2.0]
    set newMax [expr $center + $off]
    set newMin [expr $center - $off]
    
    if {$xwidth > $tCur} {
	set fX 0
	set tX $tCur
	return
    }
    if {$newMax > $tCur} {
	set fX [expr $tCur - $xwidth]
	set lX $tCur
	return
    }
    if {$newMin < 0} {
	set fX 0
	set lX $xwidth
	return
    }
    set lX $newMax
    set fX $newMin

    global selection:firstCornerXUnit \
	selection:lastCornerXUnit
    
    set selection:firstCornerXUnit 0
    set selection:lastCornerXUnit 0
}

proc selection:revert {context canvas name} {
    upvar #0 selection:xMin xMin \
	selection:xMax xMax \
	selection:yMin yMin \
	selection:yMax yMax
    global selection:firstCornerX  \
	selection:firstCornerY  \
	selection:lastCornerX  \
	selection:lastCornerY 
    
    set selection:firstCornerX $xMin
    set selection:lastCornerX $xMax
    set selection:firstCornerY $yMin
    set selection:lastCornerY $yMax
    
    selection:zoomX $context $canvas $name
    selection:zoomY $context $canvas $name
}

proc selection:fastEnable {context} {
    upvar #0 selection:fastStarted fastStarted \
	plotter:objects objects

    if {! [info exists fastStarted]} {
	set fastStarted 0
    }

    foreach i $objects($context) {
	set canvas [plotter:getWidgetFromContext $i localCanvas]
	bind $canvas <Shift-ButtonPress-1> "selection:fastRestart $i $canvas %X %Y"
	bind $canvas <Shift-B1-Motion> "selection:fastDrag $i $canvas %X %Y"
	bind $canvas <Shift-Control-ButtonPress-1> break
    }
}

proc selection:fastDisable {context} {
    upvar #0 selection:fastStarted fastStarted \
	plotter:objects objects \
	plotter:invertedHierarchy invertedHierarchy 

    set fastStarted 0

    foreach i $objects($context) {
	set canvas [plotter:getWidgetFromContext $i localCanvas]
	bind $canvas <Shift-ButtonPress-1> ""
	bind $canvas <Shift-B1-Motion> ""
	bind $canvas <Shift-Control-ButtonPress-1> ""
    }
}

proc selection:fastRestart {context canvas X Y} {
    upvar #0 selection:fastStarted fastStarted \
	selection:startx startx \
	selection:starty starty \
	selection:lastx lastx \
	selection:lasty lasty \
	selection:fastContext fastContext

    selection:start $context $canvas $X $Y
    if {$fastStarted} {
	if {$context == $fastContext} {
	    set coordlist "$startx $starty $startx $lasty $lastx $lasty $lastx $starty $startx $starty"
	    eval $canvas coords selection:all $coordlist
	} else {
	    selection:fastStop $fastContext \
		[plotter:getWidgetFromContext $fastContext localCanvas]
	}
    }
    set fastContext $context
}

proc selection:fastDrag {context canvas X Y} {
    upvar #0 selection:fastStarted fastStarted

    set coordlist [selection:commonDrag $context $canvas $X $Y]
    if {$fastStarted} {
	eval $canvas coords selection:all $coordlist
    } else {
	set fastStarted 1

	global tcl_platform
	if {$tcl_platform(platform) != "windows"} {
	    eval $canvas create line $coordlist -stipple gray50 -tags selection:all
	} else {
	    eval $canvas create line $coordlist -fill red -tags selection:all
	}
    }
}

proc selection:fastStop {context canvas} {
    upvar #0 selection:fastStarted fastStarted \
	selection:fastContext fastContext

    if {$fastStarted} {
	if {$fastContext == $context} {
	    $canvas delete selection:all
	    set fastStarted 0
	}
    }
}

proc plotter:incr {sign val} {
    set index [string first "." $val]
    if {$index != -1} {
	set prec [expr [string length $val] - $index - 1]
	set prec 1e-$prec 
    } else {
	set prec 1
    }
    return [expr $val + ($sign * $prec)]
}

# do nothing with as many arguments as you want
proc plotter:noop {args} {
}

proc localsettings:addPopUp {context canvas} {
    backmenu $canvas.local -tearoff 0
    $canvas.local bind $canvas.title
    return [$canvas.local subwidget menu]
}

proc localsettings:addEntry {context menu name command label icon state type config args} {
    eval set args $args
    
    localsettings:_addEntry $context $menu $name $command $label $icon $state $type $config $args
}

proc localsettings:_addEntry {context menu name command label icon state type config args} {
    upvar #0 localsettings:name2path name2path


    eval set args $args

    if {$type == "separator"} {
	eval $menu add $type
	return
    }

    eval $menu add $type -label \"$label\" -state $state \
	-command \"localsettings:runCmd $context $command\" $config
    set index [$menu index last]
    set name2path($name,$context) [list $menu $index]
    
    # a cascade?
    if {! [plotter:lempty $args]} {
	menu $menu.$name -tearoff 0
	$menu entryconfigure $index -menu $menu.$name 
	foreach sub $args {
 	    localsettings:_addEntry $context $menu.$name [lindex $sub 0] [lindex $sub 1] \
 		[lindex $sub 2] [lindex $sub 3] [lindex $sub 4] [lindex $sub 5] [lindex $sub 6] \
 		[lindex $sub 7] 
	}
    }
}

proc localsettings:modifyEntry {context name command label icon state type config} {
    upvar #0 localsettings:name2path name2path

    set menu [lindex $name2path($name,$context) 0]
    set index [lindex $name2path($name,$context) 1]

    eval $menu entryconfigure $index -label \"$label\" -state $state \
	-command \"localsettings:runCmd $context $command\" $config
}

proc localsettings:runCmd {context cmd args} {
    set context [plotter:menuHack $context]
    eval "$cmd $args $context"
}

proc plotter:argConfigForMenu {context name} {
    upvar #0 plotter:functionnalitiesDescription fDes
    upvar #0 plotter:entryState state    
    upvar #0 plotter:entryPushed entryPushed    
    upvar #0 plotter:entryLocked entryLocked

    if {[array names fDes $name-1] == ""} {
	return ""
    }

    set entryPushed($context,$name) 0
    set state($context,$name) $name-1
    set entryLocked($context,$name) 0
    
    if {[llength $fDes($name-1)] < 7} {
	return $fDes($name-1)
    }
    
    set arg [lreplace $fDes($name-1) end end]
    set toadd {}

    foreach sub [lindex $fDes($name-1) end] {
	lappend toadd [plotter:_argConfigForMenu $sub]
    }
    lappend arg $toadd
    return $arg
}

proc plotter:_argConfigForMenu {name} {
    upvar #0 plotter:functionnalitiesDescription fDes

    if {[llength $fDes($name-1)] < 7} {
	set toadd $name
	set arg [concat $toadd $fDes($name-1)]
    } else {
	set arg [lreplace $fDes($name-1) end end]
	set toadd {}
	foreach sub [lindex $fDes($name-1) end] {
	    lappend toadd [plotter:_argConfigForMenu $sub]
	}
	set arg [list $arg $toadd]
    }
    return $arg
}

proc breakpoint:highlight {break args} {
    upvar #0 breakpoint:atYprev atYprev
    upvar #0 breakpoint:atY atY
    
    if {$atY != $atYprev} {
    global tcl_platform
    if {$tcl_platform(platform) != "windows"} {
	$break.$atYprev configure -highlightbackground [$break cget -bg]
	$break.$atY configure -highlightbackground yellow
    } else {
	$break.$atYprev configure -bg [$break cget -bg]
	$break.$atY configure -bg yellow
    }
	set atYprev $atY
    }
}

proc breakpoint:displayInfo {context canvas name} {
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:atYprev atYprev
    upvar #0 plotter:properties properties
    upvar #0 breakpoint:bList bList
    upvar #0 breakpoint:toRemove toRemove
    upvar #0 breakpoint:valOk valOk
    upvar #0 breakpoint:breakAt breakAt
    upvar #0 breakpoint:combo combo
    
    tixLabelFrame $name.break -label "Breakpoints" \
	    -labelside acrosstop -options {
	label.padX 5
    }
    
    set break [$name.break subwidget frame]
    pack $name.break -expand yes -fill both -side top
    

    set bList [TkRequest $context GetBreakpointList]
    
    # act differently depending on the type of the data on the y axis: floating point
    # numbers or states
    if {[lindex $properties($context) 1] == "state"} {

	global tcl_platform
	if {$tcl_platform(platform) == "windows"} {
	    frame $break.padding -height 10
	    pack $break.padding -expand yes -fill x -side top
	}
	set chk 0
	foreach val [lindex $properties($context) 3] {
	    set breakAt($chk) 0
	    if {$atY == $chk} {
		set color yellow
		set atYprev $atY
	    } else {
		set color [$break cget -bg]
	    }
	    global tcl_platform
	    if {$tcl_platform(platform) != "windows"} {
		checkbutton $break.$chk -text " $val" -anchor w -onvalue 1 -offvalue 0 \
		    -variable breakpoint:breakAt($chk) \
		    -command "breakpoint:setOrUnset $context $canvas $chk" \
		    -highlightbackground $color -highlightthickness 2 
		pack $break.$chk -expand yes -fill both
	    } else {
		frame $break.$chk -bg $color

		checkbutton $break.$chk.b -text " $val" -anchor w -onvalue 1 -offvalue 0 \
			-variable breakpoint:breakAt($chk) -command "breakpoint:setOrUnset $context $canvas $chk"
		pack $break.$chk -expand yes -fill both -padx 5
		pack $break.$chk.b -expand yes -fill both -padx 1 -pady 1
	    }
	    incr chk
	}
	trace variable atY w "breakpoint:highlight $break"
	set box [tixButtonBox $name.bbox -relief flat -bd 0]
	$box add dismiss -text Close -command "breakpoint:end $context $canvas"
	pack $box -fill both -expand yes

	foreach i $bList {
	    if {$tcl_platform(platform) == "windows"} {
		$break.$i.b select
	    } else {
		$break.$i select
	    }
	    set breakAt($i) 1
	} 

    } else {
	tixComboBox $break.blist -editable 1 -variable breakpoint:atY -pady 5 -padx 5
	set combo $break.blist
	[$break.blist subwidget entry] configure -width 8
	[$break.blist subwidget listbox] configure -width 8
	foreach i $bList {
	    $break.blist appendhistory $i
	}
	set box [tixButtonBox $name.bbox -orientation vertical -relief flat -bd 0]
	$box add remove -text Remove \
	    -command "breakpoint:remove $context $canvas"
	$box add dismiss -text Close -command "breakpoint:end $context $canvas"
	pack $name.break $box -expand yes -fill both -side left
	pack $break.blist -expand yes -fill both
	bind [$combo subwidget entry] <Return> "breakpoint:add $context $canvas"
    }

    wm protocol $name WM_DELETE_WINDOW \
	"breakpoint:end $context $canvas"
}


proc breakpoint:beforeDrag {context} {
    global mainContext
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:properties properties
    upvar #0 breakpoint:started started
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:bottomb bottomb
    upvar #0 breakpoint:pixy pixy
    upvar #0 breakpoint:currentCanvas currentCanvas
    upvar #0 breakpoint:atY atY \
	plotter:globalBreakpointStarted globalStarted 
    


    global selection:started
    global selection:currentCanvas
    if {[set selection:started]} {
	set canvas [set selection:currentCanvas]
	set parent [winfo parent $canvas]
	set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	selection:end $c $canvas 
    }

    if {[info exists globalStarted]} {
	if {$globalStarted} {
	    plotter:globalBreakpointEnd $invertedHierarchy($context)
	}
    } else {
	plotter:globalBreakpointEnd $invertedHierarchy($context)
    }
    
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    
    if {$started} {
	if {$currentCanvas == $canvas} {
	    wm deiconify $canvas.break
	    raise $canvas.break
	    return 
	} else {
	    set parent [winfo parent $currentCanvas]
	    set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	    breakpoint:end $c $currentCanvas
	}
    }

    if {[lindex $properties($context) 1] == "float"} { 
	set atY 0
    } else {
	set atY 0
    }

    reticle:deactivate $context $canvas
    bind $canvas <ButtonPress-1> "breakpoint:start $context $canvas %X %Y"
    bind $canvas <B1-Motion> "breakpoint:drag $context $canvas %X %Y"
    bind $mainContext <Return> "set breakpoint:breakAt(\[set breakpoint:atY\]) 1;  breakpoint:add $context $canvas"


    set currentCanvas $canvas

    plotter:buildToplevel $context $canvas $canvas.break \
	"breakpoint:displayInfo $context $canvas $canvas.break" [lindex [lindex $properties($context) 0] 0]

    set xmin $leftb
    set xmax [expr [winfo width $canvas] - $rightb]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
    set started 1

    if {[lindex $properties($context) 1] == "float"} { 
	set newBounds [TkRequest $context FromXYValuesToPix 0 $atY 0 0]
	set atY [lindex $newBounds 3]
    } else {
	set nX 0
	set nY $atY
	set newBounds [TkRequest $context FromXYValuesToPix $nX $nY 0 0]
    }

    set h [winfo height $canvas]

    set pixy [expr $h - [lindex $newBounds 1] - $bottomb - 1]

    global tcl_platform
    if {$tcl_platform(platform) != "windows"} {
	$canvas create line $xmin $pixy $xmax $pixy -stipple gray50 \
		-tags [list breakpoint:all breakpoint:temp]
    } else {
	$canvas create line $xmin $pixy $xmax $pixy -fill red \
		-tags [list breakpoint:all breakpoint:temp]
	
    }
    
    upvar #0 selection:fastContext fastContext \
    	selection:fastStarted fastStarted

    if {$fastStarted} {
	selection:fastStop $fastContext \
	    [plotter:getWidgetFromContext $fastContext localCanvas]
	selection:fastDisable $invertedHierarchy($context)
    }
}

proc breakpoint:init {context canvas} {
    upvar #0 breakpoint:started started
    upvar #0 breakpoint:currentCanvas currentCanvas
    upvar #0 breakpoint:isDragging isDragging
    
    set isDragging 0
    set started 0
    set currentCanvas ""
    bind $canvas <Double-Button-1> "breakpoint:fastAdd $context $canvas %x %y"
}

proc breakpoint:start {context canvas X Y} {
    upvar #0 breakpoint:started started
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:bottomb bottomb
    upvar #0 breakpoint:pixy pixy
    upvar #0 breakpoint:currentCanvas currentCanvas
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:isDragging isDragging
    upvar #0 plotter:mode mode

    if {$mode($context) != "break"} {
	return
    }

    set isDragging 1
    if {$currentCanvas != ""} {
	if {$currentCanvas != $canvas} {
	    return
	}
    }

    set currentCanvas $canvas

    if {$started} {
	breakpoint:drag $context $canvas $X $Y
	return
    }
    
    set x0 [winfo rootx $canvas]
    set y0 [winfo rooty $canvas]
    set x [expr $X - $x0]
    set y [expr $Y - $y0]

    set xmin $leftb
    set xmax [expr [winfo width $canvas] - $rightb]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
    if {! ($x > $xmin && $x < $xmax && $y > [expr $ymin -1] && $y < [expr $ymax - 1])} {
	return
    }
    
    set started 1
    
    set pixy $y

    set realBounds [TkRequest $context GetXYValues [expr $x - $xmin] \
			[expr $ymax - $y]]

    set atY [lindex $realBounds 1]

    global tcl_platform
    if {$tcl_platform(platform) != "windows"} {
	$canvas create line $xmin $y $xmax $y -stipple gray50 \
		-tags [list breakpoint:all breakpoint:temp]
    } else {
	$canvas create line $xmin $y $xmax $y -fill red \
		-tags [list breakpoint:all breakpoint:temp]
    }
    set isDragging 0
}

proc breakpoint:drag {context canvas X Y} {
    upvar #0 breakpoint:started started
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:topb topb 
    upvar #0 plotter:bottomb bottomb
    upvar #0 breakpoint:pixy pixy
    upvar #0 breakpoint:currentCanvas currentCanvas
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:isDragging isDragging
    upvar #0 plotter:mode mode

    if {$mode($context) != "break"} {
	return
    }

    set isDragging 1

    if {! $started} {
	return
    }

    if {$currentCanvas != ""} {
	if {$currentCanvas != $canvas} {
	    return
	}
    }

    set x0 [winfo rootx $canvas]
    set y0 [winfo rooty $canvas]
    set x [expr $X - $x0]
    set y [expr $Y - $y0]

    set xmin $leftb
    set xmax [expr [winfo width $canvas] - $rightb]
    set ymin $topb
    set ymax [expr [winfo height $canvas] - $bottomb]
    
    if {$x < $xmin} {
	set x $xmin
    }
    if {$x > $xmax} {
	set x $xmax
    }
    if {$y < [expr $ymin - 1]} {
	set y [expr $ymin - 1]
    }
    if {$y > [expr $ymax - 1]} {
	set y [expr $ymax -1]
    }
    
    set realBounds [TkRequest $context GetXYValues [expr $x - $xmin] \
			[expr $ymax - $y]]
    
    set atY [lindex $realBounds 1]

    $canvas move breakpoint:temp 0 [expr $y - $pixy]
    $canvas itemconfigure breakpoint:temp
    
    set pixy $y
    
    set isDragging 0
}

proc breakpoint:end {context canvas args} {
    upvar #0 breakpoint:started started \
	breakpoint:currentCanvas currentCanvas \
	plotter:mode mode \
	breakpoint:atY atY \
	plotter:invertedHierarchy invertedHierarchy

    if {$started} {
	global mainContext
	
	set started 0
	set currentCanvas ""
	$canvas delete breakpoint:temp
	destroy $canvas.break

	if {$mode($context) == "break"} {
	    set mode($context) normal
	}

	reticle:activate $context $canvas 
	bind $mainContext <Return> ""
	foreach trace [trace vinfo atY] {
	    set ops [lindex $trace 0]
	    set cmd [lindex $trace 1]
	    trace vdelete atY $ops $cmd
	}
	selection:fastEnable $invertedHierarchy($context)
    }
}

proc breakpoint:updateAll {context canvas} {
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:bottomb bottomb
    upvar #0 plotter:properties properties
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:currentCanvas currentCanvas
    upvar #0 breakpoint:pixy pixy

    set xmin $leftb
    set w [winfo width $canvas]
    set h [winfo height $canvas]
    set xmax [expr $w - $rightb]

    set breakList [TkRequest $context GetBreakpointList]

    if {[lindex $properties($context) 1] == "float"} { 
	foreach i $breakList {
	    set bounds [TkRequest $context FromXYValuesToPix 0 $i 0 0]
	    set y [expr $h - [lindex $bounds 1] - $bottomb - 1]
	    $canvas coords breakpoint:$context:$i $xmin $y $xmax $y
	}
	if {$currentCanvas == $canvas} {
	    set newBounds [TkRequest $context FromXYValuesToPix 0 $atY 0 0]	
	    set atY [lindex $newBounds 3]
	    set pixy [expr $h - [lindex $newBounds 1] - $bottomb - 1]
	    $canvas coords breakpoint:temp $xmin $pixy $xmax $pixy
	}
    } else {
	set nX 0
	foreach i $breakList {
	    set bounds [TkRequest $context FromXYValuesToPix $nX $i 0 0]
	    set y [expr $h - [lindex $bounds 1] - $bottomb - 1]
	    set name $i
	    $canvas coords breakpoint:$context:$name $xmin $y $xmax $y
	}
	if {$currentCanvas == $canvas} {
	    set nY $atY
	    set newBounds [TkRequest $context FromXYValuesToPix $nX $nY 0 0]
	    set atY [lindex $newBounds 3]
	    set pixy [expr $h - [lindex $newBounds 1] - $bottomb - 1]
	    $canvas coords breakpoint:temp $xmin $pixy $xmax $pixy
	}
    }
}

proc breakpoint:initAll {context canvas} {
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:rightb rightb
    upvar #0 plotter:bottomb bottomb
    upvar #0 plotter:properties properties
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:currentCanvas currentCanvas
    
    set xmin $leftb
    set w [winfo width $canvas]
    set h [winfo height $canvas]
    set xmax [expr $w - $rightb]

    set breakList [TkRequest $context GetBreakpointList]

    if {[lindex $properties($context) 1] == "float"} { 
	foreach i $breakList {
	    set bounds [TkRequest $context FromXYValuesToPix 0 $i 0 0]
	    set y [expr $h - [lindex $bounds 1] - $bottomb - 1]
	    $canvas create line $xmin $y $xmax $y \
		-tags [list breakpoint:$context:all breakpoint:$context:$i] \
		-fill green 
	}
    } else {
	set nX 0
	foreach i $breakList {
	    set bounds [TkRequest $context FromXYValuesToPix $nX $i 0 0]
	    set y [expr $h - [lindex $bounds 1] - $bottomb - 1]
	    set name $i
	    $canvas create line $xmin $y $xmax $y \
		-tags [list breakpoint:$context:all breakpoint:$context:$name] \
		-fill green 
	    
	}
    }
}

proc breakpoint:update {context canvas args} {
    upvar #0 breakpoint:pixy pixy
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:isDragging isDragging
    upvar #0 plotter:bottomb bottomb 
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:properties properties
    upvar #0 plotter:leftb leftb
    upvar #0 plotter:topb topb 
    upvar #0 breakpoint:valOk valOk
    
    if {$isDragging} {
	return
    }
    
    if {[lindex $properties($context) 1] == "float"} { 
	set newBounds [TkRequest $context FromXYValuesToPix 0 $atY 0 0]
	set atY [lindex $newBounds 3]
    } else {
	set nX 0
	set nY $atY
	
	set newBounds [TkRequest $context FromXYValuesToPix $nX $nY 0 0]
	set atY [lindex $newBounds 3]
    }
    set h [winfo height $canvas]

    set oldpixy $pixy
    set pixy [expr $h - [lindex $newBounds 1] - $bottomb - 1]

    $canvas move breakpoint:temp 0 [expr $pixy - $oldpixy]    
}

proc breakpoint:setOrUnset {context canvas state} {
    upvar #0 breakpoint:atY atY    
    upvar #0 breakpoint:breakAt breakAt
    upvar #0 breakpoint:toRemove toRemove

    if {$breakAt($state)} {
	set atY $state
	breakpoint:update $context $canvas
	breakpoint:add $context $canvas 
    } else {
	set toRemove $state
	breakpoint:remove $context $canvas
    }
}

proc breakpoint:add {context canvas} {
    upvar #0 breakpoint:pixy pixy
    upvar #0 breakpoint:atY atY
    upvar #0 breakpoint:bList bList
    upvar #0 plotter:properties properties
    upvar #0 breakpoint:valOk valOk
    upvar #0 breakpoint:combo combo

    if {[lindex $properties($context) 1] == "float"} { 
	set valOk 0
	plotter:validateYAxis $context $canvas.break breakpoint:valOk \
	    [[$combo subwidget entry] get]
	if {$valOk} {
	    return
	}
	set atY [[$combo subwidget entry] get]
	set newlist [TkRequest $context SetBreakpoint $atY]
	set atY [lindex $newlist end]
	
    } else {
	set newlist [TkRequest $context SetBreakpoint $atY]
	set atY [lindex $newlist end]
    }
    
    if {[llength $bList] == [llength $newlist]} {
	return
    }
   
    if {[lindex $properties($context) 1] == "float"} { 
	$combo appendhistory $atY
    }

    breakpoint:update $context $canvas 0
    set bList $newlist 

    eval $canvas create line [$canvas coords breakpoint:temp] \
	-tags \[list breakpoint:$context:all breakpoint:$context:$atY\] \
	-fill green 
    $canvas lower breakpoint:$context:$atY
}

proc breakpoint:fastAdd {context canvas xpos ypos} {
    upvar #0 plotter:properties properties \
	plotter:leftb leftb \
	plotter:rightb rightb \
	plotter:bottomb bottomb \
	breakpoint:started started \
	plotter:disabledBreakpoint disa 


    if {$started} {
	upvar #0 breakpoint:atY atY \
	    breakpoint:bList bList \
	    breakpoint:breakAt breakAt
    }

    set ymax [expr [winfo height $canvas] - $bottomb]
    set xmin $leftb
    set xmax [expr [winfo width $canvas] - $rightb]

    set bList [TkRequest $context GetBreakpointList]
    
    set atY [lindex [TkRequest $context GetXYValues [expr $xpos - $xmin] \
			 [expr $ymax - $ypos]] 1]
    set newList [TkRequest $context SetBreakpoint $atY]

    set atY [lindex $newList end]
	
    
    if {[llength $bList] == [llength $newList]} {
	return
    }
    set bList $newList
    
    if {$started} {
	if {[lindex $properties($context) 1] == "state"} {
	    set breakAt($atY) 1
	} else {
	    set name $canvas.break
	    set break [$name.break subwidget frame]
	    $break.blist appendhistory $atY
	}
    }


    set newBounds [TkRequest $context FromXYValuesToPix 0 $atY 0 0]
    set y [expr $ymax - [lindex $newBounds 1]]
    
    set test 1
    if {! [plotter:lempty [array names disa $context]]} {
	set test [expr [lsearch -exact $disa($context) $atY] == -1]
    }

    if {$test} {
	$canvas create line $xmin $y $xmax $y \
	    -tags [list breakpoint:$context:all breakpoint:$context:$atY] \
	    -fill green 
    } else {
	$canvas itemconfigure breakpoint:$context:$atY -fill green
    }
    
    $canvas lower breakpoint:$context:$atY

    plotter:addToGlobalBreakpoint $context $atY
    if {! $test} {
	plotter:lremove disa($context) $atY
    }
}

proc breakpoint:remove {context canvas} {
    upvar #0 breakpoint:bList bList
    upvar #0 plotter:properties properties
    upvar #0 breakpoint:toRemove toRemove
    upvar #0 breakpoint:combo combo
    upvar #0 breakpoint:atY atY
    
    if {[lindex $properties($context) 1] == "float"} { 
	set valOk 0
	plotter:validateYAxis $context $canvas.break breakpoint:valOk \
	    [[$combo subwidget entry] get]
	if {$valOk} {
	    return
	}
	set toRemove [[$combo subwidget entry] get]
    }

    set y $toRemove 
    set newlist [TkRequest $context ClearBreakpoint $y]

    if {[llength $bList] == [llength $newlist]} {
	return
    }
    set bList $newlist

    $canvas delete breakpoint:$context:$toRemove

    if {[lindex $properties($context) 1] == "float"} { 
	set sw [$combo subwidget listbox] 
	if {[$sw get 0 end] == ""} {
	    return
	}
	set index [lsearch -exact [$sw get 0 end] $toRemove]
	$sw delete $index
	set atY 0
    } 
}

proc plotter:histoPoll {context} {
    upvar #0 plotter:objects objects
    
    foreach i $objects($context) {
	TkRequest $i HistoPolling 
    }
}


proc plotter:updateTime {context newtCur args} {

    global mainContext
    upvar #0 plotter:tMaxDisplay tMaxDisplay 
    upvar #0 plotter:tMax tMax

    set oldtMaxDisplay $tMaxDisplay($context)

    plotter:setMax $context $newtCur $tMax($context)

    set canvas [$mainContext.nb subwidget [plotter:removeDots $context]].xaxis

    foreach {cont points} [lindex $args 0] {
	
	plotter:reDrawPlotWithPts $cont $points
    }

    plotter:simpleReDrawXAxis $context $canvas 0
}

proc plotter:choiceMade {context} {
    plotter:popup $context
    global plotter:readyForPoints
    vwait plotter:readyForPoints
    
}

proc plotter:setPlotColor {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:properties properties
    upvar #0 plotter:color color
    
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    set c [tk_chooseColor -initialcolor $color($context) -parent $canvas \
	       -title "Select foreground color for [lindex [lindex $properties($context) 0] 0]"]
    
    if {$c == ""} {
	return
    }
    
    set color($context) $c
    if {[lindex $properties($context) 2] != "histo"} {
	$canvas itemconfigure $context:plot -fill $c
    } else {
	$canvas itemconfigure $context:plot -fill $c -outline $c
    }
}

proc plotter:validateTime {context w isOk time} {
    upvar #0 $isOk ok

    if {[plotter:isFloat $time]} {
	return $time
    }
    tk_messageBox -default ok -icon error -message "Bad time value: $time" \
	-parent $w -title Error -type ok
    incr ok
    return 0
}

proc selection:validateTPP {context w isOk time} {
    upvar #0 $isOk ok
    upvar #0 plotter:invertedHierarchy invertedHierarchy 

    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    
    if {[plotter:isFloat $time]} {
	return $time
    }
    tk_messageBox -default ok -icon error -message "Bad time value: $time" \
	-parent $w -title Error -type ok
    incr ok
    return [selection:updateTPP $context $canvas]
}

proc plotter:validateYAxis {context w isOk y} {
    upvar #0 $isOk ok

    if {[plotter:isFloat $y]} {
	return $y
    }
    tk_messageBox -default ok -icon error -message "Bad y-axis value: $y" \
	-parent $w -title Error -type ok
    incr ok
    return 0
}

proc plotter:validateXAxis {context w isOk y} {
    upvar #0 $isOk ok

    if {[plotter:isFloat $y]} {
	return $y
    }
    tk_messageBox -default ok -icon error -message "Bad x-axis value: $y" \
	-parent $w -title Error -type ok
    incr ok
    return 0
}

proc plotter:isFloat {val} {
    set matchvar ""
    regexp "(\\+|-)?\\ *\[0-9\]+\\.?\[0-9\]*(\[Ee\](\\+|-)?\[0-9\]+)?" $val matchvar
    return [expr ![string compare $val $matchvar]]
}

proc plotter:isInteger {val} {
    regexp "(\\+|-)?\\ *\[0-9\]+" $val matchvar
    return [expr ![string compare $val $matchvar]]
}

proc plotter:buildPolyGon {points} {
    set xb [lindex $points 0]
    set yb [lindex $points 1]
    set last [expr [llength $points] - 1]
    set ye [lindex $points $last]
    set xe [lindex $points [expr $last - 1]]
    
    if {$xb == $xe &&  $yb == $ye} {
	return $points
    }
    
    lappend points $xb $yb
    return $points
}

proc plotter:localHistoPoll {context} {
    TkRequest $context HistoPolling
}

proc plotter:setHistoDisplay {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:histoDisplay histoDisplay
    
    TkRequest $context SetHistoDisplay $histoDisplay($context)
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    plotter:reDrawPlot $context $canvas
} 

proc plotter:setHistoView {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:histoView histoView
    
    TkRequest $context SetHistoView $histoView($context)
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    plotter:reDrawPlot $context $canvas
} 


proc plotter:printAll {context} {
    upvar #0 plotter:objects objects
    
    foreach i $objects($context) {
	TkRequest $i SetPrintMe
    }

    plotter:print $context

    foreach i $objects($context) {
	TkRequest $i ResetPrintMe
    }
}

proc plotter:printThis {context} {

    TkRequest $context SetPrintMe

    upvar #0 plotter:invertedHierarchy invertedHierarchy 
    plotter:print $invertedHierarchy($context)

    TkRequest $context ResetPrintMe
}

proc plotter:print {context} {
    
    global mainContext

    plotter:choosePrintFile $context $mainContext

} 

proc plotter:doPrint {context printDes} {

    upvar #0 plotter:toolname toolname
    global mainContext
    
    if {$printDes == ""} {
	return
    }
    
    set file [lindex $printDes 0]
    set textMode [lindex $printDes 1]

    if {$textMode == "compress"} {
	set mode 0
    } else {
	set mode 1
    }

    if {$file == ""} {
	set file [TkRequest $mainContext GetTempFile]
	eval set file $file
	set error [TkRequest $context PrintIt $mode $file $toolname]
	eval set error $error
	if {$error == ""} {
	    TkRequest $mainContext PrintFile $file
	}
	file delete $file
    } else {
	set error [TkRequest $context PrintIt $mode $file $toolname]
	eval set error $error
    }
    if {$error != ""} {
	tk_messageBox -default ok -icon error \
	    -message $error \
	    -parent $mainContext -title Error -type ok

    }
}

proc plotter:setPrecision {p} {
    upvar #0 plotter:precision precision
     
    set precision $p
}

proc plotter:round {val} {
    upvar #0 plotter:precision precision
    
    set i [string first "." $val]
    if {$i == -1} {
	return $val
    }
    set last [expr $i + $precision]
    
    if {$last > [string length $val]} {
    set last [string length $val]
    } 

    return [string range $val 0 $last]
}

proc plotter:displayGlobalTimeMenu {context name} {
    upvar #0 plotter:isInConf isInConf
    global plotterconf:xadjust 

    set confList [TkRequest $context GetConf] 
    set plotterconf:xadjust [lindex $confList 0]

    checkbutton $name.xadjustb -text "" -offvalue 0 -onvalue 1 \
	-variable plotterconf:xadjust
    label $name.xadjustl -text "X-adjust: " -anchor e
    checkbutton $name.scrollb -text "" -offvalue 0 -onvalue 1 \
	-variable hbar:linked($context)
    label $name.scrolll -text "Scrolling locked: " -anchor e
    checkbutton $name.colorb -text "" -offvalue 0 -onvalue 1 \
	-variable plotter:colorAuto($context)
    label $name.colorl -text "Automatic color choice: " -anchor e
 
    set box [tixButtonBox $name.box -relief flat -bd 0]
   
    grid $name.xadjustl -row 0 -column 0 -sticky news -padx 5 -pady 5
    grid $name.xadjustb -row 0 -column 1 -sticky news -padx 5 -pady 5
    grid $name.scrolll -row 1 -column 0 -sticky news -padx 5 -pady 5
    grid $name.scrollb -row 1 -column 1 -sticky news -padx 5 -pady 5
    grid $name.colorl -row 2 -column 0 -sticky news -padx 5 -pady 5
    grid $name.colorb -row 2 -column 1 -sticky news -padx 5 -pady 5
    grid $box -row 3 -column 0 -columnspan 2 -sticky news -padx 5 -pady 5

    grid rowconfigure $name 0 -weight 0
    grid rowconfigure $name 1 -weight 0
    grid rowconfigure $name 2 -weight 0
    grid rowconfigure $name 3 -weight 0
    grid columnconfigure $name 0 -weight 1
    grid columnconfigure $name 1 -weight 1
 
    $box add ok -text OK -width 6 \
	-command "hbar:config $context; plotter:menuConfOk $context $name \[list \[set plotterconf:xadjust\]\]" 
    $box add cancel -text Cancel -command "plotter:menuConfCancel $name" -width 6

    wm protocol $name WM_DELETE_WINDOW \
	"plotter:menuConfCancel $name"

    
}

proc plotter:menuConfCancel {name} {
    upvar #0 plotter:isInConf isInConf
    global mainContext
    set isInConf 0
 
    destroy $name 
}

proc plotter:menuConfOk {context name confList args} {
    upvar #0 plotter:isInConf isInConf
    global mainContext
    set isInConf 0
    
    if {! [plotter:lempty $args]} {
	set cmd [lindex $args 0]
	if {[eval $cmd]} {
	    return
	}
    }
    destroy $name 
    
    eval TkRequest $context SetConf $confList
}

proc plotter:globalTimeMenu {context} {
    upvar #0 plotter:isInConf isInConf
    if {$isInConf} {
	return
    }
    set isInConf 1
    plotter:buildToplevel $context $context $context.global \
	"plotter:displayGlobalTimeMenu $context $context.global" "Global Settings"
}

proc plotter:localTimeCheck {name} {
    upvar #0 plotterconf:valOk valOk
    
    set valOk 0
    $name.smoothval update
    return $valOk
}

proc plotter:localTimeMenu {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:isInConf isInConf
    if {$isInConf} {
	return
    }
    set isInConf 1
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas    
    plotter:buildToplevel $context $canvas $canvas.localtl \
	"plotter:displayLocalTimeMenu $context $canvas.localtl \"plotter:localTimeCheck $canvas.localtl\"" \
	"Advanced Settings"
}

proc plotter:localHistoCheck {name} {
    upvar #0 plotterconf:valOk valOk
    
    set valOk 0
    $name.xmax update
    $name.xmin update
    return $valOk
}

proc plotter:localHistoMenu {context} {
    upvar #0 plotter:isInConf isInConf
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    if {$isInConf} {
	return
    }
    set isInConf 1
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas    
    plotter:buildToplevel $context $canvas $canvas.localtl \
	"plotter:displayLocalHistoMenu $context $canvas.localtl \"plotter:localHistoCheck $canvas.localtl\"" \
	"Advanced Settings"
}

proc plotter:displayLocalTimeMenu {context name cmd} {
    upvar #0 plotterconf:valOk valOk
    global plotterconf:yadjust 
    global plotterconf:smooth
    global plotterconf:smoothunit
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:properties properties

    set valOk 0
    
    set confList [TkRequest $context GetConf] 
    set plotterconf:yadjust [lindex $confList 0]
    set plotterconf:smooth [lindex $confList 1]
    set plotterconf:smoothunit [lindex $properties($invertedHierarchy($context)) 6] 
    
    checkbutton $name.yadjustb -text "" -offvalue 0 -onvalue 1 \
	-variable plotterconf:yadjust -anchor w
    label $name.yadjustl -text Y-adjust: -anchor e

    label $name.smoothl -text Smoothing:
    tixControl $name.smoothval -variable plotterconf:smooth \
	-incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	-validatecmd "plotter:validateTime $context $name plotterconf:valOk" \
	-options {
	    entry.width 8
	}

    set unitList [lindex $properties($invertedHierarchy($context)) 5] 
    if {! [plotter:lempty $unitList]} {
	tixOptionMenu $name.smoothunit -dynamicgeometry false -options {
	    menubutton.bd 0
	    menubutton.relief flat
	}
	set k 0
	foreach val $unitList {
	    $name.smoothunit add command $k -label $val 
	    incr k
	}
	$name.smoothunit configure -variable plotterconf:smoothunit
    } else {
	frame $name.smoothunit -width 0
    }

    set box [tixButtonBox $name.box -relief flat -bd 0]

    grid $name.yadjustl -row 1 -column 0 -sticky news -padx 5 -pady 5 
    grid $name.yadjustb -row 1 -column 1 -sticky news -padx 5 -pady 5  -columnspan 2
    grid $name.smoothl -row 0 -column 0 -sticky news -padx 5 -pady 5
    grid $name.smoothval -row 0 -column 1 -sticky news -padx 5 -pady 5
    grid $name.smoothunit -row 0 -column 2 -sticky news -padx 5 -pady 5
    grid $box -row 2 -column 0 -columnspan 3 -sticky news -padx 5 -pady 5

    grid rowconfigure $name 0 -weight 0
    grid rowconfigure $name 1 -weight 0
    grid rowconfigure $name 2 -weight 0
    grid columnconfigure $name 0 -weight 1
    grid columnconfigure $name 1 -weight 1
    grid columnconfigure $name 2 -weight 0
 
    $box add ok -text OK -width 6 \
	-command "$name.smoothval update; plotter:menuConfOk $context $name \[list \[set plotterconf:yadjust\] \[set plotterconf:smooth\] \[set plotterconf:smoothunit\]\] \"$cmd\""  
    $box add cancel -text Cancel -command "plotter:menuConfCancel $name" -width 6

    wm protocol $name WM_DELETE_WINDOW \
	"plotter:menuConfCancel $name"
}

proc plotter:displayLocalHistoMenu {context name cmd} {
    upvar #0 plotterconf:valOk valOk
    global plotterconf:stretched 
    global plotterconf:xmin
    global plotterconf:xmax
    upvar #0 plotter:properties properties

    set valOk 0
    
    set confList [TkRequest $context GetConf] 

    set plotterconf:stretched [lindex $confList 0]
    set plotterconf:xmin [lindex $confList 1]
    set plotterconf:xmax [lindex $confList 2]

    checkbutton $name.stretched -text "" -offvalue 0 -onvalue 1 \
	-variable plotterconf:stretched -anchor w
    label $name.stretchedl -text "Stretched: " -anchor e

    label $name.xminl -text "X-min: " -anchor e
    tixControl $name.xmin -variable plotterconf:xmin \
	-incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	-validatecmd "plotter:validateXAxis $context $name plotterconf:valOk"
    [$name.xmin subwidget entry] configure -width 8

    label $name.xmaxl -text "X-max: " -anchor e
    tixControl $name.xmax -variable plotterconf:xmax \
	-incrcmd "plotter:incr 1" -decrcmd "plotter:incr -1" -integer false \
	-validatecmd "plotter:validateXAxis $context $name plotterconf:valOk"
    [$name.xmax subwidget entry] configure -width 8

    set box [tixButtonBox $name.box -relief flat -bd 0]

    grid $name.stretchedl -row 0 -column 0 -sticky news -padx 5 -pady 5 
    grid $name.stretched -row 0 -column 1 -sticky news -padx 5 -pady 5
    grid $name.xminl -row 1 -column 0 -sticky news -padx 5 -pady 5
    grid $name.xmin -row 1 -column 1 -sticky news -padx 5 -pady 5
    grid $name.xmaxl -row 2 -column 0 -sticky news -padx 5 -pady 5
    grid $name.xmax -row 2 -column 1 -sticky news -padx 5 -pady 5
    grid $box -row 3 -column 0 -columnspan 2 -sticky news -padx 5 -pady 5

    grid rowconfigure $name 0 -weight 0
    grid rowconfigure $name 1 -weight 0
    grid rowconfigure $name 2 -weight 0
    grid rowconfigure $name 3 -weight 0
    grid columnconfigure $name 0 -weight 1
    grid columnconfigure $name 1 -weight 1
 
    $box add ok -text OK -width 6 \
	-command "$name.xmin update; $name.xmax update; plotter:menuConfOk $context $name \[list \[set plotterconf:stretched\] \[set plotterconf:xmin\] \[set plotterconf:xmax\] \[expr (\[set plotterconf:xmax\] != [set plotterconf:xmax]) || (\[set plotterconf:xmin\] != [set plotterconf:xmin])\] \] \"$cmd\"" 
    $box add cancel -text Cancel -command "plotter:menuConfCancel $name" -width 6

    wm protocol $name WM_DELETE_WINDOW \
	"plotter:menuConfCancel $name"
}

proc plotter:sortContext {context} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:properties properties
    
        
    foreach i $hierarchy($context) {
	if {[winfo exists $i.panedw]} {
	    set hierarchy($i) [lsort -command "plotter:sortContextCmd $i" $hierarchy($i)]
	}
    }
}

proc plotter:sortContextCmd {context el1 el2} {
    set panes [$context.panedw panes]
    
    set pane1 [plotter:removeDots $el1]
    set pane2 [plotter:removeDots $el2]
    
    set i1 [lsearch -exact $panes $pane1]
    set i2 [lsearch -exact $panes $pane2]
    
    if {$i2 == -1} {
	return -1
    }
    if {$i1 == -1} {
	return 1
    }
    if {$i1 > $i2} {
	return 1
    } else {
	return -1
    }
}

proc plotter:buildCompound {fromContext toContext} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy 
    upvar #0 plotter:objects objects
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:properties properties
    upvar #0 plotter:compound compound
    upvar #0 plotter:color color    
    upvar #0 plotter:colorAuto colorAuto

    set mc $invertedHierarchy($fromContext)
    TkRequest $fromContext SetMergeFrom
    TkRequest $toContext SetMergeTo
    set ok [TkRequest $mc CheckMerge]
    if {! $ok} {
	tk_messageBox -default ok -icon error -message "Can't create this compound plot" \
	    -parent $mc -title Error -type ok
	return
    }

    if {$ok == 1} {
	global plotter:cmpdPlotNameIsDone
	plotter:getCompoundName $mc
	vwait plotter:cmpdPlotNameIsDone
	
	set cmpdPlotName [set plotter:cmpdPlotNameIsDone]

	if {$cmpdPlotName == ""} {
	    return
	}
	
	set rep [TkRequest $mc DoMerge]
	TkRequest $rep SetCompoundTitle $cmpdPlotName

	lappend compound $rep
    } else {
	set rep [TkRequest $mc DoMerge]
    }

    set properties($rep) [TkRequest $rep GetProperties]
    
    if {$colorAuto($invertedHierarchy($rep))} {
	set j 0
	foreach i [lindex $properties($rep) 4] {
	    set color($i) [plotter:colorShift $j]
	    incr j 1
	}
    }

    set todisplay {}
    foreach i $plotters {
	lappend todisplay $i
	foreach j $objects($i) {
	    if {$j != $fromContext} {
		if {$j == $toContext} {
		    lappend todisplay $rep
		} else {
		    lappend todisplay $j
		}
	    } 
	}      
    }

    plotter:updateFunctionForCmpd $rep
    global mainContext
    plotter:display $mainContext $todisplay
    if {$rep == $fromContext || $rep == $toContext} {
	set canvas [$invertedHierarchy($rep).panedw subwidget [plotter:removeDots $rep]].canvas
	plotter:reDrawPlot $rep $canvas
    }

    # make sure the just created compound plot is visible
    plotter:bringIntoFocus $mc $rep
} 

proc plotter:addDots {name parent} {
    set parentNoDot [plotter:removeDots $parent]
    set psize [string length $parentNoDot]
    return $parent.[string range $name $psize end]
}

proc plotter:getCompoundName {context} {
    global plotter:cmpdPlotNameIsDone
    set plotter:cmpdPlotNameIsDone 0
    
    set tp [toplevel $context.getCompoundName]
    wm title $tp "New Compound Plot"
    cascadeWindow $tp
    
    set f [frame $tp.f -relief raised -bd 1]
    pack $f -side top -expand no -fill both
    set le [tixLabelEntry $f.le -label "Name:"]
    set box [tixButtonBox $tp.bbox -relief flat -bd 0]
    pack $le $box -side top -expand yes -fill both -padx 5 -pady 5

    $box add ok -text Create \
	-command "plotter:checkCompoundName $context $tp $le"
    set e [$le subwidget entry]
    bind $e <Return> "plotter:checkCompoundName $context $tp $le"
    bind $e <Escape> "destroy $tp; set plotter:cmpdPlotNameIsDone \"\""
    wm protocol $tp WM_DELETE_WINDOW \
	"set plotter:cmpdPlotNameIsDone \"\""
    focus $e
    $box add cancel -text Cancel -command "destroy $tp; set plotter:cmpdPlotNameIsDone \"\""

    tkwait visibility $tp
    grab $tp
}

proc plotter:checkCompoundName {context tp le} {
    upvar #0 plotter:cmpdPlotName cmpdPlotName
    upvar #0 plotter:compound compound
    upvar #0 plotter:properties properties
    
    set cmpdPlotName [[$le subwidget entry] get]

    if {[string trim $cmpdPlotName] == ""} {
	tk_messageBox -default ok -icon error -message "Enter a name please." \
	    -parent $tp -title Error -type ok
	return
    }
    
    foreach i $compound {
	set name [lindex [lindex $properties($i) 0] 0]
	if {$name == $cmpdPlotName} {
	    tk_messageBox -default ok -icon error -message "Compound \"$name\" already exists." \
		-parent $tp -title Error -type ok
	    return
	}
    }

    global plotter:cmpdPlotNameIsDone
    set plotter:cmpdPlotNameIsDone $cmpdPlotName
    destroy $tp
}

proc plotter:updateFunctionForCmpd {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:properties properties
    upvar #0 plotter:functionnalitiesLocalHisto fLocalCMPD
    upvar #0 plotter:functionnalitiesDescription fDes

    set cList [lindex $properties($context) 4]
    if {! [winfo exists $invertedHierarchy($context).panedw]} {
	set test 1
    } else {
	if {[lsearch -exact [$invertedHierarchy($context).panedw panes] [plotter:removeDots $context]] == -1} {
	    set test 1
	} else {
	    set test 0
	}
    }
    
    if {$test} {
	set listColor {}
	set listContext {}
	foreach i $cList {
	    set fDes(color:$context:$i-1) \
		[list "plotter:setPlotColorForCmpd $i" "[plotter:titleFormat $i]" "" normal command]
	    
	    set fDes(context:$context:$i-1) \
		[list "plotter:removeElt $i" "[plotter:titleFormat $i]" "" normal command]
	    
	    lappend listColor color:$context:$i
	    lappend listContext context:$context:$i
	}
	set fDes(multiPlotColor-1) [list plotter:noop "Colors" "" normal cascade "" $listColor]
	set fDes(multiPlotContext-1) [list plotter:noop "Remove" "" normal cascade "" $listContext ]
	if {[lindex $properties($context) 1] == "float"} {
	    set fDes(localCMPD-1) $fDes(localTimeG-1)
	} 
    } else {
	set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
	set menu [$canvas.local subwidget menu].multiPlotColor   
	set length [expr [$menu index end] + 1]
	for {set i $length} {$i < [llength $cList]} {incr i} {
	    set j [lindex $cList $i]
	    $menu add command -label "[plotter:titleFormat $j]" -command "plotter:setPlotColorForCmpd $j $context"
	}
	set menu [$canvas.local subwidget menu].multiPlotContext
	set length [expr [$menu index end] + 1]
	for {set i $length} {$i < [llength $cList]} {incr i} {
	    set j [lindex $cList $i]
	    $menu add command -label "[plotter:titleFormat $j]" -command "plotter:removeElt $j $context"
	}
    }
}

proc plotter:setPlotColorForCmpd {contCMPD context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:properties properties
    upvar #0 plotter:color color
    
    set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
    set c [tk_chooseColor -initialcolor $color($contCMPD) -parent $canvas \
	       -title "Select foreground color for [lindex [lindex $properties($contCMPD) 0] 0]"]
    
    if {$c == ""} {
	return
    }
    
    set color($contCMPD) $c
    $canvas itemconfigure $contCMPD:plot -fill $c
}

proc plotter:removeElt {elt context} {
    upvar #0 plotter:properties properties
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:objects objects
    upvar #0 plotter:plotters plotters

    set cList [lindex $properties($context) 4]   

    TkRequest $context RemoveFromCmpd $elt
    if {[llength $cList] == 1} {
	set todisplay {}
	foreach i $plotters {
	    if {[llength $objects($i)] != 1 || [lindex $objects($i) 0] != $context} {
		lappend todisplay $i
	    }
	    foreach j $objects($i) {
		if {$j != $context} {
		    lappend todisplay $j
		} 
	    }      
	}
	global mainContext
	plotter:display $mainContext $todisplay	
    } else {
	set index [lsearch -exact [lindex $properties($context) 4] $elt ]
	set properties($context) [TkRequest $context GetProperties]
	plotter:updateFunctionForCmpd $context
	set canvas [$invertedHierarchy($context).panedw subwidget [plotter:removeDots $context]].canvas
	plotter:reDrawPlot $context $canvas
	set menu [$canvas.local subwidget menu]   
	$menu.multiPlotColor delete $index
	$menu.multiPlotContext delete $index
    }
}

proc bgerror {msg} {
    global errorInfo
    puts "++++++++++++++++++++++++++++++"
    puts "-- Error : $msg"
    puts "--"
    puts "-- stack: $errorInfo"
    puts "++++++++++++++++++++++++++++++"
}

proc rearrangeBindings {w} {

# Rearrange the bindtags so the widget comes after the class.
# This hack was lifted from gdbtk...

    set class [winfo class $w]
    set new_list {}

    foreach tag [bindtags $w] {
	if {$tag == $w} {
	    # no-op
	} {
	    lappend new_list $tag
	    if {$tag == $class} {
		lappend new_list $w
	    }
	}
    }

    bindtags $w $new_list
}

proc plotter:colorShift {nbColor} {
    set color [list "#000000" "#0000fe" "#00fe00" "#00fefe" "#fe0000" \
		   "#fe00fe" "#fefe00" "#fefefe"]
    set s [llength $color]
    set l [expr $nbColor % $s]
    return [lindex $color $l]
}



proc plotter:modeNormal {context} {
    global breakpoint:started
    global breakpoint:currentCanvas
    if {[set breakpoint:started]} {
	set canvas [set breakpoint:currentCanvas]
	set parent [winfo parent $canvas]
	set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	if {$context == $c} {
	    breakpoint:end $c $canvas
	}
    }

    global selection:started
    global selection:currentCanvas
    if {[set selection:started]} {
	set canvas [set selection:currentCanvas]
	set parent [winfo parent $canvas]
	set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	if {$context == $c} {
	selection:end $c $canvas 
	}
    }
}

proc plotter:simCont {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    TkRequest $invertedHierarchy($context) ReleaseBackend
}

proc plotter:simStop {context} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    TkRequest $invertedHierarchy($context) HoldBackend
}

proc plotter:getGlobalTConf {context} {
    global mainMenu:xadjust 
    global hbar:linked mainMenu:linked
    global plotter:colorAuto mainMenu:colorAuto

    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:properties properties
 
    set newContext [plotter:getVisiblePlotter $context]
    
    if {[lindex $properties([lindex $hierarchy($newContext) 0]) 2] != "time"} {
	set mainMenu:xdajust 0
	set mainMenu:linked 0
	set mainMenu:colorAuto 0
	return	
    }

    set confList [TkRequest $newContext GetConf] 
    set mainMenu:xadjust [lindex $confList 0]

    set mainMenu:linked [set hbar:linked($newContext)]
    set mainMenu:colorAuto [set plotter:colorAuto($newContext)]
    
    global mainMenu:autoSaveSession
    upvar #0 plotter:autoSaveSession autoSaveSession
    set mainMenu:autoSaveSession $autoSaveSession
}

proc plotter:setGlobalTConf {varName context} {
    upvar #0 mainMenu:$varName toSet
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:plotterState state

    set cont [plotter:getVisiblePlotter $invertedHierarchy($context)]

    switch $varName {
	xadjust {
	    TkRequest $cont SetConf [list $toSet]
	    if {$tCur == 0} {
		if {$toSet} {
		    set state($context,compress) 1
		    plotter:modifyButton $cont compress-2
		} else {
		    set state($context,compress) 0
		    plotter:modifyButton $cont compress-1
		}
	    }
	}
	linked {
	    global hbar:linked 
	    set hbar:linked($cont) $toSet
	    hbar:config $cont
	}
	colorAuto {
	    global plotter:colorAuto
	    set plotter:colorAuto($cont) $toSet
	}
	autoSaveSession {
	    global plotter:autoSaveSession 
	    set plotter:autoSaveSession $toSet
	}
    }
}

proc plotter:titleFormat {context} {
    upvar #0 plotter:properties properties
    set nameList [lindex $properties($context) 0]
    if {[llength $nameList] > 1} {
	return "[lindex $nameList 0] ([join [lrange $nameList 1 end] ","])"
    } else {
	return "[lindex $nameList 0]"
    }
}

proc plotter:seekBw {context} {
    set t [TkRequest $context getPrevDate]
    
    plotter:seek $context $t
}


proc plotter:seekFw {context} {
    set t [TkRequest $context getNextDate]
    
    plotter:seek $context $t
}

proc plotter:seek {context t} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 hbar:hBar hBar
    upvar #0 plotter:tMaxDisplay tMaxDisplay 

    if {$t == -1} {
	bell
	return
    }

    set mCont $invertedHierarchy($context)
    
    set delta [expr ($tMax($mCont) - $tMin($mCont)) / 2.0]  
    set newtMin [expr $t - $delta]
    set newtMax [expr $t + $delta]
    plotter:setBounds $mCont $newtMin $newtMax 0
    set master [winfo parent $hBar($mCont)] ;# mouais...
    plotter:drawXAxis $mCont $master.xaxis 0 [expr $tMin($mCont) / $tMaxDisplay($mCont)]
    plotter:refreshGraph $mCont

}

proc plotter:seekAndScroll {context x y dir} {
     upvar #0 plotter:properties properties

    set w [winfo containing $x $y]
    if {[plotter:pathDepth $w] <= 3} {
	return
    }

    set wp $w
    while {[winfo name $wp] != "canvas"} {
	set wp [winfo parent $wp]
	if {[plotter:pathDepth $wp] == 3} {
	    return
	}
    }
    set wp [winfo parent $wp]
    set cont [plotter:addDots [winfo name $wp] [winfo parent [winfo parent $wp]]]
    
    if {[lindex $properties($cont) 2] != "time"} {
	return
    }

    if {$dir == 1} {
	plotter:seekFw $cont
    } else {
	plotter:seekBw $cont
    }
}

proc plotter:simStopped {context} {
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:properties properties
    
    foreach i $plotters {
	if {[lindex $properties([lindex $hierarchy($i) 0]) 2] == "time"} {
	    plotter:modifyButton $i simStop-1
	    plotter:modifyButton $i simCont-1
	}
    }
}

proc plotter:simRunning {context} {
    upvar #0 plotter:plotters plotters
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:properties properties

    foreach i $plotters {
	if {[lindex $properties([lindex $hierarchy($i) 0]) 2] == "time"} {
	    plotter:modifyButton $i simStop-2
	    plotter:modifyButton $i simCont-2
	}
    }
}

proc plotter:initStates {context} {
    upvar #0 plotter:plotterState state \
	plotter:properties properties
    
    set state($context,vcompress) 0

    if {[lindex $properties($context) 1] == "time"} {
	# mouai...
	if {[info exists state($context,compress)]} {
	    if {$state($context,compress)} {
		plotter:modifyButton $context compress-2	    
	    }
	} else {
	    set state($context,compress) 0
	}
	
	set state($context,zoomin) 0
	set state($context,zoomout) 0
	
	upvar #0 plotter:tCur tCur
	upvar #0 plotter:tMin tMin
	upvar #0 plotter:tMax tMax
	upvar #0 plotter:tMaxDisplay tMaxDisplay 
	
	trace variable tCur w "plotter:tCurChanged $context"
	trace variable tMin($context) w "plotter:processNextState $context"
	trace variable tMax($context) w "plotter:processNextState $context"
	trace variable tMaxDisplay($context) w "plotter:processNextState $context"
    }
}

proc plotter:tCurChanged {context name1 name2 op} {
    upvar #0 plotter:plotterState state
    upvar #0 plotter:tCur tCur

    if {$state($context,zoomin) == 0} {
	if {$tCur > 0} {
	    set state($context,zoomin) 1
	    plotter:modifyButton $context zoomIn-2
	    trace vdelete tCur w "plotter:tCurChanged $context"
	}
    }
}

proc plotter:processNextState {context name1 name2 op} {
    upvar #0 plotter:plotterState state
    upvar #0 plotter:tMin tMin
    upvar #0 plotter:tMax tMax
    upvar #0 plotter:tMaxDisplay tMaxDisplay 
    upvar #0 plotter:tCur tCur
    upvar #0 plotter:properties properties

    set diff [expr $tMax($context) - $tMin($context)]
    
    if {$state($context,compress) == 0} {
	if {($diff >= $tMaxDisplay($context)) && ($tCur != 0)} {
	    set state($context,compress) 1
	    plotter:modifyButton $context compress-2
	}
    } else {
	if {$state($context,compress) == 1} {
	    if {$diff < $tMaxDisplay($context)} {
		set state($context,compress) 0
		plotter:modifyButton $context compress-1
	    }
	}
    }

    if {$state($context,zoomin) == 1} {
	if {$diff <= [lindex $properties($context) 4]} {
	    set state($context,zoomin) 2
	    plotter:modifyButton $context zoomIn-1
	}
    } else {
	if {$state($context,zoomin) == 2} {
	    if {$diff > [lindex $properties($context) 4]} {
		set state($context,zoomin) 1
		plotter:modifyButton $context zoomIn-2
	    }
	}
    }

    if {$state($context,zoomout) == 0} {
	if {$diff < $tMaxDisplay($context)} {
	    set state($context,zoomout) 1
	    plotter:modifyButton $context zoomOut-2
	}
    } else {
	if {$state($context,zoomout) == 1} {
	    if {$diff >= $tMaxDisplay($context)} {
		set state($context,zoomout) 0
		plotter:modifyButton $context zoomOut-1
	    }
	}
    }
}

proc plotter:processCurrentState {context} {
    upvar #0 plotter:plotterState state
    upvar #0 plotter:invertedHierarchy invertedHierarchy \
	plotter:properties properties
        
    if {$state($context,vcompress) == 0} {
	plotter:modifyEntry $invertedHierarchy($context) mvcompress-1
    } else {
	if {$state($context,vcompress) == 1} {
	    plotter:modifyEntry $invertedHierarchy($context) mvcompress-2
	} else {
	    if {$state($context,vcompress) == 2} {
		plotter:modifyEntry $invertedHierarchy($context) mvcompress-3
	    }
	}
    }

    if {[lindex $properties($context) 1] == "time"} {
	if {$state($context,compress) == 0} {
	    plotter:modifyEntry $invertedHierarchy($context) mcompress-1
	} else {
	    if {$state($context,compress) == 1} {
		plotter:modifyEntry $invertedHierarchy($context) mcompress-2
	    }
	}
	
	
	if {$state($context,zoomin) == 1} {
	    plotter:modifyEntry $invertedHierarchy($context) mzoomIn-2
	} else {
	    if {$state($context,zoomin) == 2} {
		plotter:modifyEntry $invertedHierarchy($context) mzoomIn-1
	    } 
	}
	
	if {$state($context,zoomout) == 0} {
	    plotter:modifyEntry $invertedHierarchy($context) mzoomOut-1
	} else {
	    if {$state($context,zoomout) == 1} {
		plotter:modifyEntry $invertedHierarchy($context) mzoomOut-2
	    }
	}
    }
}

proc plotter:preProcessCurrentState {context} {
    upvar #0 plotter:hierarchy hierarchy
    upvar #0 plotter:properties properties

    set thisContext [plotter:getVisiblePlotter $context]
    plotter:processCurrentState $thisContext
}

# an attempt to change the mouse cursor during treatment
proc plotter:startIsBusy {context} {
#     upvar #0 plotter:winListForCursor win
#     upvar #0 plotter:cursors cursors
#     global mainContext

#     foreach i [winfo children $mainContext] {
# 	lappend 
# 	set c [$w cget -cursor]
# 	$w configure -cursor watch
# 	set cursors($w) $c	
#     }
    
    #     upvar #0 plotter:winListForCursor win
    
#     set win {}

#     set currWin [eval winfo containing -displayof $context [winfo pointerxy $context]]
#     if {[string compare $currWin ""]} {
# 	plotter:modifyCursor $currWin
#     }

#     bind all <Motion> "+plotter:modifyCursor %W"
}

proc plotter:modifyCursor {w} {
    upvar #0 plotter:winListForCursor win
    upvar #0 plotter:cursors cursors
    
    if {[lsearch -exact $win $w] == -1} {
	set c [$w cget -cursor]
	$w configure -cursor watch
	lappend win $w
	set cursors($w) $c
    }
}

proc plotter:stopIsBusy {context} {


#     upvar #0 plotter:winListForCursor win
#     upvar #0 plotter:cursors cursors

#     plotter:removeBinding all <Motion> "plotter:modifyCursor %W"
    
#     foreach i $win {
# 	if {[winfo exists $i]} {
# 	    $i configure -cursor $cursors($i)
# 	}
#     }
}


proc plotter:removeBinding {class event script} {
    set cmd [bind $class $event]
    set i [string first $script $cmd]
    if {$i == -1} {
	return
    }

    set cmdList [split $cmd \n]
    set newCmd ""
    set el 0
    set max [llength $cmdList]
    foreach i $cmdList {
	if {$i != $script} {
	    incr el
	    if {$el == [expr $max - 1]} {
		set newCmd $newCmd$i
	    } else {
		set newCmd $newCmd$i\n
	    }
	}
    }
    bind $class $event $newCmd
}

proc plotter:removeThisGraph {context} {
    upvar #0 plotter:objects objects \
	plotter:plotters plotters

    set todisplay {}
    set parent {}
    foreach i $plotters {
	set flag 0
	foreach j $objects($i) {
	    if {$j != $context} {
		lappend todisplay $j
		set flag 1
	    }
	}
	if {$flag} {
	    lappend parent $i
	}
    }
    
    if { ! [plotter:lempty $todisplay]} {
	set todisplay [concat $parent $todisplay]
    }

    global mainContext
    plotter:display $mainContext $todisplay
}

proc plotter:verticalCompress {context} {
    upvar #0 plotter:plotterState state
    set state($context,vcompress) 1

    global plotter:vComp
    set plotter:vComp($context) 1

    plotter:modifyButton $context vcompress-2

    $context yview moveto 0
    set scrollregion [$context cget -scrollregion]
    set height [winfo height $context]
    
    $context itemconfigure plotter:$context -height $height
    set scrollregion [lreplace $scrollregion 3 3 $height]
    $context configure -scrollregion $scrollregion
    
    plotter:compressAxisFont $context
}

proc plotter:verticalUncompress {context} {
    upvar #0 plotter:plotterState state
    set state($context,vcompress) 0

    global plotter:vComp
    set plotter:vComp($context) 0

    plotter:modifyButton $context vcompress-1

    plotter:panedSetSizeWhenMapped $context
    plotter:restoreAxisFont $context
}

proc plotter:choosePrintFile {context parent} {
    if {[winfo exists $parent.printFile]} {
	wm deiconify $parent.printFile
	raise $parent.printFile
	return
    }
    set tl [toplevel $parent.printFile]
    # can't use grab with tixFileEntry
    wm title $tl "Print"
    wm resizable $tl 0 0
    cascadeWindow $tl

    tixLabelFrame $tl.dest -label Destination -labelside acrosstop
    pack $tl.dest -side top -expand no -fill both
    set destf [$tl.dest subwidget frame]

    set toprinter [radiobutton $destf.toprinter -text "To printer:" \
		       -variable plotter:fileOrPrinter -value toprinter]
    pack $toprinter -side top -pady 0 -anchor w -padx 8
    
    set filef [frame $destf.file]
    pack $filef -expand no -fill both

    set infile [radiobutton $filef.infile -text "To file:" \
		    -variable plotter:fileOrPrinter -value infile]

    set select [tixFileEntry $filef.select -dialogtype tixFileSelectDialog \
		    -labelside left -variable plotter:printFile -selectmode normal]

    pack $infile $select -side left -padx 8 -pady 0

    $infile configure -command "plotter:togglePrintFile $select"
    $toprinter configure -command "plotter:togglePrintFile $select"

    tixLabelFrame $tl.mode -label Mode -labelside acrosstop
    pack $tl.mode -expand no -fill both
    set modef [$tl.mode subwidget frame]

    set compress [radiobutton $modef.compress -text "Compressed" \
		      -variable plotter:printMode -value compress]

    set uncompress [radiobutton $modef.uncompress -text "Uncompressed" \
		      -variable plotter:printMode -value uncompress]

    pack $compress $uncompress -side top -pady 0 -anchor w -padx 8

    upvar #0 plotter:fileOrPrinter forp plotter:printMode printMode
    set forp toprinter
    $select configure -state disabled
    set printMode compress
    
    upvar #0 plotter:printFile printFile

    set printFile ""

    set box [tixButtonBox $tl.buttons -relief flat -bd 0]
    pack $box -side bottom -fill x
    $box add print -text Print  \
	-command "plotter:printFileChosen $context $select $tl"
    $box add cancel -text Cancel \
	-command "destroy $tl"

    bind $tl <Return> "plotter:printFileChosen $context $select $tl"
}

proc plotter:printFileChosen {context select tl} {
    upvar #0 plotter:fileOrPrinter forp \
	plotter:printMode printMode \
	plotter:printFile printFile

    $select update
    
    set printFile [string trim $printFile]

    if {($printFile == "") && ($forp != "toprinter")} {
	return
    }
    if {$forp == "toprinter"} {
	set printFile ""
    }
    
    if {$printMode == "compress"} {
	set res [list $printFile compress]
    } else {
	set res [list $printFile uncompress]
    }
    destroy $tl

    plotter:doPrint $context $res
}

proc plotter:togglePrintFile {select} {
    upvar #0 plotter:fileOrPrinter forp
    
    if {$forp == "toprinter"} {
	$select configure -state disabled
    }  else {
	$select configure -state normal
    }
}

# TODO: give a key and get the path of tk widget based on the context
# I add this so that if the path of one widget is changed during developement, 
# to reflect this modification everywhere in the code, only this proc have to be 
# changed (no query-replace). But for the first 57xx lines of tcl I typed, I used 
# predefined names and build path names of widget based on these conventions. This 
# proc is not in use in the older code but it should be
proc plotter:getWidgetFromContext {context widget {subcont ""}} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy

    switch $widget {
	localCanvas {
	    set panedw $invertedHierarchy($context).panedw
	    set subw [plotter:removeDots $context]
	    if {[lsearch -exact [$panedw panes] $subw] != -1} {
		set p [$panedw subwidget $subw]
		return $p.canvas
	    } else {
		return ""
	    }
   	}
	mainCanvas {
	    return $context
	}
	panedWindow {
	    return $context.panedw
	}
	localPane {
	    set subw [plotter:removeDots $subcont]
	    if {[lsearch -exact [$context.panedw panes] $subw] != -1} {
		return [$context.panedw subwidget $subw]
	    } else {
		return ""
	    }
	}
    }
}

proc plotter:bringIntoFocus {context subcont} {

    set index 0
    set panedw [plotter:getWidgetFromContext $context panedWindow]
    set paneList [$panedw panes]
    set paneToDisplay [plotter:getWidgetFromContext $context localPane $subcont]

    if {$paneToDisplay == ""} {
	return
    }

    for {set i 0; set j [lindex $paneList $i]} {$j != [winfo name $paneToDisplay]} \
	{incr i; set j [lindex $paneList $i]} {
	    set p [$panedw subwidget $j]
	    set index [expr [winfo height $p.canvas] + $index]
    }
    
    set overall [winfo height $panedw]	
    [plotter:getWidgetFromContext $context mainCanvas] yview moveto \
	[expr $index.0 / $overall]
}


proc plotter:globalBreakpointStart {context} {
    upvar #0 breakpoint:started brkStarted \
	plotter:hierarchy hierarchy \
	plotter:properties properties \
	plotter:globalBreakpointStarted started \
	plotter:compound compound \
	plotter:breakpointContext2Path context2Path \
	plotter:disabledList disableList \
	plotter:disabledBreakpoint disa \
	plotter:contextBreak2Path contextBreak2Path
       
    # can't use the global breakpoint widget while the local breakpoint widget 
    # is poped up 
    if {$brkStarted} {
	global breakpoint:currentCanvas
	set canvas [set breakpoint:currentCanvas]
	set parent [winfo parent $canvas]
	set c [plotter:addDots [winfo name $parent] [winfo parent [winfo parent $parent]]]
	breakpoint:end $c $canvas
    }

    if {[winfo exists $context.globalBreakpoint]} {
	wm deiconify $context.globalBreakpoint
	raise $context.globalBreakpoint
	return
    }
    
    set started 1

    if {! [info exists disableList]} {
	set disableList {}
    }
    
    set tl [toplevel $context.globalBreakpoint]
    wm title $tl "Graph Breakpoints"
    wm protocol $tl WM_DELETE_WINDOW \
	"plotter:globalBreakpointEnd $context"
    cascadeWindow $tl

    set tixTree [tixTree $tl.list -scrollbar auto]
    set box [tixButtonBox $tl.buttons -relief flat -bd 0]
    
    $box add cancel -text Close \
	-command "plotter:globalBreakpointEnd $context"
   
    grid $tixTree -column 0 -row 0 -sticky news
    grid $box -column 0 -row 1 -sticky news
    grid columnconfigure $tl 0 -weight 1
    grid rowconfigure $tl 0 -weight 1
    grid rowconfigure $tl 1 -weight 0
    
    set hlistw [$tixTree subwidget hlist]
    $hlistw configure -width 30 -height 20 \
	-drawbranch 0 
    
    set menu [menu $tixTree.menu -tearoff false]
    $menu add command -label "Remove" \
	-command "plotter:globalRemoveBreakpoint $context $tixTree"
    $menu add command -label "Disable" \
	-command "plotter:globalDisaOrEnaBreakpoint $context $tixTree 0"
    $menu add command -label "Enable" \
	-command "plotter:globalDisaOrEnaBreakpoint $context $tixTree 1"
    
    plotter:breakpointBind $tixTree $tl $menu

    set donttry {}
    foreach i $compound {
	foreach j [lindex $properties($i) 4] {
	    lappend donttry $j
	}
    }

    set ii 0
    foreach i $hierarchy($context) {
	set disabled {}
	if {[lsearch -exact $donttry $i] == -1} {
	    set bList [TkRequest $i GetBreakpointList]
	    if {! [plotter:lempty [array names disa $i]]} {
		set bList [concat $bList $disa($i)]
		set disabled $disa($i)
	    }
	    if {! [plotter:lempty $bList]} {
		set image [plotter:getIconForGraph $i]

		$hlistw add $ii -itemtype imagetext \
		    -image $image -text "[plotter:titleFormat $i]" \
		    -data [list $i]
		set jj 0
		set alreadyDisplayed {}
		foreach j $bList {
		    # do this test because compound can return a list containing 
		    # duplicated elements
		    if {[lsearch -exact $alreadyDisplayed $j] == -1} { 
			if {[lindex $properties($i) 1] == "state"} {
			    set text [lindex [lindex $properties($i) 3] $j]
			} else {
			    set text $j
			}
			set flag 1
			if {[lsearch -exact $disabled $j] != -1} {
			    set text "$text (disabled)"
			    set flag 0
			}
			$hlistw add $ii.$jj -text $text \
			    -data [list $i $j $flag]
			set contextBreak2Path($i,$j) $ii.$jj
			incr jj
			lappend alreadyDisplayed $j 
		    }
		}
		set context2Path($i) [list $ii $jj]
		incr ii
	    }
	}
    }
}

proc plotter:globalBreakpointEnd {context} {
    upvar #0 plotter:globalBreakpointStarted started \
	plotter:breakpointContext2Path context2Path \
	plotter:contextBreak2Path contextBreak2Path

    set started 0
    destroy $context.globalBreakpoint
    if {[info exists context2Path]} {
	unset context2Path
    }
    if {[info exists contextBreak2Path]} { 
	unset contextBreak2Path 
    }
}

proc plotter:globalRemoveBreakpoint {context tixTree} {
    upvar #0 plotter:breakpointContext2Path context2Path \
	plotter:disabledBreakpoint disa

    set hlistw [$tixTree subwidget hlist]
    set path [$hlistw info selection]
    set data [$hlistw info data $path]
    
    set c [lindex $data 0]
    set canvas [plotter:getWidgetFromContext $c localCanvas]

    set hlistEntry $path
    if {[llength $data] == 1} {
	set bList [TkRequest $c GetBreakpointList]
	if {! [plotter:lempty [array names disa $c]]} {
	    set bList [concat $bList $disa($c)]
	}
	unset context2Path($c)
	if {! [plotter:lempty [array names disa $c]]} {
	    unset disa($c)
	}
    } else {
	set bList [lindex $data 1]
	set parent [$hlistw info parent $path]
	set children [$hlistw info children $parent]
	if {[llength $children] == 1} {
	    set hlistEntry $parent
	    unset context2Path($c)
	    if {! [plotter:lempty [array names disa $c]]} {
		unset disa($c)
	    }
	}
    }
    
    $hlistw delete entry $hlistEntry

    foreach i $bList {
	if {$canvas != ""} {
	    $canvas delete breakpoint:$c:$i
	}
	TkRequest $c ClearBreakpoint $i
	if {! [plotter:lempty [array names disa $c]]} {
	    plotter:lremove disa($c) $i
	}
    }
}

proc plotter:breakpointBind {treew w menu} {
    bind $w <3> "plotter:popBreakpointMenu $treew $menu %X %Y"
    bind $w <Double-Button-1> "plotter:breakpointSee $treew %x %y"
}

proc plotter:popBreakpointMenu {treew menu X Y} {
    set hlist [$treew subwidget hlist]

    set toplevel [winfo toplevel $treew]

    set y0 [winfo rooty $toplevel]
    set y [expr $Y - $y0]
    set path [$hlist nearest $y]
    
    if {$path != ""} {
	$hlist selection clear
	$hlist selection set $path
	
	set data [$hlist info data $path]
	if {[llength $data] > 1} {
	    if {[lindex $data 2] == 1} {
		$menu entryconfigure 1 -state normal
		$menu entryconfigure 2 -state disabled
	    } else {
		$menu entryconfigure 1 -state disabled
		$menu entryconfigure 2 -state normal
	    }
	} else {
	    $menu entryconfigure 1 -state normal
	    $menu entryconfigure 2 -state normal
	}
	tk_popup $menu $X $Y
    }
}

proc plotter:addToGlobalBreakpoint {context toSet} {
    upvar #0 plotter:globalBreakpointStarted started \
	plotter:invertedHierarchy invertedHierarchy \
	plotter:breakpointContext2Path context2Path \
 	plotter:properties properties  \
	plotter:contextBreak2Path contextBreak2Path \
	plotter:disabledBreakpoint disa 
    
    if {[info exists started]} {
	 if {! $started} {
	     return
	 }
    } else {
	return
    }
    
    set mc $invertedHierarchy($context)

    set tixTree $mc.globalBreakpoint.list
    set hlistw [$tixTree subwidget hlist]

    set test 1
    if {! [plotter:lempty [array names disa $context]]} {
	set test [expr [lsearch -exact $disa($context) $toSet] == -1]
    }
    
    if {! $test} {
	plotter:globalDisaOrEnaBreakpoint $invertedHierarchy($context) $tixTree 1  \
	    $context $toSet
	return
    }
 
     if {[lindex $properties($context) 1] == "state"} {
	set text [lindex [lindex $properties($context) 3] $toSet]
    } else {
	set text $toSet
    }

    if {[plotter:lempty [array names context2Path $context]]} {
	set current [$hlistw info children]
	if {[llength $current] > 0} {
	    set pos [expr [lindex $current end] + 1]
	} else {
	    set pos 0
	}
	
	set image [plotter:getIconForGraph $context]

	$hlistw add $pos -itemtype imagetext \
	    -image $image -text "[plotter:titleFormat $context]" \
	    -data [list $context]

	set context2Path($context) [list $pos 1]
	set pos $pos.0
    } else {
	set posList $context2Path($context)
	set pos [lindex $posList 0].[lindex $posList 1]
	set new [expr [lindex $posList 1] + 1]
	set context2Path($context) [lreplace $posList 1 1 $new]
    }

    $hlistw add $pos -text $text \
 	-data [list $context $toSet 1]
    set contextBreak2Path($context,$toSet) $pos
}

proc plotter:getIconForGraph {context} {
    upvar #0 plotter:properties properties

    if {[plotter:lempty [lindex $properties($context) 4]]} {
	if {[lindex $properties($context) 1] == "state"} {
	    set image [fetchImage sdiagram]
	} else {
	    set image [fetchImage tgraph]
	}
    } else {
	if {[lindex $properties($context) 1] == "state"} {
	    set image [fetchImage sdiagrams]
	} else {
	    set image [fetchImage tgraphes]
	}
    }
    return $image
}

proc plotter:breakpointSee {treew x y} {
    upvar #0 plotter:invertedHierarchy invertedHierarchy 
    
    set hlist [$treew subwidget hlist]
    set path [$hlist nearest $y]
    
    if {$path == ""} {
	return
    }
    
    set data [$hlist info data $path]
    set context [lindex $data 0]
    
    plotter:bringIntoFocus $invertedHierarchy($context) $context
}

proc plotter:globalDisaOrEnaBreakpoint {context tixTree disaOrEna args} {
    upvar #0 plotter:breakpointContext2Path context2Path \
	plotter:properties properties \
	plotter:disabledBreakpoint disa \
	plotter:contextBreak2Path contextBreak2Path

    set hlistw [$tixTree subwidget hlist]
    if {[plotter:lempty $args]} {
	set path [$hlistw info selection]
    } else {
	set path $contextBreak2Path([lindex $args 0],[lindex $args 1])
    }
    set data [$hlistw info data $path]

   
    set c [lindex $data 0]
    set canvas [plotter:getWidgetFromContext $c localCanvas]
    
    set info $context2Path($c)
    
    set children [$hlistw info children $path]

    set pos -1
    if {[llength $data] == 1} {
	set bList [TkRequest $c GetBreakpointList]
	if {! [plotter:lempty [array names disa $c]]} {
	    set bList [concat $bList $disa($c)]
	}
    } else {
	set bList [lindex $data 1]
	set pos $path
    }

    foreach i $bList {
	# don't use $pos != $path since we want string comparisons and pos and path can
	# be seen as numbers by tcl
	if {$pos != $path} { 
	    set pos $contextBreak2Path($c,$i)
	}

	if {[lindex $properties($c) 1] == "state"} {
	    set text [lindex [lindex $properties($c) 3] $i]
	} else {
	    set text $i
	}

	if {! $disaOrEna} {
	    set color pink
	    set text "$text (disabled)"
	    TkRequest $c ClearBreakpoint $i
	    if {[plotter:lempty [array names disa $c]]} {
		set disa($c) $i
	    } else {
		plotter:ladd disa($c) $i
	    }
	} else {
	    set color green
	    TkRequest $c SetBreakpoint $i

	    if {! [plotter:lempty [array names disa $c]]} {
		plotter:lremove disa($c) $i
	    }
	}
	if {$canvas != ""} {
	    $canvas itemconfigure breakpoint:$c:$i -fill $color
	}
	$hlistw entryconfigure $pos -text "$text"

	set newData [lreplace [$hlistw info data $pos] 2 2 $disaOrEna]
	$hlistw entryconfigure $pos -data $newData
    }
}

proc plotter:getItsMinHeight {context} {
    upvar #0 plotter:properties properties \
	plotter:bottomb bottomb \
	plotter:topb topb
  
    set minsize [expr $bottomb + $topb]
    set perState [font actual plotter:vAxisComp -size]
    set ascent [font metrics plotter:vAxisComp -ascent]
    set descent [font metrics plotter:vAxisComp -ascent]
    set height [expr 3 * $perState - ($ascent + $descent)]
    set height [plotter:point2pixel $height]

    set min 20
    
    if {[lindex $properties($context) 1] == "state"} {
	set nbStates [llength [lindex $properties($context) 3]]
	set toAdd [expr $perState * $nbStates]
	if {$toAdd > $min} {
	    set min $toAdd
	}
    }
    set minsize [expr $minsize + $min]
    return $minsize
}

proc plotter:getAllMinHeight {context} {
    upvar #0 plotter:objects objects
    
    set min 0
    foreach i $objects($context) {
	incr min [plotter:getItsMinHeight $i]
    }
    return $min
}

proc plotter:manageVerticalCompress {context} {
    upvar #0 plotter:vComp vComp \
	plotter:plotterState state
    global plotter:vComp

    set height [winfo height $context]
    set min [plotter:getAllMinHeight $context]
 
    if {$min > $height} {
	if {$vComp($context)} {
	    plotter:verticalUncompress $context
	}
	set state($context,vcompress) 2
	set plotter:vComp($context) 0
	plotter:modifyButton $context vcompress-3
    } else {
	if {$state($context,vcompress) == 2} {
	    set state($context,vcompress) 0
	    plotter:modifyButton $context vcompress-1
	}
    }
}

proc plotter:compressAxisFont {context} {
    eval font configure plotter:vAxis [font configure plotter:vAxisComp]
}

proc plotter:restoreAxisFont {context} {
    eval font configure plotter:vAxis [font configure plotter:axis]
}
