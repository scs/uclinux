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

#  global tcl_traceExec
#  set tcl_traceExec 1
set Workspace:windowCache {}
set Workspace:statusBar {}
set Workspace:statusMsg {}
set Workspace:speedValue 0
set Workspace:statusFlip 0
set Workspace:runIcons(0) {}
set Workspace:runOnce false
set Workspace:geometry {}
set Workspace:errorLogFile {}

proc Workspace:initialize {context runOnce errorLogFile} {

    global Workspace:runOnce Workspace:errorLogFile

    set Workspace:runOnce $runOnce
    set Workspace:errorLogFile $errorLogFile

    toplevel $context
    bind $context <Destroy> "Workspace:cleanup %W $context"
    wm protocol $context WM_DELETE_WINDOW "Workspace:quit $context"

    set mbar [frame $context.mbar -bd 1 -relief raised]

    ### File

    menubutton $mbar.file -text File \
	-menu $mbar.file.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.file.m -tearoff false

    $mbar.file.m add command -label Open... \
	-command "Workspace:visitFile $context" \
	-underline 0

    $mbar.file.m add sep

    $mbar.file.m add cascade -label "Projects" \
	-menu $mbar.file.m.projects \
	-underline 0

    menu $mbar.file.m.projects -tearoff false

    $mbar.file.m add sep

    ##YM
    $mbar.file.m add command -label Preferences... \
	-command "Workspace:updateSettings $context preferences" \
	-underline 0
    ##YM

    $mbar.file.m add command -label Quit \
	-command "Workspace:quit $context" \
	-underline 0

    ### Project

    menubutton $mbar.project -text Project \
	-menu $mbar.project.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.project.m -tearoff false

    $mbar.project.m add command -label Open... \
	-command "Workspace:openProject $context" \
	-underline 0

    $mbar.project.m add command -label Edit... \
	-command "Workspace:editProject $context" \
	-underline 0

    $mbar.project.m add sep

    $mbar.project.m add command -label New... \
	-command "Workspace:newProject $context" \
	-underline 0

    $mbar.project.m add sep

    $mbar.project.m add command -label Settings... \
	-command "Workspace:updateSettings $context" \
	-underline 0

    $mbar.project.m add sep

    $mbar.project.m add command -label Close \
	-command "Workspace:closeProject $context" \
	-underline 0

    ### GDB

    menubutton $mbar.debug -text GDB \
	-menu $mbar.debug.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.debug.m -tearoff false

    $mbar.debug.m add command -label Load \
	-command "Workspace:loadDebug $context" \
	-underline 0

    $mbar.debug.m add command -label Run \
	-command "Workspace:runDebug $context" \
	-underline 0

    $mbar.debug.m add sep

    $mbar.debug.m add command -label Stop \
	-command "Workspace:holdSimulation $context" \
	-underline 0

    $mbar.debug.m add sep

    $mbar.debug.m add command -label Restart \
	-command "Workspace:restartDebug $context" \
	-underline 1

    $mbar.debug.m add command -label Kill \
	-command "Workspace:killSimulation $context" \
	-underline 0

    ### MVM

    menubutton $mbar.simulation -text MVM \
	-menu $mbar.simulation.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.simulation.m -tearoff false

    $mbar.simulation.m add command -label Run \
	-command "Workspace:startSimulation $context" \
	-underline 0

    $mbar.simulation.m add command -label Stop \
	-command "Workspace:holdSimulation $context" \
	-underline 0

    $mbar.simulation.m add command -label Continue \
	-command "Workspace:releaseSimulation $context" \
	-underline 0

    $mbar.simulation.m add command -label Inspect... \
	-command "Workspace:inspectSimulation $context" \
	-underline 0

    $mbar.simulation.m add command -label Traces... \
	-command "Workspace:traceSimulation $context" \
	-underline 0

    $mbar.simulation.m add command -label Timers... \
	-command "Workspace:timerManager $context" \
	-underline 2

    $mbar.simulation.m add sep

    $mbar.simulation.m add command -label Restart \
	-command "Workspace:restartSimulation $context" \
	-underline 1

    $mbar.simulation.m add command -label Kill \
	-command "Workspace:killSimulation $context" \
	-underline 0

    ### Window

    menubutton $mbar.window -text Window \
	-menu $mbar.window.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.window.m -tearoff false

    ### About
    
    menubutton $mbar.about -text About \
	-menu $mbar.about.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.about.m -tearoff false

    $mbar.about.m add command -label "About the MVM..." \
	-command "Workspace:displayAboutBox $context" \
	-underline 0

    pack $mbar.file $mbar.project $mbar.debug $mbar.simulation -side left

    pack $mbar.window -side left
    pack $mbar.about -side right
    pack $mbar -side top -fill x

    ### Main toolbar
    
    set mtoolbar [frame $context.mtoolbar -bd 1 -relief groove]
    pack $context.mtoolbar -side top -expand no -fill x

    ## Tools shortcuts

    set tools $mtoolbar.tools

    tixSelect $tools -allowzero true -radio true \
	-variable $context:mtools \
	-command "Workspace:toolbarExec $context"

    $tools add openProject -image [fetchImage openproj]
    Workspace:addToolTip $tools openProject Workspace:statusMsg \
	"Open project" "Open existing MVM project"

    $tools add updateSettings -image [fetchImage configure]
    Workspace:addToolTip $tools updateSettings Workspace:statusMsg \
	"Settings" "Edit current project settings"

    $tools add loadDebug -image [fetchImage debug]
    Workspace:addToolTip $tools loadDebug Workspace:statusMsg \
	"Debug" "Start GDB on the MVM" <F2>

    $tools add startSimulation -image [fetchImage start]
    Workspace:addToolTip $tools startSimulation Workspace:statusMsg \
	"Run" "Run standalone MVM (no GDB)"

    pack $tools -expand no -anchor w -padx 4 -pady 4 -side left

    ## MVM control shortcuts

    set controls $mtoolbar.controls

    tixSelect $controls -allowzero true -radio true \
	-variable $context:mcontrols \
	-command "Workspace:controlExec $context"

    $controls add inspectSimulation -image [fetchImage inspect]
    Workspace:addToolTip $controls inspectSimulation Workspace:statusMsg \
	"Inspect" "Display/Modify system objects"

    $controls add displayPlotter -image [fetchImage plotter]
    Workspace:addToolTip $controls displayPlotter Workspace:statusMsg \
	"Graphs" "Display graphs"

    $controls add traceSimulation -image [fetchImage traces]
    Workspace:addToolTip $controls traceSimulation Workspace:statusMsg \
	"API trace" "Trace system calls"

    $controls add timerManager -image [fetchImage timers]
    Workspace:addToolTip $controls timerManager Workspace:statusMsg \
	"Timers" "Set MVM timers"

    $controls add releaseSimulation -image [fetchImage cont]
    Workspace:addToolTip $controls releaseSimulation Workspace:statusMsg \
	"Continue" "Resume execution"

    $controls add holdSimulation -image [fetchImage break]
    Workspace:addToolTip $controls holdSimulation Workspace:statusMsg \
	"Stop" "Suspend execution"

    ## Simulation clock, speed spinbox and status icon
    global Workspace:speedValue Workspace:runIcons

    # Clock label
    set clock $mtoolbar.clock
    label $clock

    # Speed spinbox
    set speedf [frame $mtoolbar.speed -relief raised -bd 1]
    label $speedf.icon -image [fetchImage speedo] \
	-relief flat -bd 0 -takefocus 0
    pack $speedf.icon -side left -expand no -fill none -padx 1
    # note: although we do not want any title to be displayed for the
    # spinbox, we do not use -labelside none attribute because an
    # extra space at the left of the entry widget is still consumed for
    # the non-existent label (?!). Instead, we put an empty label at the
    # right of the entry widget, which gives a better visual effect.
    tixControl $speedf.control \
	-variable Workspace:speedValue \
	-value 10 \
	-integer true \
	-min 1 \
	-max 10 \
	-padx 0 \
	-allowempty false \
	-label {} \
	-labelside right \
	-command "Workspace:setSimulationSpeed $context" \
	-options {
	    entry.width 2
	    entry.relief ridge
	}
    pack $speedf.control -expand yes -fill both -padx 1
    # the following option must be configured after the widget is
    # built to bypass tix overrides... (i.e. want no icursor at all)
    $speedf.control subwidget entry config -insertontime 0
    Workspace:addToolTipSimple $speedf.icon Workspace:statusMsg \
	"Speed" "Set execution speed"

    # Simulation status
    button $mtoolbar.status -relief raised -bd 1 \
	-command "Workspace:openBreakContext $context"
    set Workspace:runIcons(0) [fetchImage runflip]
    set Workspace:runIcons(1) [fetchImage runflap]
    setDynamicTooltip $mtoolbar.status "Workspace:displayStatus $context" 0
    bind $mtoolbar.status <Leave> "+ set Workspace:statusMsg {}"

    # Status message bar
    global Workspace:statusBar
    set Workspace:statusBar \
	[frame $context.status -height 20 -relief groove -bd 1]
    pack $context.status -fill x
    label $context.status.message -textvariable Workspace:statusMsg
    pack $context.status.message -side left

    ### register trace hook to get informed of major context changes
    traceEvent Application:event \
	eventQueue:$context \
	"Workspace:processGlobalEvent $context"

    ### trigger initialization event
    pushEvent Application:event InitWorkspaceEvent
}

proc Workspace:addToolTip {toolbar cmd var shortmsg {longmsg {}} {fkey {}}} {

    set w [$toolbar subwidget $cmd]
    $w config -bd 1 -relief raised
    setStaticTooltip $w $shortmsg

    if {$longmsg != {}} {
	bind $w <Enter> "+ set $var \"$longmsg\""
	bind $w <Leave> "+ set $var {}"
    }

    if {$fkey != {}} {
	bind [winfo toplevel $toolbar] $fkey "$toolbar invoke $cmd"
    }
}

proc Workspace:addToolTipSimple {w var shortmsg longmsg} {

    setStaticTooltip $w $shortmsg
    bind $w <Enter> "+ set $var \"$longmsg\""
    bind $w <Leave> "+ set $var {}"
}

proc Workspace:displayStatus {context w X Y} {

    global Workspace:statusMsg
    global Monitor:simulationState Monitor:standaloneRun

    if {${Monitor:standaloneRun} == 0} {
	global Debugger:childState
	if {${Debugger:childState} == "zombie"} {
	    if {${Monitor:simulationState} == "zombie"} {
		# really zombie -- not crashed
		set status done
	    } {
		set status brkcrash
	    }
	} {
	    set status [Monitor:getStopIcon]
	}
    } {
	if {${Monitor:simulationState} == "zombie"} {
	    set status done
	} {
	    set status [Monitor:getStopIcon]
	}
    }

    switch $status {
	brkuncond {
	    set shortmsg "User break"
	    set longmsg "Execution has been stopped by user"
	}

	brktimer {
	    set shortmsg "Timer break"
	    set longmsg "A timer has elapsed"
	}

	brkgraph {
	    set shortmsg "State diagram break"
	    set longmsg "A state breakpoint was hit"
	}

	brktrace {
	    set shortmsg "Trace break"
	    set longmsg "A traced syscall has returned"
	}
	
	brkerror {
	    set shortmsg "Error break"
	    set longmsg "An error condition was raised"
	}

	brkdebug {
	    set shortmsg "Debug break"
	    set longmsg "A debugger breakpoint was hit"
	}

	brkwatch {
	    set shortmsg "Watchpoint break"
	    set longmsg "A debugger watchpoint was hit"
	}

	brkcrash {
	    set shortmsg "Crashed!"
	    set longmsg "The MVM received an unexpected exception"
	}

	done {
	    set shortmsg "Finished"
	    set longmsg "The simulation is finished"
	}

	default {
	    set shortmsg "Running"
	    set longmsg "The MVM is running"
	}
    }

    set Workspace:statusMsg $longmsg

    return $shortmsg
}

proc Workspace:openBreakContext {context} {

    global Monitor:simulationState Monitor:standaloneRun

    if {${Monitor:standaloneRun} == 0} {
	global Debugger:childState
	if {${Debugger:childState} == "zombie" ||
	    ${Monitor:simulationState} == "zombie"} {
	    return
	}
    } {
	if {${Monitor:simulationState} == "zombie"} {
	    return
	}
    }

    set status [Monitor:getStopIcon]

    switch $status {
	brktimer {
	    Workspace:timerManager $context	    
	}

	brkgraph {
	    Workspace:displayPlotter $context	    
	}

	brktrace {
	    Workspace:traceSimulation $context
	}
	
	brkerror {
	    TkRequest $context DisplayErrorLog
	}

	brkdebug {
	    TkRequest $context EditBreakpoints
	}

	brkwatch {
	    TkRequest $context EditWatchpoints
	}
    }
}

proc Workspace:toolbarExec {context button state} {

    # a little trick to have the tix select widget
    # behave like a toolbar: a selected button is
    # immediately re-invoked to restore its initial
    # graphic state. This is why the button state is
    # checked to filter out "off" invocations.
    if {$state == 1} {
	global Workspace:statusMsg
	set Workspace:statusMsg {}
	$context.mtoolbar.tools invoke $button
	Workspace:$button $context
    }
}

proc Workspace:controlExec {context button state} {

    if {$state == 1} {
	global Workspace:statusMsg
	set Workspace:statusMsg {}
	$context.mtoolbar.controls invoke $button
	Workspace:$button $context
    }
}

# "File" Menu actions

proc Workspace:cleanup {w context} {

    if {$w == $context} {
	destroy .
    }
}

proc Workspace:visitFile {context {filename {}}} {
    # file will be displayed in the main
    # debugging frame
    TkRequest $context VisitFile $filename
}

proc Workspace:quit {context} {

    global Monitor:channel

    # Be a good boy, ask confirmation if a debug session
    # is in progress before exiting...

     if {${Monitor:channel} != {}} {
 	set answer [tk_messageBox -parent $context \
 			-message "Simulation in progress... Really quit?" \
 			-type yesno -icon warning -title Warning]
 	if {$answer == "no"} {
 	    return
 	}
	 TkRequest $context KillSimulation
     }

    pushEvent Application:event WorkspaceQuitEvent
    Workspace:saveProject $context
    destroy $context
}

# "Project" Menu actions

proc Workspace:newProject {context} {

    global Workspace:session Project:settings

    set w $context.newproj

    if {[winfo exists $w]} {
	# Cannot grab focus for this toplevel (i.e. Tix FileDlg
	# is not a member of this window hierarchy); thus we
	# need to check for a currently open context; we could
	# have disabled the "New" menu item instead, but this
	# would have been much more "complex" to handle
	# menu enable/disable actions than doing this.
	wm deiconify $w
	raise $w
	return;
    }

    toplevel $w
    wm title $w "New Project"
    cascadeWindow $w $context
    
    set f [frame $w.f]
    pack $f -side top -expand yes -fill both

    global $context:projfile
    set $context:projfile ""

    set dialog [tix filedialog tixFileSelectDialog]
    $dialog config -title "Select a Project file"

    catch {
	$dialog subwidget fsbox config -directory [set Workspace:session(DefaultProjectDir)]
    }

    tixFileEntry $f.projfile -label "Project file: " \
 	-variable $context:projfile \
	-validatecmd "Workspace:valProjectFile" \
	-dialogtype tixFileSelectDialog \
 	-options {
 	    entry.width 30
 	    label.anchor w
	}

    global $context:projexe
    set $context:projexe ""

    set dialog [tix filedialog tixExFileSelectDialog]
    $dialog config -title "Select an executable file"

    catch {
	$dialog subwidget fsbox config -directory \
	    [TkRequest $context CanonicalizePath [set Workspace:session(DefaultExecDir)]]
    }

    $dialog subwidget fsbox config -filetypes { \
		{{*}		{*      -- All files}}
    }

    $dialog subwidget fsbox subwidget types pick 0

    tixFileEntry $f.projexe -label "Executable file: " \
 	-variable $context:projexe \
	-validatecmd "Workspace:valExecName" \
	-dialogtype tixExFileSelectDialog \
 	-options {
 	    entry.width 30
 	    label.anchor w
	}

    pack $f.projfile $f.projexe \
	-anchor w -expand yes -fill x -padx 10 -pady 10

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add update -text Create \
 	-command "Workspace:newProjectOk $context"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus [$f.projfile subwidget entry]
}

proc Workspace:newProjectOk {context} {

    global $context:projfile $context:projexe
    global Project:settings Workspace:session

    set w $context.newproj
    set f $w.f
    $f.projfile update
    set projfile [getAbsolutePath [set $context:projfile]]

    if {$projfile == ""} {
	tk_messageBox -parent $context \
	    -message "No project file selected" \
	    -type ok -icon error -title Error
	raise $w
	return
    }

    if {[file exists $projfile]} {
	tk_messageBox -parent $context \
	    -message "Project file already exists" \
	    -type ok -icon error -title Error
	raise $w
	return
    }

    $f.projexe update

    Project:resetSettings
    set Project:settings(Executable) [set $context:projexe]

    if {[Workspace:saveProject $context $projfile] == "false"} {
	tk_messageBox -parent $context \
	    -message "$projfile: cannot open project file for writing" \
	    -type ok -icon error -title Error
	return
    }

    set Workspace:session(DefaultProjectDir) [file dirname $projfile]
    set executable [getAbsolutePath [set $context:projexe]]
    set Workspace:session(DefaultExecDir) [file dirname $executable]
    Workspace:openProjectOk $context $projfile

    destroy $w
}

proc Workspace:valProjectFile {path} {

    if {[catch {if {$path != ""} {
	if {[file isdirectory $path] == 1} {
	    return ""
	}
	if {[file extension $path] == {}} {
	    append path ".mvm"
	}
    }}] == 1} {
	# may be an invalid ~user syntax
	return ""
    }

    return $path
}

proc Workspace:openProject {context {projfile {}}} {

    global Workspace:session

    if {$projfile != {}} {
	# if a filename has been given, open the
	# corresponding project directly.
	if {[Workspace:openProjectOk $context $projfile] == "false"} {
	    # we failed to open the specified project...
	    # remove it from the fast access menu (if present).
	    Workspace:uncacheRecentProject $context $projfile
	}
	return
    }

    # otherwise, prompt for a valid project
    set dialog [tix filedialog tixExFileSelectDialog]
    $dialog config -command "Workspace:openProjectOk $context" \
	-title "Select a Project"

    catch {
	$dialog subwidget fsbox config -directory [set Workspace:session(DefaultProjectDir)]
    }

    $dialog subwidget fsbox config -filetypes { \
	{{*.mvm} {*.mvm  -- Xenoscope project files}}
	{{*} {*      -- All files}}
    }

    $dialog subwidget fsbox subwidget types pick 0
    cascadeWindow $dialog $context
    $dialog popup
}

proc Workspace:openProjectOk {context projfile} {

    global Workspace:session

    if {[set Workspace:session(CurrentProject)] != {} &&
	[set Workspace:session(CurrentProject)] != $projfile} {
	# close currently active project
	Workspace:closeProject $context
    }

    # Just in case further tk_messageBox are involved -- ensure the
    # toplevel is visible before attempting to grab the focus.
    # update idletasks

    set projfile [TkRequest $context CanonicalizePath [getAbsolutePath $projfile]]
    set Workspace:session(CurrentProject) $projfile

    if {[Workspace:restoreProject $context $projfile] == "false"} {
	tk_messageBox -parent $context \
	    -message "$projfile: cannot open project file for reading" \
	    -type ok -icon error -title Error
	return false
    }

    pushEvent Application:event OpenProjectEvent
    Workspace:cacheRecentProject $context $projfile

    # Finally, save the project directory for the next OpenProject
    # request.
    set Workspace:session(DefaultProjectDir) [file dirname $projfile]

    pushEvent Application:event ConfigureWallpaperEvent

    return true
}

proc Workspace:closeProject {context} {

    global Workspace:session
    Workspace:saveProject $context
    set Workspace:session(CurrentProject) {}
    pushEvent Application:event CloseProjectEvent
}

proc Workspace:editProject {context} {

    global Workspace:session Project:settings

    set w $context.editproj

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	return
    }

    toplevel $w
    wm title $w "Edit Project"
    cascadeWindow $w $context
    
    set f [frame $w.f]
    pack $f -side top -expand yes -fill both

    tixLabelEntry $f.projfile -label "Filename: " \
 	-options {
 	    label.anchor w
	}

    set e [$f.projfile subwidget entry]
    $e insert 0 [set Workspace:session(CurrentProject)]
    $e config -state disabled
    bind $e <1> "+ focus $e"

    global $context:projexe
    set $context:projexe [set Project:settings(Executable)]

    set dialog [tix filedialog tixExFileSelectDialog]
    $dialog config -title "Select the executable file"

    catch {
	$dialog subwidget fsbox config -directory \
	    [TkRequest $context CanonicalizePath [set Workspace:session(DefaultExecdir)]]
    }

    $dialog subwidget fsbox config -filetypes { \
		{{*}		{*      -- All files}}
    }

    $dialog subwidget fsbox subwidget types pick 0

    tixFileEntry $f.projexe -label "Executable file: " \
 	-variable $context:projexe \
	-validatecmd "Workspace:valExecName" \
	-dialogtype tixExFileSelectDialog \
 	-options {
 	    entry.width 30
 	    label.anchor w
	}

    set e [$f.projexe subwidget entry]
    bind $e <Return> "Workspace:editProjectOk $context"
    bind $e <Escape> "destroy $w"
    focus $e

    pack $f.projfile $f.projexe -side top \
	-anchor w -padx 10 -pady 10 -fill x -expand yes

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add update -text Save \
 	-command "Workspace:editProjectOk $context"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x
}

proc Workspace:valExecName {path} {
    
    if {[catch { if {$path != ""} {
	if {[file isdirectory $path] == 1} {
	    return ""
	}
    }}] == 1} {
	# may be an invalid ~user syntax
	return ""
    }

    return $path
}

proc Workspace:editProjectOk {context} {

    global $context:projexe Workspace:session Project:settings

    set w $context.editproj
    set f $w.f
    $f.projexe update

    # Do not verify executable path; user should be able
    # to select it later...

    # getAbsolutePath() does not expand the environment variables,
    # this is ok for us.
    set executable [getAbsolutePath [set $context:projexe]]
    set Workspace:session(DefaultExecdir) [file dirname $executable]
    set Project:settings(Executable) $executable
    Workspace:saveProject $context
    pushEvent Application:event ProjectUpdateEvent

    destroy $w
}

# "Debug" Menu actions

proc Workspace:loadDebug {context} {

    global Debugger:main
    Debugger:run ${Debugger:main} bt
}

proc Workspace:runDebug {context} {

    global Debugger:main
    Debugger:run ${Debugger:main} t
}

proc Workspace:restartDebug {context} {
    Workspace:killSimulation $context
    Workspace:loadDebug $context
}

proc Workspace:startSimulation {context} {
    
    global Monitor:main
    Monitor:run ${Monitor:main} b
}

proc Workspace:restartSimulation {context} {
    Workspace:killSimulation $context
    Workspace:startSimulation $context
}

proc Workspace:killSimulation {context} {
    TkRequest $context KillSimulation
}

proc Workspace:setSimulationSpeed {context v} {
    TkRequest $context SetSimulationSpeed $v
}

proc Workspace:holdSimulation {context} {

    # Plan for the program to enter the held state.
    # This means to hit the debugger's internal breakpoint
    # the next time the user code enters the preemption hook,
    # or make the monitoring thread enter a blocking read
    # state on the command channel, depending whether we
    # currently run with debugging support or not.
    TkRequest $context HoldSimulation
}

proc Workspace:releaseSimulation {context} {
    TkRequest $context ContSimulation
}

proc Workspace:inspectSimulation {context} {
    pushEvent Application:event InspectSimulationEvent
    TkRequest $context InspectSimulation {}
}

proc Workspace:traceSimulation {context} {
    pushEvent Application:event InspectSimulationEvent
    TkRequest $context InspectSimulation {System RT/Interfaces}
}

proc Workspace:timerManager {context} {
    TimerManager:popup $context
}

proc Workspace:displayPlotter {context} {
    pushEvent Application:event PlotterVisibleEvent
    TkRequest $context DisplayPlotter
}

proc Workspace:updateSettings {context {what {}}} {

    global Application:treeSeparator
    global Project:settings Workspace:session

    set w $context.settings
    toplevel $w
    wm title $w Settings
    cascadeWindow $w $context
    bind $w <Escape> "destroy $w"

    tixNoteBook $w.nb -ipadx 6 -ipady 6
    $w.nb subwidget nbframe config
    pack $w.nb -expand yes -fill both -padx 5 -pady 5 -side top

    set state disabled
    if {[set Workspace:session(CurrentProject)] != {}} {
	set state normal
    }

    ## Options configuration

    $w.nb add options -label Options -state $state
    set optab [$w.nb subwidget options]

    tixLabelFrame $optab.monlbf -label "MVM" \
	-labelside acrosstop

    pack $optab.monlbf -fill both -expand no
    set monlbf [$optab.monlbf subwidget frame]

    tixLabelFrame $optab.dbglbf -label "Debugger" \
	-labelside acrosstop

    pack $optab.dbglbf -fill both -expand no
    set dbglbf [$optab.dbglbf subwidget frame]

    checkbutton $monlbf.brkwarn -text "Break on warnings" \
	-variable Project:settings(Options,breakOnWarnings) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,breakOnWarnings)] == 1} {
	$monlbf.brkwarn select
    } {
	$monlbf.brkwarn deselect
    }
    checkbutton $monlbf.popwarn -text "Auto-raise error log" \
	-variable Project:settings(Options,popupOnWarnings) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,popupOnWarnings)] == 1} {
	$monlbf.popwarn select
    } {
	$monlbf.popwarn deselect
    }
    checkbutton $monlbf.threadqual -text "Fully qualify thread identifiers" \
	-variable Project:settings(Options,threadQualify) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,threadQualify)] == 1} {
	$monlbf.threadqual select
    } {
	$monlbf.threadqual deselect
    }
    checkbutton $monlbf.raisetops -text "Auto-raise trace windows" \
	-variable Project:settings(Options,autoRaise) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,autoRaise)] == 1} {
	$monlbf.raisetops select
    } {
	$monlbf.raisetops deselect
    }
    checkbutton $monlbf.brkalert -text "Break on trace alerts" \
	-variable Project:settings(Options,breakOnAlerts) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,breakOnAlerts)] == 1} {
	$monlbf.brkalert select
    } {
	$monlbf.brkalert deselect
    }
    checkbutton $dbglbf.ktrace -text "Trace Xenomai kernel" \
	-variable Project:settings(Options,traceKernel) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,traceKernel)] == 1} {
	$dbglbf.ktrace select
    } {
	$dbglbf.ktrace deselect
    }
    checkbutton $dbglbf.itrace -text "Trace real-time interface" \
	-variable Project:settings(Options,traceIface) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,traceIface)] == 1} {
	$dbglbf.itrace select
    } {
	$dbglbf.itrace deselect
    }
    checkbutton $dbglbf.utrace -text "Trace application" \
	-variable Project:settings(Options,traceApp) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,traceApp)] == 1} {
	$dbglbf.utrace select
    } {
	$dbglbf.utrace deselect
    }
    checkbutton $dbglbf.linenums -text "Display source line numbers" \
	-variable Project:settings(Options,lineNumbering) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,lineNumbering)] == 1} {
	$dbglbf.linenums select
    } {
	$dbglbf.linenums deselect
    }
    checkbutton $dbglbf.evbubbles -text "Activate evaluation bubbles" \
	-variable Project:settings(Options,evalBubbles) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,evalBubbles)] == 1} {
	$dbglbf.evbubbles select
    } {
	$dbglbf.evbubbles deselect
    }
    checkbutton $dbglbf.forcefocus -text "Force focus on breakpoint/watchpoint" \
	-variable Project:settings(Options,forceFocusOnBreak) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,forceFocusOnBreak)] == 1} {
	$dbglbf.forcefocus select
    } {
	$dbglbf.forcefocus deselect
    }
    checkbutton $dbglbf.useglyph -text "Use glyph cursor in source" \
	-variable Project:settings(Options,useGlyphCursor) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Options,useGlyphCursor)] == 1} {
	$dbglbf.useglyph select
    } {
	$dbglbf.useglyph deselect
    }

    pack $monlbf.brkwarn \
	$monlbf.brkalert \
	$monlbf.popwarn \
	$monlbf.threadqual \
	$monlbf.raisetops \
	$dbglbf.ktrace \
	$dbglbf.itrace \
	$dbglbf.utrace \
	$dbglbf.linenums \
	$dbglbf.evbubbles \
	$dbglbf.forcefocus \
	$dbglbf.useglyph \
	-side top -pady 0 -anchor w -padx 8

    ## Simulation parameters

    $w.nb add simulation -label Simulation -state $state
    set simtab [$w.nb subwidget simulation]

    tixLabelFrame $simtab.parlbf -label "Timing" \
	-labelside acrosstop

    pack $simtab.parlbf -fill both -expand false
    set f [$simtab.parlbf subwidget frame]

    # Simulation time limit

    global $f.stime:value
    set $f.stime:value [lindex [set Project:settings(SimulationTime)] 0]

    frame $f.f1
    tixControl $f.f1.stime \
	-label "Simulation time:" \
	-variable $f.stime:value \
	-value 0 \
	-min 0 \
	-allowempty false -options {
	    label.anchor e
	    label.width 16
	    entry.width 8
	}

    tixOptionMenu $f.f1.ustime -labelside none \
	-variable $f.ustime:unit -options {
	    menubutton.bd 0
	    menubutton.relief flat
	}

    $f.f1.ustime add command usc -label usc
    $f.f1.ustime add command msc -label msc
    $f.f1.ustime add command sec -label sec
    $f.f1.ustime configure -value [lindex [set Project:settings(SimulationTime)] 1]
    pack $f.f1 -anchor w -padx 5
    pack $f.f1.stime $f.f1.ustime -side left

    # Display tick

    global $f.dtick:value
    set $f.dtick:value [lindex [set Project:settings(DisplayTick)] 0]

    frame $f.f3
    tixControl $f.f3.dtick \
	-label "Display tick:" \
	-variable $f.dtick:value \
	-value 0 \
	-min 0 \
	-allowempty false -options {
	    label.anchor e
	    label.width 16
	    entry.width 8
	}

    tixOptionMenu $f.f3.udtick -labelside none \
	-variable $f.udtick:unit -options {
	    menubutton.bd 0
	    menubutton.relief flat
	}
			
    $f.f3.udtick add command usc -label usc
    $f.f3.udtick add command msc -label msc
    $f.f3.udtick add command sec -label sec
    $f.f3.udtick configure -value [lindex [set Project:settings(DisplayTick)] 1]
    pack $f.f3 -anchor w -padx 5
    pack $f.f3.dtick $f.f3.udtick -side left

    # Warp factor

    global $f.warp:value
    set $f.warp:value [set Project:settings(WarpFactor)]

    tixControl $f.warp \
	-label "Warp factor:" \
	-variable $f.warp:value \
	-value 3.0 \
	-integer false \
	-min 0.0 \
	-max 10.0 \
	-step 0.1 \
	-allowempty false -options {
	    label.anchor e
	    label.width 16
	    entry.width 8
	}

    pack $f.warp -anchor w -padx 5

    # Time unit

    tixOptionMenu $f.tunit -label "Time unit:" \
	-variable $f.tunit:value -options {
	    menubutton.bd 0
	    menubutton.relief flat
	    label.width 16
	    label.anchor e
	}

    $f.tunit add command usc -label usc
    $f.tunit add command msc -label msc
    $f.tunit add command sec -label sec
    $f.tunit configure -value [set Project:settings(TimeUnit)]
    pack $f.tunit -anchor w -padx 5

    checkbutton $f.vtime -text "Virtual time" \
	-variable Project:settings(Options,virtualTime) \
	-relief flat -bd 2 -pady 0 -width 30

    if {[set Project:settings(Options,virtualTime)] == 1} {
	$f.vtime select
    } {
	$f.vtime deselect
    }
    pack $f.vtime -anchor w

    ## General configuration

    $w.nb add tools -label General -state $state
    set tooltab [$w.nb subwidget tools]

    tixLabelFrame $tooltab.parlbf -label "Parameters" \
	-labelside acrosstop

    pack $tooltab.parlbf -fill both -expand no
    set parlbf [$tooltab.parlbf subwidget frame]

    tixControl $parlbf.tcp \
	-label "TCP/server port:" \
	-variable Project:settings(ServerPort) \
	-value 6545 \
	-min 1024 \
	-allowempty false \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 6
	}

    pack $parlbf.tcp -pady 5 -anchor w -padx 5

    tixControl $parlbf.wdog \
	-label "Watchdog timeout:" \
	-variable Project:settings(Watchdog) \
	-min 0 \
	-allowempty false \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 6
	}

    pack $parlbf.wdog -pady 5 -anchor w -padx 5

    tixControl $parlbf.tlogsz \
	-label "Trace buffer (lines):" \
	-variable Project:settings(TraceLogSize) \
	-min 0 \
	-allowempty false \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 6
	}

    pack $parlbf.tlogsz -pady 5 -anchor w -padx 5

    tixLabelEntry $parlbf.debugger -label "GDB path:" \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 25
	}

    $parlbf.debugger subwidget entry config -textvariable Project:settings(GdbPath)
    pack $parlbf.debugger -pady 5 -anchor w -padx 5 -fill x -expand yes

    tixLabelEntry $parlbf.srcdirs -label "Source directories:" \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 25
	}

    $parlbf.srcdirs subwidget entry config -textvariable Project:settings(SourceDirs)
    pack $parlbf.srcdirs -pady 5 -anchor w -padx 5 -fill x -expand yes

    tixLabelEntry $parlbf.wd -label "Working directory:" \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 25
	}

    $parlbf.wd subwidget entry config -textvariable Project:settings(WorkingDir)
    pack $parlbf.wd -pady 5 -anchor w -padx 5 -fill x -expand yes

    tixLabelEntry $parlbf.args -label "Local arguments:" \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 25
	}

    global Monitor:localArgs
    $parlbf.args subwidget entry config -textvariable Project:settings(LocalArgs)
    pack $parlbf.args -pady 5 -anchor w -padx 5 -fill x -expand yes

    tixLabelEntry $parlbf.printcmd -label "Print command:" \
	-options {
	    label.width 18
	    label.anchor e
	    entry.width 25
	}

    $parlbf.printcmd subwidget entry config -textvariable Project:settings(PrintCmd)
    pack $parlbf.printcmd -pady 5 -anchor w -padx 5 -fill x -expand yes

    ##YM
    ## Preferences

    global tkbridge_prefixdir

    $w.nb add preferences -label Preferences
    set preftab [$w.nb subwidget preferences]

    tixLabelFrame $preftab.prjlbf -label "Project" \
	-labelside acrosstop

    pack $preftab.prjlbf -fill both -expand no
    set prjlbf [$preftab.prjlbf subwidget frame]

    checkbutton $prjlbf.bgimagecb -text "Display wallpaper" \
	-variable Project:settings(Preferences,displaywp) \
	-relief flat -bd 2 -pady 0 -anchor w
    if {[set Project:settings(Preferences,displaywp)] == 1} {
	$prjlbf.bgimagecb select
    } {
	$prjlbf.bgimagecb deselect
    }

    tixComboBox $prjlbf.bgimagebox -label "Wallpaper:" \
	-variable Project:settings(Preferences,wallpaper) \
	-options {
	    label.width 18
	    label.anchor e
	}
    foreach file [glob -nocomplain -- $tkbridge_prefixdir/share/sim/images/bgnd*] {
	set fname [string range $file [expr 1 + [string last "/" $file]] [expr [string last "." $file] - 1]]
	if {$fname != {}} {
	    $prjlbf.bgimagebox insert end $fname
	}
    }

    pack $prjlbf.bgimagecb -side top -pady 0 -anchor w -padx 8
    pack $prjlbf.bgimagebox -expand yes -fill both -padx 10 -pady 10 -side left

    ##YM

    # get a copy of the old option settings
    set optlist {}
    global Workspace:opt2var Workspace:optNames
    foreach option ${Workspace:optNames} {
	set var [set Workspace:opt2var($option)]
	global $var
	lappend optlist [set $var]
    }

    ##YM
    ## If a particular page was specified,
    ## raise it now
    if {$what != {}} {
	$w.nb raise $what
    }
    ##YM

    ## Button box

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add save -text Save -command "Workspace:updateSettingsOk $context"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    tkwait visibility $w
    grab $w
}

proc Workspace:updateSettingsOk {context} {

    global Project:settings

    set w $context.settings

    set simtab [$w.nb subwidget simulation]
    set parlbf [$simtab.parlbf subwidget frame]

    global $parlbf.stime:value $parlbf.ustime:unit
    $parlbf.f1.stime update
    set Project:settings(SimulationTime) \
	[list [set $parlbf.stime:value] [set $parlbf.ustime:unit]]

    global $parlbf.dtick:value $parlbf.udtick:unit
    $parlbf.f3.dtick update
    set Project:settings(DisplayTick) \
	[list [set $parlbf.dtick:value] [set $parlbf.udtick:unit]]

    global $parlbf.warp:value
    $parlbf.warp update
    set Project:settings(WarpFactor) [set $parlbf.warp:value]

    global $parlbf.tunit:value
    set Project:settings(TimeUnit) [set $parlbf.tunit:value]

    set tooltab [$w.nb subwidget tools]
    set parlbf [$tooltab.parlbf subwidget frame]

    $parlbf.tcp update
    $parlbf.wdog update

    destroy $w

    pushEvent Application:event ConfigurationChanged
    pushEvent Application:event ConfigureWallpaperEvent
    pushEvent Application:event OptionChanged
}

proc Workspace:getOptionValue {context option} {

    global Workspace:opt2var

    if {[catch {set var [set Workspace:opt2var($option)]}] == 1} {
	puts "Xenoscope: unknown option \"$option\""
	return 0
    }

    global $var
    return [set $var]
}

proc Workspace:cacheWindowIn {context w label} {

    global Workspace:windowCache

    bind $w <Destroy> "Workspace:cacheWindowOut $context $w %W"
    set nth [lsearch -exact ${Workspace:windowCache} $w]

    # prevent multiple caching

    if {$nth == -1} {
	if {${Workspace:windowCache} == {}} {
	    # 1st cached window available -- enable fast-access menu
	    $context.mbar.window configure -state normal
	}
	lappend Workspace:windowCache $w
	$context.mbar.window.m add command -label $label \
	    -command "wm deiconify $w; raise $w"
    }
}

proc Workspace:cacheWindowOut {context theW {w {}}} {
    
    global Workspace:windowCache

    if {$w != {} && $w != $theW} {
	return
    }

    set nth [lsearch -exact ${Workspace:windowCache} $theW]

    if {$nth != -1} {
	set Workspace:windowCache \
	    [lreplace ${Workspace:windowCache} $nth $nth]
	
	catch {
	    $context.mbar.window.m delete $nth

	    if {${Workspace:windowCache} == {}} {
		# no more cached windows -- disable fast-access menu
		$context.mbar.window configure -state disabled
	    }
	}
    }
}

proc Workspace:cacheRecentProject {context filepath} {

    global Workspace:session

    # insert the path of the just open project into the cache
    # list, ensuring that no more than 8 entries are
    # concurrently kept...

    set plist [set Workspace:session(RecentProjects)]
    set cacheix [lsearch -exact $plist $filepath]

    if {$cacheix != -1} {
	set plist [lreplace $plist $cacheix $cacheix]
    }
    if {[llength $plist] >= 8} {
	set plist [lreplace $plist end end]
    }
    # LIFO ordering
    set Workspace:session(RecentProjects) \
	[linsert $plist 0 $filepath]

    Workspace:updateRecentProjects $context
}

proc Workspace:uncacheRecentProject {context filepath} {

    global Workspace:session

    set plist [set Workspace:session(RecentProjects)]
    set cacheix [lsearch -exact $plist $filepath]

    if {$cacheix != -1} {
	set Workspace:session(RecentProjects) \
	    [lreplace $plist $cacheix $cacheix]
	Workspace:updateRecentProjects $context
    }
}

proc Workspace:updateRecentProjects {context} {

    global Workspace:session

    set mbar $context.mbar
    $mbar.file.m.projects delete 0 end
    set nentries 0

    foreach filename [set Workspace:session(RecentProjects)] {
	if {[file exists $filename]} {
	    set basename [file rootname [file tail $filename]]
	    $mbar.file.m.projects add command -label $basename \
		-command "Workspace:openProject $context $filename"
	    incr nentries
	}
    }

    if {$nentries > 0} {
	$mbar.file.m entryconfigure 2 -state normal
    } {
	$mbar.file.m entryconfigure 2 -state disabled
    }
}

proc Workspace:print {context file} {

    global Project:settings

    set cmd [set Project:settings(PrintCmd)]

    if {$cmd == {}} {
	tk_messageBox \
	    -message "Print command has not been defined.\n\
Please define one using the Project/Settings/General setup window." \
	    -type ok -icon error -title Error
	return
    }

    if {[regexp -indices ".*\(%f\).*" $cmd mvar fileph] == 1} {
	set head [string range $cmd 0 [expr [lindex $fileph 0] - 1]]
	set tail [string range $cmd [expr [lindex $fileph 1] + 1] end]
	set cmd $head$file$tail
    } {
	# if no file placeholder has been found, simply append file name
	# to the command...
	append cmd " $file"
    }

    if {[catch { eval exec -- $cmd } err] == 1} {
	tk_messageBox \
	    -message "Print command failed with the following message:\n$err" \
	    -type ok -icon error -title Error
    }
}

proc Workspace:saveDisplays {context} {

    global Monitor:standaloneRun

    # We are actually saving monitor's stuff in the workspace code
    # because its far more easier to do this here than anywhere else.

    set tracerStatus [TkRequest $context GetInspectorStatus {System RT/Interfaces}]

    if {${Monitor:standaloneRun} == 0} {
	set inspectorStatus [TkRequest $context GetInspectorStatus]
    } {
	set inspectorStatus withdrawn
    }

    Project:setResource MonitorDisplayStatuses [list $tracerStatus $inspectorStatus]
}

proc Workspace:restoreDisplays {context} {

    global Monitor:standaloneRun

    set dispStat [Project:getResource MonitorDisplayStatuses]
    set tracerStatus [lindex $dispStat 0]
    set inspectorStatus [lindex $dispStat 1]

    if {$tracerStatus == "displayed"} {
	Workspace:traceSimulation $context
    }

    if {$inspectorStatus == "displayed" && ${Monitor:standaloneRun} == 0} {
	Workspace:inspectSimulation $context
    }
}

proc Workspace:displayAboutBox {context} {

    set w $context.about

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	return
    }

    set info [TkRequest $context GetVersionInfo]
    set version [lindex $info 0]
    set buildcf [lindex $info 1]

    toplevel $w
    wm title $w "About Xenomai/sim"
    wm resizable $w 0 0
    cascadeWindow $w
    bind $w <Escape> "destroy $w"

    frame $w.banner -relief flat -bd 0
    label $w.banner.image -image [fetchImage banner] -anchor c
    pack $w.banner.image -pady 0 -padx 0
    pack $w.banner

    frame $w.f -relief sunken -bd 3
    pack $w.f -expand yes -fill both

    tixScrolledText $w.f.gpl -scrollbar y -options {
	text.spacing1 0
	text.spacing3 0
	text.height 16
	text.width 60
	text.wrap word
    }

    pack $w.f.gpl -expand yes -fill both
    set textw [$w.f.gpl subwidget text]
    $textw tag config aligned -lmargin1 30 -lmargin2 30

    $textw insert end "\nXenomai/sim is free software; you can redistribute it and/or modify it\n" aligned
    $textw insert end "under the terms of the GNU General Public License as published by the\n" aligned
    $textw insert end "Free Software Foundation; either version 2 of the License, or (at your\n" aligned
    $textw insert end "option) any later version.\n\n" aligned
    $textw insert end "This program is distributed in the hope that it will be useful,\n" aligned
    $textw insert end "but WITHOUT ANY WARRANTY; without even the implied warranty of\n" aligned
    $textw insert end "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n" aligned
    $textw insert end "See the GNU General Public License for more details.\n\n" aligned

    $textw insert end "You are currently running the Xenoscope, a RTOS-aware debugger\n" aligned
    $textw insert end "for programs running on top of Xenomai's Minute Virtual Machine.\n\n" aligned

    $textw insert end "MVM version $version.\n" aligned
    $textw insert end "Configured as: $buildcf.\n" aligned

    $textw config -state disabled

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    tkwait visibility $w
    grab $w
}

proc Workspace:processGlobalEvent {context name1 name2 op} {

    global Workspace:session Project:settings

    set mbar $context.mbar
    set tools $context.mtoolbar.tools
    set controls $context.mtoolbar.controls

    while {[popEvent eventQueue:$context e] == "true"} {
	switch $e {
	    InitWorkspaceEvent {
		# may not open text files
		$mbar.file.m entryconfigure 0 -state disabled
		# may not edit project
		$mbar.project.m entryconfigure 1 -state disabled
		# may not edit project settings
		$mbar.project.m entryconfigure 5 -state disabled
		# may not close project
		$mbar.project.m entryconfigure 7 -state disabled
		# may not access debugger
		$mbar.debug configure -state disabled
		$tools subwidget loadDebug configure -state disabled
		# may not access simulation actions
		$mbar.simulation configure -state disabled
		$tools subwidget updateSettings configure -state disabled
		$tools subwidget startSimulation configure -state disabled
		wm title $context Xenoscope
		# no cached windows at startup
		$mbar.window configure -state disabled
		# no RecentProjects
		$mbar.file.m entryconfigure 2 -state disabled
	    }

	    OpenProjectEvent -
	    ProjectUpdateEvent {
		# may edit project
		$mbar.project.m entryconfigure 1 -state normal
		# may edit project settings
		$mbar.project.m entryconfigure 5 -state normal
		# may close project
		$mbar.project.m entryconfigure 7 -state normal
		# may access debugger if executable seems valid
		set progfile [set Project:settings(Executable)]
		set progpath [TkRequest $context CanonicalizePath ${progfile}]
		if {$progfile != {} && \
			[file isfile $progpath] == 1 && \
			[file executable $progpath] == 1} {
		    # may access debugger actions
		    $mbar.debug configure -state normal
		    $tools subwidget loadDebug configure -state normal
		    # may access simulation actions
		    $mbar.simulation configure -state normal
		    $tools subwidget startSimulation configure -state normal
		} {
		    # may not access debugger actions
		    $mbar.debug configure -state disabled
		    $tools subwidget loadDebug configure -state disabled
		    # may not access simulation actions
		    $mbar.simulation configure -state disabled
		    $tools subwidget startSimulation configure -state disabled
		}
		# may configure the simulation
		$tools subwidget updateSettings configure -state normal
		# may not break/restart/stop debuggee
		$mbar.debug.m entryconfigure 3 -state disabled
		$mbar.debug.m entryconfigure 5 -state disabled
		$mbar.debug.m entryconfigure 6 -state disabled
		# may not hold simulation
		$mbar.simulation.m entryconfigure 1 -state disabled
		# may not release simulation
		$mbar.simulation.m entryconfigure 2 -state disabled
		# may not inspect simulation
		$mbar.simulation.m entryconfigure 3 -state disabled
		# may not trace simulation
		$mbar.simulation.m entryconfigure 4 -state disabled
		# may not access simulation timers
		$mbar.simulation.m entryconfigure 5 -state disabled
		# may not restart/kill simulation
		$mbar.simulation.m entryconfigure 7 -state disabled
		$mbar.simulation.m entryconfigure 8 -state disabled
		set projname [file rootname [file tail [set Workspace:session(CurrentProject)]]]
		wm title $context "Xenoscope: $projname"
	    }
	
	    CloseProjectEvent {
		# may not edit project
		$mbar.project.m entryconfigure 1 -state disabled
		# may not edit project settings
		$mbar.project.m entryconfigure 5 -state disabled
		# may not close project
		$mbar.project.m entryconfigure 7 -state disabled
		# may not access debugger
		$mbar.debug configure -state disabled
		$tools subwidget loadDebug configure -state disabled
		# may not access simulation actions
		$mbar.simulation configure -state disabled
		$tools subwidget updateSettings configure -state disabled
		$tools subwidget startSimulation configure -state disabled
		wm title $context Xenoscope
	    }
	    
	    SimulationStartedEvent {
		# may not access project actions or change
		# current project.
		$mbar.project configure -state disabled
		$tools subwidget openProject configure -state disabled
		$mbar.file.m entryconfigure 2 -state disabled
		# may not open source files
		$mbar.file.m entryconfigure 0 -state disabled
		# may not access debug actions (but restart if !runOnce)
		$mbar.debug.m entryconfigure 0 -state disabled
		$mbar.debug.m entryconfigure 1 -state disabled
		$mbar.debug.m entryconfigure 6 -state disabled
		$tools subwidget loadDebug configure -state disabled
		# may not start simulation
		$mbar.simulation.m entryconfigure 0 -state disabled
		$tools subwidget startSimulation configure -state disabled
		# may hold simulation
		$mbar.simulation.m entryconfigure 1 -state normal
		$controls subwidget holdSimulation configure -state normal
		# may not release simulation
		$mbar.simulation.m entryconfigure 2 -state disabled
		$controls subwidget releaseSimulation configure -state disabled
		# may restart simulation, but if running in "self-exit" mode
		global Workspace:runOnce
		if {${Workspace:runOnce} == 0} {
		    $mbar.debug.m entryconfigure 5 -state normal
		    $mbar.simulation.m entryconfigure 7 -state normal
		}
		# may kill simulation
		$mbar.simulation.m entryconfigure 8 -state normal
	    }

	    SimulationHeldEvent {
		# may not hold simulation
		$mbar.simulation.m entryconfigure 1 -state disabled
		$controls subwidget holdSimulation configure -state disabled
		# may release simulation
		$mbar.simulation.m entryconfigure 2 -state normal
		$controls subwidget releaseSimulation configure -state normal
		# update status icon
		set icon [Monitor:getStopIcon]
		$context.mtoolbar.status config -image [fetchImage $icon]
	    }

	    SimulationReleasedEvent {
		# may hold simulation
		$mbar.simulation.m entryconfigure 1 -state normal
		$controls subwidget holdSimulation configure -state normal
		# may not release simulation
		$mbar.simulation.m entryconfigure 2 -state disabled
		$controls subwidget releaseSimulation configure -state disabled
		# update status icon
		$context.mtoolbar.status config -image [fetchImage runflip]
	    }

	    SimulationWarmEvent {
		# display status icon
		pack $context.mtoolbar.status -expand no \
		    -padx 6 -pady 4 -side right
		# display speed control spinbox
		pack $context.mtoolbar.speed -expand no -anchor e \
		    -padx 0 -pady 4 -side right
		# Warm and Finished events are shared between standalone
		# and debug running modes.
		# may access simulation controls
		pack $controls -expand no -padx 6 -pady 4 -side right
		$controls config -state normal
		# display simulation clock
		pack $context.mtoolbar.clock -expand no -anchor e \
		    -padx 10 -pady 4 -side left
		# enable speed spinbox and reset its value to the max.
		$context.mtoolbar.speed.control config -state normal
		$context.mtoolbar.speed.control config -value 10

		global Monitor:standaloneRun

		if {${Monitor:standaloneRun} == 1} {
		    # may not re-access inspector's window (i.e. always visible)
		    $mbar.simulation.m entryconfigure 3 -state disabled
		    $controls subwidget inspectSimulation config -state disabled
		} {
		    # may inspect simulation through inspector's window
		    $mbar.simulation.m entryconfigure 3 -state normal
		}
		# may trace simulation
		$mbar.simulation.m entryconfigure 4 -state normal
		# may access simulation timers
		$mbar.simulation.m entryconfigure 5 -state normal
	    }

	    SimulationReadyEvent {
		# restore timers
		TimerManager:restoreTimers $context
		# restore main displays
		Workspace:restoreDisplays $context
	    }

	    SimulationFinishedEvent {
		global Monitor:standaloneRun
		# may not hold simulation (using the simulation controls)
		$controls subwidget holdSimulation config -state disabled
		# may not hold simulation (using Simulation menu)
		$mbar.simulation.m entryconfigure 1 -state disabled
		# may not access simulation timers (using the simulation controls)
		$controls subwidget timerManager config -state disabled
		# may not access simulation timers (using Simulation menu)
		$mbar.simulation.m entryconfigure 5 -state disabled
		if {${Monitor:standaloneRun} != 1} {
		    # may not break debuggee (using Debug menu)
		    $mbar.debug.m entryconfigure 3 -state disabled
		}
		# disable speed spinbox
		$context.mtoolbar.speed.control config -state disabled
		# update status icon
		$context.mtoolbar.status config -image [fetchImage done]
	    }

 	    SimulationKilledEvent {
		# may access project actions
		$mbar.project configure -state normal
		$tools subwidget openProject configure -state normal
		# may open source files
		$mbar.file.m entryconfigure 0 -state normal
		global Workspace:session
		if {[set Workspace:session(RecentProjects)] != {}} {
		    $mbar.file.m entryconfigure 2 -state normal
		}
		# may access debug actions
		$mbar.debug.m entryconfigure 0 -state normal
		$mbar.debug.m entryconfigure 1 -state normal
		$mbar.debug.m entryconfigure 5 -state disabled
		$mbar.debug.m entryconfigure 6 -state disabled
		$tools subwidget loadDebug configure -state normal
		# may start simulation
		$mbar.simulation.m entryconfigure 0 -state normal
		$tools subwidget startSimulation configure -state normal
		# may not hold simulation
		$mbar.simulation.m entryconfigure 1 -state disabled
		# may not release simulation
		$mbar.simulation.m entryconfigure 2 -state disabled
		# may not inspect simulation
		$mbar.simulation.m entryconfigure 3 -state disabled
		# may not trace simulation
		$mbar.simulation.m entryconfigure 4 -state disabled
		# may not access simulation timers
		$mbar.simulation.m entryconfigure 5 -state disabled
		# may not restart/kill simulation
		$mbar.simulation.m entryconfigure 7 -state disabled
		$mbar.simulation.m entryconfigure 8 -state disabled
 	    }

	    DebuggerStartedEvent {
		# may open text files
		$mbar.file.m entryconfigure 0 -state normal
		# may not access project actions
		$mbar.project configure -state disabled
		$tools subwidget openProject configure -state disabled
		$mbar.file.m entryconfigure 2 -state disabled
		# may only access configuration (never disabled) and
		# restart/kill entries
		$mbar.simulation.m entryconfigure 0 -state disabled
		$mbar.simulation.m entryconfigure 1 -state disabled
		$mbar.simulation.m entryconfigure 2 -state disabled
		$mbar.simulation.m entryconfigure 3 -state disabled
		$mbar.simulation.m entryconfigure 4 -state disabled
		$mbar.simulation.m entryconfigure 5 -state disabled
		# may restart simulation, but if running in "self-exit" mode
		global Workspace:runOnce
		if {${Workspace:runOnce} == 0} {
		    $mbar.simulation.m entryconfigure 7 -state normal
		}
		$mbar.simulation.m entryconfigure 8 -state normal
		# cannot start simulation through toolbar
		$tools subwidget startSimulation configure -state disabled
		# may not load nor run debuggee
		$mbar.debug.m entryconfigure 0 -state disabled
		$mbar.debug.m entryconfigure 1 -state disabled
		$tools subwidget loadDebug configure -state disabled
		# may not break debuggee (until the monitor is up)
		$mbar.debug.m entryconfigure 3 -state disabled
		# may restart debuggee, but if running in "self-exit" mode
		if {${Workspace:runOnce} == 0} {
		    $mbar.debug.m entryconfigure 5 -state normal
		}
		# may stop debugger
		$mbar.debug.m entryconfigure 6 -state normal
	    }

	    DebuggerAbortEvent - 
	    DebuggerStoppedEvent {
		# may not open text files
		$mbar.file.m entryconfigure 0 -state disabled
		# may access project actions
		$mbar.project configure -state normal
		$tools subwidget openProject configure -state normal
		global Workspace:session
		if {[set Workspace:session(RecentProjects)] != {}} {
		    $mbar.file.m entryconfigure 2 -state normal
		}
		# reset simulation actions
		$mbar.simulation.m entryconfigure 0 -state normal
		$mbar.simulation.m entryconfigure 1 -state disabled
		$mbar.simulation.m entryconfigure 2 -state disabled
		$mbar.simulation.m entryconfigure 3 -state disabled
		$mbar.simulation.m entryconfigure 4 -state disabled
		$mbar.simulation.m entryconfigure 5 -state disabled
		$mbar.simulation.m entryconfigure 7 -state disabled
		$mbar.simulation.m entryconfigure 8 -state disabled
		$tools subwidget startSimulation configure -state normal
		# may load or run debuggee
		$mbar.debug.m entryconfigure 0 -state normal
		$mbar.debug.m entryconfigure 1 -state normal
		$tools subwidget loadDebug configure -state normal
		# may not break debuggee
		$mbar.debug.m entryconfigure 3 -state disabled
		# may not stop/restart debugger
		$mbar.debug.m entryconfigure 5 -state disabled
		$mbar.debug.m entryconfigure 6 -state disabled
	    }

	    DebuggeeHeldEvent {
		global Debugger:childState
		# may not break debuggee
		$mbar.debug.m entryconfigure 3 -state disabled
		# may not hold simulation (using the simulation controls)
		$controls subwidget holdSimulation configure -state disabled
		if {${Debugger:childState} == "released"} {
		    # may release simulation (using the simulation controls)
		    # (unless child is in a zombie state)
		    $controls subwidget releaseSimulation configure -state normal
		}
	    }

	    DebuggeeReleasedEvent {
		global Monitor:channel
		# may break debuggee (if the monitor is up)
		if {${Monitor:channel} != {}} {
		    $mbar.debug.m entryconfigure 3 -state normal
		    # may hold simulation (using the simulation controls)
		    $controls subwidget holdSimulation configure -state normal
		    # may not release simulation (using the simulation controls)
		    $controls subwidget releaseSimulation configure -state disabled
		}
	    }

	    DebuggerExceptionEvent {
		# may access simulation controls
		$controls configure -state disabled
		# may not hold simulation (using Simulation menu)
		$mbar.simulation.m entryconfigure 1 -state disabled
		# may not break debuggee (using Debug menu)
		$mbar.debug.m entryconfigure 3 -state disabled
		# disable speed spinbox
		$context.mtoolbar.speed.control config -state disabled
		# may not inspect simulation
		$mbar.simulation.m entryconfigure 3 -state disabled
		# may not trace simulation
		$mbar.simulation.m entryconfigure 4 -state disabled
		# may not access simulation timers
		$mbar.simulation.m entryconfigure 5 -state disabled
		# update status icon
		$context.mtoolbar.status config -image [fetchImage brkcrash]
	    }

	    MonitorConnectEvent {
		global Monitor:simulationState
		# may break debuggee (if still released)
		if {${Monitor:simulationState} == "released"} {
		    $mbar.debug.m entryconfigure 3 -state normal
		}
		# may hold simulation
		$mbar.simulation.m entryconfigure 1 -state normal
	    }

 	    MonitorShutdownEvent {
		# save timers then destroy timer manager
		TimerManager:saveTimers $context
		TimerManager:destroy $context
		# save display status
		global Monitor:initState
		if {${Monitor:initState} == "ok"} {
		    Workspace:saveDisplays $context
		}
 	    }

 	    MonitorDisconnectEvent {
		# may not break debuggee
		$mbar.debug.m entryconfigure 3 -state disabled
		# may not hold simulation
		$mbar.simulation.m entryconfigure 1 -state disabled
		# may not release simulation
		$mbar.simulation.m entryconfigure 2 -state disabled
		# may not access simulation controls
		pack forget $controls
		# hide simulation clock & speed
		pack forget $context.mtoolbar.clock
		pack forget $context.mtoolbar.speed
		pack forget $context.mtoolbar.status
 	    }

	    TimeUpdateEvent {
		global Monitor:currentTime Workspace:runIcons
		global Workspace:statusFlip Monitor:simulationState
		$context.mtoolbar.clock config -text \
		    [format "Time: %s" ${Monitor:currentTime}]
		if {${Monitor:simulationState} == "released"} {
		    # flicker status
		    set nth ${Workspace:statusFlip}
		    $context.mtoolbar.status config -image [set Workspace:runIcons($nth)]
		    set nth [expr 1 - $nth]
		    set Workspace:statusFlip $nth
		}
	    }

	    WorkspaceQuitEvent {
		Session:save $context
	    }
	}
    }
}
