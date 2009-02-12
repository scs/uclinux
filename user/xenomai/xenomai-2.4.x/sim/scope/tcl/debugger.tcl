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
# GDB state among "dead" or "alive"
set Debugger:state dead
# Debug frame to parent context array: f2c($debugfrm)
set Debugger:f2c(0) {}
# Context to debug frames array: c2f($context)
set Debugger:c2f(0) {}
# Debug frame to its subwindows: f2w($debugfrm,wintype)
set Debugger:f2w(0,0) ""
# Current source file displayed in debug frame: f2s($debugfrm)
set Debugger:f2s(0) ""
# Source file of last updated PC: pcfile($debugfrm)
set Debugger:pcfile(0) {}
# Line number within pcfile of last updated PC: pcline($debugfrm)
set Debugger:pcline(0) {}
# View position within visited source files (never cleared): fpos($path)
set Debugger:fpos(-) {}
# File access cache, last 8 pathes kept
set Debugger:fcache {}
# Current focus tracked by debug frame: focus($debugfrm) may contain
# "system" or a numeric value standing for and internal thread
# identifier (i.e. oid)
set Debugger:focus(0) 0
# Last executing context, which can be different from the
# focus() value if a specific thread focus in currently in effect.
# This context is of the form { type numid1 numid2 }
# as returned by the VRTOS monitor answering a GetContext
# request.
set Debugger:xcontext(0) {}
# current stack information obtained on a debug context
# since the last breakpoint hit 
set Debugger:stackinfo(0) {}
# length of current call chain information (i.e. stackinfo)
set Debugger:stacklength(0) {}
# local data information obtained on a debug context
set Debugger:localinfo(0,0) {}
# current frame number since last focus update (including up/down)
set Debugger:stacklevel(0) {}
# current state of debuggee among "dead", "held", "released" or "zombie"
set Debugger:childState dead
# the event which made the debuggee enter the zombie state
set Debugger:zombieCause {}
# serial id for secondary debug frames - starts at 2
set Debugger:fserial 2
# Known threads list {threadID threadName threadEntry}
set Debugger:threadlist {}
# Host workspace context of debugger context
set Debugger:workspace(0) {}
# Flag telling whether the configuration has changed.
set Debugger:configHasChanged false
# Last search-string information from debug frame
set Debugger:searchinfo(0,0) {}
# Misc. information about the simulated system
# syspecs currenty is: {threadTypeName}
set Debugger:syspecs {}
# Operating debug frame (i.e. the last for which were invoked
# trace commands)
set Debugger:operating {}
# Thread lock flag set for frame
set Debugger:lockview(0) 0
# Last hot symbol marked
set Debugger:hotSymbol {}
# The array of per-frame hot symbol evaluation timers
set Debugger:symbolEvalTimer(0) {}
# List of breakpoints; each element is a sublist describing
# a breakpoint: { focus state bpnum file lineno condition [systeminfo] }
set Debugger:bplist {}
# identifier of pending oneshot bp
set Debugger:bpOneshot {}

proc Debugger:initialize {context workspace pipeout} {

    global Workspace:statusBar Debugger:operating
    global Debugger:main Debugger:pipeout

    # create main debug window in workspace
    set Debugger:operating $context
    set Debugger:main $context
    set Debugger:pipeout $pipeout
    Debugger:createDebugFrame $context $context $workspace
    pack $context.window -side bottom -expand yes -fill both
    pack $context -before ${Workspace:statusBar} -expand yes -fill both
    global $context:statusMsg
    trace variable $context:statusMsg w "Debugger:routeMainStatus $context"

    # register trace hook to get informed of major context changes
    traceEvent Application:event \
	globalEventQueue:$context \
	"Debugger:processGlobalEvent $context"

    # trigger initialization event
    pushEvent Application:event InitDebuggerEvent
}

proc Debugger:createDebugFrame {context debugfrm workspace} {

    global Debugger:f2c Debugger:c2f Debugger:f2s Debugger:f2w
    global Debugger:pcline Debugger:pcfile
    global Debugger:xcontext Debugger:focus
    global Debugger:stackinfo Debugger:stacklength
    global Debugger:localinfo Debugger:stacklevel
    global Debugger:workspace Debugger:lockview
    global Debugger:symbolEvalTimer
    global tixOption

    # save host workspace handle for this frame
    set Debugger:workspace($debugfrm) $workspace
    
    set Debugger:f2c($debugfrm) $context
    lappend Debugger:c2f($context) $debugfrm
    set Debugger:f2s($debugfrm) {}
    set Debugger:pcfile($debugfrm) {}
    set Debugger:pcline($debugfrm) 0
    set Debugger:focus($debugfrm) system
    set Debugger:xcontext($debugfrm) {init 0 0 0}
    set Debugger:stackinfo($debugfrm) {}
    set Debugger:stacklength($debugfrm) {}
    set Debugger:stacklevel($debugfrm) 0
    set Debugger:symbolEvalTimer($debugfrm) {}
    set Debugger:lockview($debugfrm) 0

    frame $debugfrm
    bind $debugfrm <Destroy> "Debugger:closeDebugFrame %W $debugfrm"

    ### Toolbar frame

    frame $debugfrm.toolbar -width 600 -bd 1 -relief groove

    ## Tools shortcuts

    global $debugfrm:tools
    set $debugfrm:tools {}

    set tools $debugfrm.toolbar.tools

    tixSelect $tools -allowzero true -radio true \
	-variable $debugfrm:tools \
	-command "Debugger:toolbarExec $tools $debugfrm" \
	-options {
	    label.anchor e
	}

    $tools add stepover -image [fetchImage stepover]
    Workspace:addToolTip $tools stepover $debugfrm:statusMsg \
	"Step over" "Step over next statement (F10)" <Key-F10>

    $tools add stepinto -image [fetchImage stepinto]
    Workspace:addToolTip $tools stepinto $debugfrm:statusMsg \
	"Step into" "Step into next statement (F11)" <Key-F11>

    $tools add stepout -image [fetchImage stepout]
    Workspace:addToolTip $tools stepout $debugfrm:statusMsg \
	"Step out" "Step out current function (F12)" <Key-F12>

    $tools add cont -image [fetchImage cont]
    Workspace:addToolTip $tools cont $debugfrm:statusMsg \
	"Continue" "Resume execution (F5)" <Key-F5>

    $tools add xbreak -image [fetchImage break]
    Workspace:addToolTip $tools xbreak $debugfrm:statusMsg \
	"Stop" "Suspend execution (F6)" <Key-F6>

    $tools add up -image [fetchImage up]
    Workspace:addToolTip $tools up $debugfrm:statusMsg \
	"Up stack" "Move stack pointer upward (to outer frames)"

    $tools add down -image [fetchImage down]
    Workspace:addToolTip $tools down $debugfrm:statusMsg \
	"Down stack" "Move stack pointer downward (to inner frames)"

    $tools add breakpoints -image [fetchImage stoplst]
    Workspace:addToolTip $tools breakpoints $debugfrm:statusMsg \
	"Breakpoints" "Edit breakpoints"

    $tools add watchpoints -image [fetchImage watchlst]
    Workspace:addToolTip $tools watchpoints $debugfrm:statusMsg \
	"Watchpoints" "Edit watchpoints"

    $tools add globals -image [fetchImage globals]
    Workspace:addToolTip $tools globals $debugfrm:statusMsg \
	"Globals" "Display global symbols"

    $tools add examine -image [fetchImage examine]
    Workspace:addToolTip $tools examine $debugfrm:statusMsg \
	"Examine" "Examine memory and evaluate expressions"

    $tools add thrlock -image [fetchImage thrlock]
    Workspace:addToolTip $tools thrlock $debugfrm:statusMsg \
	"Follow thread" "Lock focus on current thread"

    $tools add newframe -image [fetchImage newfrm]
    Workspace:addToolTip $tools newframe $debugfrm:statusMsg \
	"New frame" "Open new debug window"

    pack $tools -anchor w -padx 4 -pady 4 -side left

    ## Switches

    global $debugfrm:switches
    set $debugfrm:switches {}

    # warning: this variable name is used for bindings later
    # in this proc.
    set switches $debugfrm.toolbar.switches

    tixSelect $switches -allowzero true -radio false \
	-command "Debugger:toolbarSwitch $debugfrm" \
	-variable $debugfrm:switches \
	-selectedbg $tixOption(dark1_bg) \
	-options {
	    label.anchor e
	}

    pack $switches -anchor e -padx 6 -pady 4 -side right

    $switches add stack -image [fetchImage stack]
    Workspace:addToolTip $switches stack $debugfrm:statusMsg \
	"Stack" "Toggle backtrace display window"
    $switches add locals -image [fetchImage locals]
    Workspace:addToolTip $switches locals $debugfrm:statusMsg \
	"Locals" "Toggle locals display window"
    $switches add asynch -image [fetchImage asynch]
    Workspace:addToolTip $switches asynch $debugfrm:statusMsg \
	"Trace asynch." "Toggle asynchronous contexts trace"

    ## source file commands

    global $debugfrm:factions
    set $debugfrm:factions {}

    set srcmd [frame $debugfrm.toolbar.srcmd -bd 0 -relief flat]
    pack $srcmd -side right -fill both
    set filecmd $srcmd.factions

    tixSelect $filecmd -allowzero true -radio true \
	-variable $debugfrm:factions \
	-command "Debugger:toolbarExec $filecmd $debugfrm" \
	-options {
	    label.anchor e
	}

    $filecmd add resynch -image [fetchImage resynch]
    Workspace:addToolTip $filecmd resynch $debugfrm:statusMsg \
	"Show next statement" "Show next executable statement"

    $filecmd add reload -image [fetchImage reload]
    Workspace:addToolTip $filecmd reload $debugfrm:statusMsg \
	"Reload file" "Reload current source file"

    menubutton $srcmd.fstack -image [fetchImage files] \
	-takefocus 0 -indicatoron yes -bd 1 -relief raised \
	-menu $srcmd.fstack.m

    menu $srcmd.fstack.m -tearoff false \
	-relief raised -bd 2 \
	-postcommand "Debugger:buildSourceStack $debugfrm $srcmd.fstack.m"

    Workspace:addToolTipSimple $srcmd.fstack \
	$debugfrm:statusMsg \
	"Recent files" "Visit recent files"

    pack $srcmd.fstack -side right -padx 0 -ipady 1
    pack $filecmd -side right -padx 0

    # Selectors frame
    frame $debugfrm.selectors -width 600 -bd 1 -relief groove

    ## focus selector

    global $debugfrm:focus
    set $debugfrm:focus {}

    tixComboBox $debugfrm.selectors.focus -label "Focus " -dropdown true \
	-command "Debugger:setFocus $debugfrm" \
	-editable false \
	-variable $debugfrm:focus \
	-grab local \
	-history false \
	-options {
	    slistbox.scrollbar auto
	    listbox.height 12
	    listbox.width 30
	    label.width 6
	    label.anchor w
	}

    $debugfrm.selectors.focus subwidget entry configure -width 20
    Debugger:clearFocus $debugfrm
    pack $debugfrm.selectors.focus -padx 5 -side left

    ## Tick count display

    global $debugfrm:tickval
    set $debugfrm:tickval {}

    label $debugfrm.selectors.ticks -textvariable $debugfrm:tickval
    pack $debugfrm.selectors.ticks -padx 5 -side left

    ## Scratchpad

    global $debugfrm:scratchpad
    set $debugfrm:scratchpad {}

    tixComboBox $debugfrm.selectors.scratchpad \
	-variable $debugfrm:scratchpad \
	-label {} \
	-labelside left \
	-dropdown true \
	-editable true \
	-grab local \
	-history true \
	-prunehistory true \
	-options {
	    slistbox.scrollbar auto
	    listbox.height 6
	    listbox.width 21
	    label.padX 0
	    entry.width 21
	}

    pack $debugfrm.selectors.scratchpad -padx 5 -side right

    ### Msg frame

    frame $debugfrm.messages -width 600 -bd 1 -relief groove
    label $debugfrm.messages.location -text {} -anchor e
    label $debugfrm.messages.warning -text {} -anchor e
    pack $debugfrm.messages.location -side left -padx 4
    pack $debugfrm.messages.warning -side right -padx 4

    ### Main Paned Window

    tixPanedWindow $debugfrm.window -orientation vertical 

    set p1 [$debugfrm.window add p1 -min 70 -expand 0.85]
    set p2 [$debugfrm.window add p2 -min 70 -expand 0.15]

    ### Source pane

    tixScrolledText $p1.source -height 300 -width 600 -options {
	text.spacing1 0
	text.spacing3 0
	text.state disabled
	text.font SourceFont
    }
    set text [$p1.source subwidget text]
    pack $p1.source -expand yes -fill both
    set Debugger:f2w($debugfrm,source) $text
    # force focus on the text widget upon Mouse-click 1. Having it disabled
    # seems to prevent the defaut binding to be applied. So help ourselves.
    bind $text <1> "+ focus $text"
    bind $text <Motion> "+ Debugger:lookupWord $debugfrm $text %x %y %X %Y"
    bind $text <Control-Button-1> "+ Debugger:lookupSymbol $debugfrm"
    rearrangeBindings $text

    set popup $text.popup
    backmenu $popup -tearoff 0
    $popup validate "Debugger:postSourceMenu $debugfrm"
    $popup bind $text

    ### Data pane

    #### Data Paned SubWindow

    tixPanedWindow $p2.data -orientation horizontal \
	-dynamicgeometry false
    pack $p2.data -expand yes -fill both
    set Debugger:f2w($debugfrm,data) $p2.data

    #### Stack pane
    set subp1 [$p2.data add stack -expand 0.50 -min 200]
    tixScrolledListBox $subp1.stack -scrollbar auto \
	-browsecmd "Debugger:browseStack $debugfrm"
    set lbox [$subp1.stack subwidget listbox]
    bind $lbox <1> "+ focus $lbox"
    pack $subp1.stack -expand yes -fill both
    set Debugger:f2w($debugfrm,stack) $subp1.stack
    $p2.data forget stack
    bind $lbox <Escape> "$switches invoke stack"

    #### Locals pane
    set subp2 [$p2.data add locals -expand 0.50 -min 200]
    DataDisplay:makeLocalsTree $debugfrm $subp2.locals
    set Debugger:f2w($debugfrm,locals) $subp2.locals
    $p2.data forget locals
    bind [$subp2.locals subwidget hlist] <Escape> "$switches invoke locals"
}

proc Debugger:displayWallPaper {context} {

    global Debugger:workspace Debugger:f2w

    set wsmbar [set Debugger:workspace($context)].mbar
    set textw [set Debugger:f2w($context,source)]
    set wallpaper [canvas $textw.wallpaper]
    bind $wallpaper <Configure> \
	"+ Debugger:resizeWallPaper $context $wallpaper %w %h"
    pack $wallpaper -expand yes -fill both
}

proc Debugger:removeWallPaper {context} {

    global Debugger:f2w
    set textw [set Debugger:f2w($context,source)]
    catch { destroy $textw.wallpaper }
}

proc Debugger:resizeWallPaper {context wallpaper w h} {

    global Debugger:workspace Project:settings

    catch { $wallpaper delete plaid }

    if {[set Project:settings(Preferences,displaywp)] == 1} {
	set bgimage [fetchImage [set Project:settings(Preferences,wallpaper)]]
	if {$bgimage != {}} {
	    set y 0
	    while {$y < $h} {
		set x 0
		while {$x < $w} {
		    $wallpaper create image $x $y -image $bgimage -anchor nw -tag plaid
		    set x [expr $x + [image width $bgimage]]
		}
		set y [expr $y + [image height $bgimage]]
	    }
	}
    }
}

proc Debugger:createSecondaryFrame {context} {

    global Debugger:fserial Debugger:workspace

    regexp "^(.*)\\..*$" $context mvar root
    set w $context.frm${Debugger:fserial}
    toplevel $w
    wm title $w [format "%s #%d" [wm title $root] ${Debugger:fserial}]
    wm geometry $w 700x600
    cascadeWindow $w
    set mbar [frame $w.mbar -bd 1 -relief raised]
    pack $mbar -fill x

    menubutton $mbar.file -text File \
	-menu $mbar.file.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.file.m -tearoff false

    $mbar.file.m add command -label Close \
	-command "destroy $w" \
	-underline 0

    pack $mbar.file -side left

    set debugfrm $w.f
    Debugger:createDebugFrame \
	$context $debugfrm [set Debugger:workspace($context)]
    pack $debugfrm.toolbar -side top -expand no -fill x
    pack $debugfrm.selectors -expand no -fill x
    pack $debugfrm.messages -expand no -fill x
    pack $debugfrm.window -expand yes -fill both
    # create local status bar
    global $debugfrm:statusMsg
    frame $debugfrm.status -height 20 -relief groove -bd 1
    pack $debugfrm.status -fill x
    label $debugfrm.status.message -textvariable $debugfrm:statusMsg
    pack $debugfrm.status.message -side left
    # pack it all
    pack $debugfrm -expand yes -fill both

    tkwait visibility $w

    incr Debugger:fserial
    if {[Debugger:resume $context] != "false"} {
	Debugger:updateFocus $debugfrm {}
	Debugger:suspend $context
	Debugger:updateThreads $debugfrm
	$debugfrm.selectors.focus pick 0
    }
}

proc Debugger:destroySecondaryFrame {debugfrm} {

    regexp "^(.*)\\.f$" $debugfrm mvar root
    destroy $root
}

proc Debugger:toolbarExec {toolbar debugfrm button state} {

    # a little trick to have the tix select widget
    # behave like a toolbar: a selected button is
    # immediately re-invoked to restore its initial
    # graphic state. This is why the button state is
    # checked to filter out "off" invocations.

    if {$state == 1} {

	$toolbar invoke $button
	if {[$toolbar subwidget $button cget -state] == "disabled"} {
	    # this can occur if triggered thru a function key
	    # whose bindings are never disabled. So we need to
	    # test the corresponding button's state to confirm
	    # the operation.
	    return
	}

	global Debugger:f2c Debugger:operating
	global Debugger:stacklevel Debugger:stackinfo
	global Debugger:stacklength $debugfrm:statusMsg

	set Debugger:operating $debugfrm
	set $debugfrm:statusMsg {}

	# clear last warning (if any)
	$debugfrm.messages.warning configure -text {}
	set context [set Debugger:f2c($debugfrm)]

	switch $button {
	    up {
		set level [set Debugger:stacklevel($debugfrm)]

		if {[expr $level + 1] >= [set Debugger:stacklength($debugfrm)]} {
		    # already at outer level
		    $debugfrm.messages.warning configure \
			-text "Outer frame reached - cannot go up"
		    bell -displayof $debugfrm
		    return
		}
		incr Debugger:stacklevel($debugfrm)
		Debugger:displayStackFrame $debugfrm
	    }

	    down {
		set level [set Debugger:stacklevel($debugfrm)]

		if {$level <= 0} {
		    # already at inner level
		    $debugfrm.messages.warning configure \
			-text "Inner frame reached - cannot go down"
		    bell -displayof $debugfrm
		    return
		}
		incr Debugger:stacklevel($debugfrm) -1
		Debugger:displayStackFrame $debugfrm
	    }

	    stepover {
		# fetch command appropriate to initiate a step over
		# the instruction pointed by the current debugging
		# focus for this debug frame...
		set focuscmd [Debugger:buildStepCmd $debugfrm]
		TkRequest $context StepOver $focuscmd
	    }

	    stepinto {
		# fetch command appropriate to initiate a step into
		# the instruction pointed by the current debugging
		# focus for this debug frame...
		set focuscmd [Debugger:buildStepCmd $debugfrm]
		TkRequest $context StepInto $focuscmd
	    }
	    
	    stepout {
		# fetch command appropriate to initiate a step out
		# the last traced context...
		set focuscmd [Debugger:buildStepCmd $debugfrm]
		TkRequest $context StepOut $focuscmd
	    }
	    
	    cont {
		TkRequest $context ContSimulation
	    }

	    xbreak {
		TkRequest $context HoldSimulation
	    }

	    breakpoints {
		Debugger:editBreakpoints $debugfrm
	    }

	    watchpoints {
		Debugger:editWatchpoints $debugfrm
	    }

	    globals {
		DataDisplay:showGlobals $context
	    }

	    examine {
		Examiner:popup $context
	    }

	    thrlock {
		Debugger:setThreadLock $debugfrm
	    }

	    newframe {
		Debugger:createSecondaryFrame $context
	    }

	    resynch {
		Debugger:sourceSynch $debugfrm
	    }

	    reload {
		Debugger:sourceReload $debugfrm
	    }

	    default {
		gdb:$button $context
	    }
	}
    }
}

proc Debugger:toolbarSwitch {debugfrm button state} {

    global $debugfrm:statusMsg

    set $debugfrm:statusMsg {}

    if {$state == 1} {
	# Toggle on
	if {[$debugfrm.toolbar.switches \
		 subwidget $button cget -state] == "disabled"} {
	    # this can occur if triggered thru a function key
	    # which bindings are never disabled. So we need to
	    # test the corresponding button's state to confirm
	    # the operation.
	    return
	}
	switch -- $button {
	    stack {
		Debugger:showStack $debugfrm
	    }
	    locals {
		Debugger:showLocals $debugfrm
	    }
	}
    } {
	# Toggle off
	switch -- $button {
	    stack {
		Debugger:hideStack $debugfrm
	    }
	    locals {
		Debugger:hideLocals $debugfrm
	    }
	}
    }
}

proc Debugger:closeDebugFrame {wdestroyed w} {

    if {$wdestroyed == $w} {

	global Debugger:f2c Debugger:c2f Debugger:f2w
	global Debugger:f2s Debugger:pcfile Debugger:pcline
	global Debugger:focus Debugger:xcontext
	global Debugger:stackinfo Debugger:stacklevel
	global Debugger:stacklength Debugger:searchinfo
	global $w:tools $w:focus $w:scratchpad $w:switches
	global $w:statusMsg Debugger:workspace Debugger:operating

	# cancel the currently running eval timer (if any)
	Debugger:resetEvalTimer $w

	# Remove destroyed window from context's window list
	set context [set Debugger:f2c($w)]
	set n [lsearch -exact [set Debugger:c2f($context)] $w]
	set Debugger:c2f($context) \
	    [lreplace [set Debugger:c2f($context)] $n $n]

	if {${Debugger:operating} == $w} {
	    set Debugger:operating $context
	}

	# destroy current source pick window (if any) as it could
	# be attached to the destroyed frame
	catch { destroy $context.srcpick }

	# clear per-frame variables
	catch { unset Debugger:f2w($w,source) }
	catch { unset Debugger:f2w($w,data) }
	catch { unset Debugger:f2w($w,stack) }
	catch { unset Debugger:f2s($w) }
	catch { unset Debugger:pcfile($w) }
	catch { unset Debugger:pcline($w) }
	catch { unset Debugger:focus($w) }
	catch { unset Debugger:xcontext($w) }
	catch { unset Debugger:stackinfo($w) }
	catch { unset Debugger:stacklength($w) }
	catch { unset Debugger:stacklevel($w) }
	catch { unset Debugger:workspace($w) }
	catch { unset Debugger:searchinfo($w,searchwhence) }
	catch { unset Debugger:searchinfo($w,searchindex) }
	catch { unset $w:tools }
	catch { unset $w:focus }
	catch { unset $w:scratchpad }
	catch { unset $w:switches }
	catch { unset $w:statusMsg }
    }
}

proc Debugger:run {context flags} {

    global Debugger:state
    global Debugger:threadlist Debugger:pipeout
    global Debugger:configHasChanged Monitor:main
    global Debugger:childState Project:settings

    Monitor:tcpListen ${Monitor:main} [set Project:settings(ServerPort)]

    set args [Monitor:getMvmArgs $flags]

    unset Debugger:threadlist
    set Debugger:threadlist {}
    set Debugger:configHasChanged false
    
    pushEvent Application:event DebuggerStartedEvent
    $context.messages.location configure -text (Loading)

    if {[catch {set gdbPath [file nativename [set Project:settings(GdbPath)]]}] == 1} {
	# may be an invalid ~user syntax
	set gdbPath [set Project:settings(GdbPath)]
    }

    global Debugger:zombieCause
    set Debugger:zombieCause {}
    set Debugger:childState released
    set executable [set Project:settings(Executable)]
    set srcdirs [set Project:settings(SourceDirs)]

    if {[gdb:init $context $gdbPath $executable $args $srcdirs ${Debugger:pipeout}] != {}} {
	set Debugger:state alive
	Debugger:restoreGeometry $context
    } {
	set Debugger:childState dead
	pushEvent Application:event DebuggerAbortEvent
	return
    }

    gdb:run $context $args
    Debugger:listen $context Busy

    if {${Debugger:state} == "alive"} {
	Debugger:restoreSwitches $context
	Debugger:restoreScratchPad $context
    }
}

proc Debugger:stop {context} {

    global Debugger:state

    # ask driver to close the debug connection
    gdb:stop $context
    set Debugger:state dead
    # trigger appropriate event at a global level
    pushEvent Application:event DebuggerStoppedEvent
}

proc Debugger:exit {context {errmsg {}}} {

    global Debugger:state

    set Debugger:state dead
    update idletasks
    bell

    if {$errmsg != {}} {
	tk_messageBox \
	    -message "[string toupper gdb]: $errmsg" \
	    -type ok -icon error -title Error
    } {
	tk_messageBox \
	    -message "Application exited normally" \
	    -type ok -icon info -title Information
    }

    pushEvent Application:event DebuggerStoppedEvent
}

proc Debugger:visitFile {debugfrm filename} {

    if  {$filename != {}} {
	# if file is already known -- display it
	# then return...
	displaySource $debugfrm $filename
	return
    }

    # otherwise, open a file dialog to get its name...

    set dialog [tix filedialog tixExFileSelectDialog]
    $dialog config -command "Debugger:displaySource $debugfrm" \
	-title "Select a File"

    $dialog subwidget fsbox config -filetypes { \
	{{*.c}	{*.c  -- C source files}}
	{{*.h}	{*.h  -- C/C++ header files}}
	{{*.cc}	{*.cc  -- C++ source files}}
	{{*.C}	{*.C  -- C++ source files}}
	{{*.cpp}	{*.cpp  -- C++ source files}}
	{{*}		{*      -- All files}}
    }

    $dialog subwidget fsbox subwidget types pick 0
    cascadeWindow $dialog [winfo toplevel $debugfrm]
    $dialog popup
}

proc Debugger:buildSourceStack {debugfrm menu} {

    global Debugger:fcache Debugger:f2c
    global Debugger:fpos Debugger:pcfile
    global Debugger:f2s

    $menu delete 0 end

    if {${Debugger:fcache} == {}} {
	return
    }

    set context [set Debugger:f2c($debugfrm)]

    foreach file ${Debugger:fcache} {
	if {$file == [set Debugger:pcfile($debugfrm)]} {
	    set mark " * "
	} {
	    if {$file == [set Debugger:f2s($debugfrm)]} {
		set mark " + "
	    } {
		set mark "   "
	    }
	}
	$menu add command -label $mark[TkRequest $context GetUserPath $file] \
	    -command "Debugger:pickSource $debugfrm $file"
    }

    if {[expr [array size Debugger:fpos] - 1] > [llength ${Debugger:fcache}]} {
	# -1 because we need to substract the dummy entry '-'
	$menu add separator
	$menu add command -label "More..." \
	    -command "Debugger:pickSource $debugfrm {}"
    }
}

proc Debugger:pickSource {debugfrm filepath} {

    global Debugger:fpos Debugger:f2c Debugger:pcfile Debugger:f2s

    if {$filepath != {}} {
	Debugger:displaySource $debugfrm $filepath
	return
    }

    # if no file has been given, open a selection toplevel
    # to have the user pick the file among all known sources

    set flist [lsort -dictionary [array names Debugger:fpos]]

    set context [set Debugger:f2c($debugfrm)]
    set w $context.srcpick

    if {[winfo exists $w]} {
	destroy $w
    } 

    toplevel $w
    wm title $w "Source Files"
    cascadeWindow $w

    set f [frame $w.f]
    pack $f -expand yes -fill both

    tixScrolledListBox $f.list -scrollbar auto \
	-browsecmd "Debugger:pickSourceSel $debugfrm $f.list"
    set lbox [$f.list subwidget listbox]
    $lbox config -height 20 -width 60 -selectmode single
    pack $f.list -expand yes -fill both
    bind $w <Escape> "destroy $w"

    foreach filepath $flist {
	if {$filepath != "-"} {
	    if {$filepath == [set Debugger:pcfile($debugfrm)]} {
		set mark " * "
	    } {
		if {$filepath == [set Debugger:f2s($debugfrm)]} {
		    set mark " + "
		} {
		    set mark "   "
		}
	    }
	    $lbox insert end $mark$filepath
	}
    }

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "destroy $w"
    pack $w.bbox -fill x
}

proc Debugger:pickSourceSel {debugfrm listbox} {

    set lbox [$listbox subwidget listbox]
    set sel [$lbox curselection]

    if {$sel != {}} {
	set filepath [string range [$lbox get $sel] 3 end]
	Debugger:displaySource $debugfrm $filepath
    }
}

proc Debugger:cacheSourcePath {filepath} {

    global Debugger:fcache

    # insert the path of the just open source file into the cache
    # list, ensuring that no more than 8 entries are concurrently
    # kept...

    set cacheix [lsearch -exact ${Debugger:fcache} $filepath]

    if {$cacheix != -1} {
	set Debugger:fcache \
	    [lreplace ${Debugger:fcache} $cacheix $cacheix]
    }
    if {[llength ${Debugger:fcache}] >= 8} {
	set Debugger:fcache \
	    [lreplace ${Debugger:fcache} end end]
    }
    # LIFO ordering
    set Debugger:fcache \
	[linsert ${Debugger:fcache} 0 $filepath]
}

proc Debugger:sourceSynch {debugfrm} {

    global Debugger:pcfile

    set hotfile [set Debugger:pcfile($debugfrm)]

    if {$hotfile != {}} {
	Debugger:displaySource $debugfrm $hotfile
    }
}

proc Debugger:sourceReload {debugfrm} {

    global Debugger:f2s

    set filepath [set Debugger:f2s($debugfrm)]

    if {$filepath != {}} {
	Debugger:displaySource $debugfrm $filepath true
	$debugfrm.messages.warning configure \
	-text "[file tail $filepath] reloaded..."
    }
}

proc Debugger:displaySource {debugfrm filepath {freload false}} {

    global Debugger:f2c
    global Debugger:f2s
    global Debugger:f2w
    global Debugger:bplist
    global Project:settings
    global Debugger:fpos

    set oldpath [set Debugger:f2s($debugfrm)]

    if {$freload == "false" && $oldpath == $filepath} {
	# hotspot may have changed however -- try updating it
	Debugger:displayHotSpot $debugfrm
	return
    }

    # fetch back context and text widget of the designated
    # debug frame
    set context [set Debugger:f2c($debugfrm)]
    set textw [set Debugger:f2w($debugfrm,source)]

    if {$oldpath != {}} {
	set Debugger:fpos($oldpath) [$textw index @0,0]
    }
    set Debugger:f2s($debugfrm) $filepath

    $textw tag delete hotspot
    $textw configure -state normal
    $textw delete 1.0 end
    
    # Open the file, and read it into the text widget
    if {[catch {open $filepath} fh]} {
	# File can't be read.
	$textw configure -state disabled
	return
    }
    
    set lineno 1
    foreach line [split [read $fh] \n] {
	if {[set Project:settings(Options,lineNumbering)] == 1} {
	    $textw insert $lineno.0 [format "  \t%4d  %s\n" $lineno "$line"]
	} else {
	    $textw insert $lineno.0 "  \t$line\n"
	}
	incr lineno
    }

    catch {
	set oldpos [set Debugger:fpos($filepath)]
	# restore last view if the file used to be displayed
	$textw yview $oldpos
    }

    close $fh
    $textw configure -state disabled

    # insert breakpoint spots in the current source
    Debugger:plotBreakpoints $context $debugfrm

    # try to highlight the hotspot in this file
    Debugger:displayHotSpot $debugfrm

    # update the file position when the view is stable
    # if this is the first time this file is loaded
    if {[array get Debugger:fpos $filepath] == {}} {
	set Debugger:fpos($filepath) [$textw index @0,0]
    }

    # cache source file path
    Debugger:cacheSourcePath $filepath
}

proc Debugger:redisplaySources {context} {

    global Project:settings
    global Debugger:c2f
    global Debugger:f2s

    foreach debugfrm [set Debugger:c2f($context)] {
	Debugger:displaySource $debugfrm [set Debugger:f2s($debugfrm)] true
    }
}

proc Debugger:displayHotSpot {debugfrm} {

    global Debugger:f2s
    global Debugger:f2w
    global Debugger:pcfile
    global Debugger:pcline

    if {[set Debugger:f2s($debugfrm)] == [set Debugger:pcfile($debugfrm)]} {
	set textw [set Debugger:f2w($debugfrm,source)]
	$textw tag delete hotspot
	set pcline [set Debugger:pcline($debugfrm)]
	$textw tag add hotspot $pcline.1 $pcline.end
	global Application:visualType Project:settings
	if {${Application:visualType} == "color" &&
	    [set Project:settings(Options,useGlyphCursor)] == 0} {
	    $textw tag configure hotspot -background yellow
	} {
	    # use a cursor to mark the hotspot with monochrome displays
	    # or if the use of the glyph cursor has been otherwised forced.
	    set mark $textw.hotspot
	    catch { destroy $mark }
	    set image [fetchImage cursor]
	    label $mark -bd 0 -relief flat -padx 0 -pady 0 \
		-image $image -bg [$textw cget -bg]
	    $textw configure -state normal
	    $textw window create $pcline.1 -window $mark
	    $textw configure -state disabled
	}
	catch { $textw see $pcline.0 }
    }
}

proc Debugger:updateSource {debugfrm location {freload false}} {

    global Debugger:pcfile Debugger:pcline
    global Debugger:xcontext gdb:obsoleted

    set function [lindex $location 0]

    if {$function == "?"} {
	# function does not belong to the code location --
	# the latter is however the first viewable inner location
	# which is available for display. This is our best-effort
	# to show a familiar source to the user.
	set function [lindex $location 1]
	set filepath [lindex $location 2]
	set lineno [lindex $location 3]
	set besteffort true
    } {
	set filepath [lindex $location 1]
	set lineno [lindex $location 2]
	set besteffort false
    }

    # xxx:getproto{} should return a 2-element list of
    # the form { xlation-type name-to-display }
    # where the 1st one is a non-null number if a
    # translation occurred, zero otherwise, and the
    # second is the function name to display.

    set funinfo [gdb:getproto $function]
    set thread [Debugger:getContextInfo $debugfrm]
    set locmsg [format "$thread stopped in %s" [lindex $funinfo 1]]
    if {[lindex $funinfo 0] == 0} {
	# "call" operator need to be appended to regular
	# function names
	append locmsg "()"
    }

    # may have break in a spot with no debug information
    # available - check for it...

    if {$filepath != {}} {
	set filepath [getAbsolutePath $filepath]
	set Debugger:pcfile($debugfrm) $filepath
	set Debugger:pcline($debugfrm) $lineno
	Debugger:displaySource $debugfrm $filepath $freload

	if {$besteffort == "false"} {
	    append locmsg [format ", %s:%d" \
			       [file tail $filepath] $lineno]
	}
    }

    foreach {_ctx _iid imask ticks modeflags} \
	[set Debugger:xcontext($debugfrm)] {
	    if {$modeflags != {}} {
		if {$imask > 0} {
		    append locmsg " ($modeflags, imask=${imask})"
		} {
		    append locmsg " ($modeflags)"
		}
	    } {
		if {$imask > 0} {
		    append locmsg " (imask=${imask})"
		}
	    }
	    global $debugfrm:tickval
	    set $debugfrm:tickval "Ticks: $ticks"
	}

    $debugfrm.messages.location configure -text $locmsg

    if {${gdb:obsoleted} == "true"} {
	$debugfrm.messages.warning configure \
	    -text "Source file is more recent than executable"
	set gdb:obsoleted false
    }
}

proc Debugger:buildFocusCmd {debugfrm} {

    global Debugger:focus

    set scope [lindex [set Debugger:focus($debugfrm)] 0]
    set tid 0

    switch $scope {
	system {
	    set cmd SYSTEM_SCOPE
	}

	default {
	    # i.e. some thread context...
	    set cmd THREAD_SCOPE
	    set tid [set Debugger:focus($debugfrm)]
	}
    }

    return [list $cmd $tid]
}

proc Debugger:getContextInfo {debugfrm} {

    global Debugger:xcontext

    set scope [lindex [set Debugger:xcontext($debugfrm)] 0]

    switch $scope {
	callout {
	    set thread Callout
	}
	ihandler {
	    set thread "Interrupt handler"
	}
	thread {
	    set tid [lindex [set Debugger:xcontext($debugfrm)] 1]
	    set tsktype [Debugger:getThreadTypeName]
	    set thread "$tsktype [Debugger:getThreadName $tid]"
	}
	preamble {
	    set thread Preamble
	}
	init -
	idle -
	default {
	    set thread System
	}
    }

    return $thread
}

proc Debugger:buildStepCmd {debugfrm} {

    global Debugger:focus $debugfrm:switches

    set scope [lindex [set Debugger:focus($debugfrm)] 0]
    set tid 0

    switch $scope {
	system {
	    set scope system
	}

	default {
	    # i.e. some thread context...
	    set scope thread
	    set tid [set Debugger:focus($debugfrm)]
	}
    }

    if {[lsearch -exact [set $debugfrm:switches] asynch] != -1} {
	return [list asynch $scope $tid]
    }

    return [list $scope $tid]
}

proc Debugger:updateFocus {debugfrm location {freload false}} {

    global Debugger:f2c
    global Debugger:stackinfo Debugger:stacklevel
    global Debugger:stacklength Debugger:localinfo
    global Debugger:xcontext $debugfrm:switches
    global Debugger:f2w Debugger:focus

    set focuscmd [Debugger:buildFocusCmd $debugfrm]
    set context [set Debugger:f2c($debugfrm)]
    set Debugger:stacklevel($debugfrm) 0
    set Debugger:xcontext($debugfrm) {init 0 0 0}
    set locals {}
    set xcontext {}

    if {[lsearch -exact [set $debugfrm:switches] locals] != -1} {
	# locals displayed -- because it is a costly operation
	# to trace local variables, they are only polled if their
	# display frame is packed within the data subwindow.
	set Debugger:stackinfo($debugfrm) \
	    [gdb:backtrace $context \
		 $focuscmd location xcontext locals]
	set depth [llength [set Debugger:stackinfo($debugfrm)]]
	set Debugger:xcontext($debugfrm) $xcontext
	set Debugger:localinfo($xcontext,0) $locals
	# length of call chain must be up-to-date before
	# DataDisplay:updateLocalData is invoked
	set Debugger:stacklength($debugfrm) $depth

	DataDisplay:updateLocalData $debugfrm \
	    [set Debugger:f2w($debugfrm,locals)]
    } {
	set Debugger:stackinfo($debugfrm) \
	    [gdb:backtrace $context \
		 $focuscmd location xcontext]

	set depth [llength [set Debugger:stackinfo($debugfrm)]]
	set Debugger:xcontext($debugfrm) $xcontext
	set Debugger:localinfo($xcontext,0) {}
	set Debugger:stacklength($debugfrm) $depth
    }

    if {[set Debugger:stackinfo($debugfrm)] != {}} {
	set stackw [set Debugger:f2w($debugfrm,stack)]
	set lbox [$stackw subwidget listbox]
	$lbox delete 0 end
	set level 0

	foreach frame [set Debugger:stackinfo($debugfrm)] {
	    $lbox insert end [concat \#$level " " [lindex $frame 1]]
	    incr level
	}

	if {[lsearch -exact [set $debugfrm:switches] stack] != -1} {
	    $lbox selection set 0
	}
    }

    if {[lsearch -exact [set $debugfrm:switches] asynch] == -1 &&
	[lindex $xcontext 0] != "thread"} {
	# enable asynchronous contexts view if we stopped
	# in such kind of context.
	lappend $debugfrm:switches asynch
    }

    Debugger:updateSource $debugfrm $location $freload
}

proc Debugger:displayStackFrame {debugfrm} {

    global Debugger:f2c
    global Debugger:stackinfo Debugger:stacklevel
    global $debugfrm:switches Debugger:f2w
    global Debugger:localinfo

    set focuscmd [Debugger:buildFocusCmd $debugfrm]
    set level [set Debugger:stacklevel($debugfrm)]
    set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    set context [set Debugger:f2c($debugfrm)]

    set hotspot [Debugger:resume $context $focuscmd $fnum]

    if {$hotspot != {}} {
	Debugger:updateSource $debugfrm $hotspot
	if {[lsearch -exact [set $debugfrm:switches] stack] != -1} {
	    # highlight the selected frame in the stack
	    # listbox if open
	    set stackw [set Debugger:f2w($debugfrm,stack)]
	    set lbox [$stackw subwidget listbox]
	    $lbox selection clear 0 end
	    $lbox selection set $level
	}
	if {[lsearch -exact [set $debugfrm:switches] locals] != -1} {
	    global Debugger:xcontext
	    set xcontext [set Debugger:xcontext($debugfrm)]
	    set Debugger:localinfo($xcontext,$level) [gdb:getlocals]
	    # note: "false" last arg means that we do not need
	    # auto-focus to be done by the update procedure
	    # as we already point to the right context after
	    # a successful Debugger:resume
	    DataDisplay:updateLocalData $debugfrm \
		[set Debugger:f2w($debugfrm,locals)] false
	}
	Debugger:suspend $context $focuscmd
    }
}

proc Debugger:browseStack {debugfrm} {

    global Debugger:f2w Debugger:stacklevel

    set stackw [set Debugger:f2w($debugfrm,stack)]
    set lbox [$stackw subwidget listbox]
    set level [$lbox curselection]

    if {$level != {} && $level != [set Debugger:stacklevel($debugfrm)]} {
	$debugfrm.messages.warning configure -text {}
	# the stack display list follows the same ordering
	# rules than stack levels do: from 0 (the outer one,
	# on top of display) to [llength(stackinfo) - 1]
	# (the inner one, at bottom).
	set Debugger:stacklevel($debugfrm) $level
	Debugger:displayStackFrame $debugfrm
    }
}

proc Debugger:showStack {debugfrm} {
    global Debugger:f2w Debugger:stacklevel
    set dataw [set Debugger:f2w($debugfrm,data)]
    $dataw manage stack
    set level [set Debugger:stacklevel($debugfrm)]
    set stackw [set Debugger:f2w($debugfrm,stack)]
    set lbox [$stackw subwidget listbox]
    catch { $lbox selection set $level }
}

proc Debugger:hideStack {debugfrm} {
    global Debugger:f2w
    set dataw [set Debugger:f2w($debugfrm,data)]
    $dataw forget stack
}

proc Debugger:showLocals {debugfrm} {

    global Debugger:f2c Debugger:f2w Debugger:localinfo
    global Debugger:stackinfo
    global Debugger:xcontext Debugger:stacklevel
    global $debugfrm:switches

    set dataw [set Debugger:f2w($debugfrm,data)]
    $dataw manage locals
    set focuscmd [Debugger:buildFocusCmd $debugfrm]
    set context [set Debugger:f2c($debugfrm)]
    set level [set Debugger:stacklevel($debugfrm)]
    set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    set xcontext [set Debugger:xcontext($debugfrm)]

    if {[Debugger:resume $context $focuscmd $fnum] != {}} {
	set Debugger:localinfo($xcontext,$level) \
	    [gdb:getlocals]
	Debugger:suspend $context $focuscmd
    }

    set tree [set Debugger:f2w($debugfrm,locals)]
    DataDisplay:updateLocalData $debugfrm $tree
}

proc Debugger:hideLocals {debugfrm} {
    global Debugger:f2w
    set dataw [set Debugger:f2w($debugfrm,data)]
    $dataw forget locals
    DataDisplay:hideLocals $debugfrm [set Debugger:f2w($debugfrm,locals)]
}

proc Debugger:forceSwitchOn {debugfrm what} {

    global $debugfrm:switches

    if {[lsearch -exact [set $debugfrm:switches] $what] == -1} {
	# note: altering the following tracked variable
	# triggers the proper toolbarSwitch invocation...
	lappend $debugfrm:switches $what
    }
}

proc Debugger:notifyPreamble {context} {

    # restore breakpoints
    Debugger:restoreBreakpoints $context
    # restore watchpoints
    Debugger:restoreWatchpoints $context
}

proc Debugger:notifyBreak {context location} {

    global Debugger:c2f Debugger:state Project:settings
    global Debugger:configHasChanged Debugger:lockview
    global Debugger:operating
    global Monitor:stopCond

    if {${Debugger:configHasChanged}} {
	gdb:setsrc [set Project:settings(SourceDirs)]
	set Debugger:configHasChanged false
    }

    set w ${Debugger:operating}

    if {[set Debugger:lockview($w)] == 0} {

	# If a break condition has been raised, ensure the display is
	# in sync with the execution path, unless the current view
	# as been explicitly locked on a given thread. To
	# achieve this, just switch the focus of the operating frame
	# to "system".  Setting the focus to the destination value
	# prior to pick the "system" entry from the focus combo
	# prevents any attempt to update the display now. We just want
	# the proper value to be displayed in the combo.

	global Debugger:focus
	set Debugger:focus($w) system
	$w.selectors.focus pick 0
    }
    
    foreach debugfrm [set Debugger:c2f($context)] {
	$debugfrm.messages.location configure -text (Busy)
	Debugger:updateFocus $debugfrm $location
    }

    # something may fail during the focus update -- so be VERY
    # conservative and check for the GDB connection before asking for
    # global data...

    if {${Debugger:state} == "alive"} {
	DataDisplay:updateGlobalData $context
    }
}

proc Debugger:notifyException {context location siginfo} {

    global Debugger:c2f Debugger:focus Debugger:workspace

    # cancel startup timer (if any)
    set progressbar [set Debugger:workspace($context)].mtoolbar.progress

    if {[winfo exists $progressbar] == 1} {
	global Debugger:ptimer
	after cancel ${Debugger:ptimer}
	destroy $progressbar
    }

    # oops, exception raised - each frame should display
    # the faulty address - switch each frame to the system
    # context before updating focuses.

    foreach debugfrm [set Debugger:c2f($context)] {
	set Debugger:focus($debugfrm) system
    }

    Debugger:notifyBreak $context $location

    foreach debugfrm [set Debugger:c2f($context)] {
	$debugfrm.messages.warning configure -text $siginfo
	bell -displayof $debugfrm
    }

    pushEvent Application:event DebuggerExceptionEvent
}

proc Debugger:updateThreads {debugfrm} {

    global Debugger:f2c Debugger:threadlist Project:settings

    Debugger:clearFocus $debugfrm
    set context [set Debugger:f2c($debugfrm)]
    set threadlist [TkRequest $context GetThreads]
    set Debugger:threadlist $threadlist

    foreach threaddef $threadlist {
	set name [lindex $threaddef 1]
	set body [lindex $threaddef 2]
	if {[set Project:settings(Options,threadQualify)] == 0 || $body == {}} {
	    set idstring $name
	} {
	    set idstring [format "%s(%s)" $body $name]
	}
	$debugfrm.selectors.focus insert end $idstring
    }
}

proc Debugger:clearFocus {debugfrm} {

    set lbox [$debugfrm.selectors.focus subwidget listbox]
    $lbox delete 0 end
    $lbox insert end (system)
}

proc Debugger:setFocus {debugfrm focus} {

    if {$focus == {}} {
	return
    }

    global Debugger:focus Debugger:f2c Debugger:lockview

    set context [set Debugger:f2c($debugfrm)]
    set oldfocus [set Debugger:focus($debugfrm)]

    switch $focus {
	(system) {
	    set Debugger:focus($debugfrm) system
	    set Debugger:lockview($debugfrm) 0
	}
	default {
	    global Debugger:threadlist
	    set lbox [$debugfrm.selectors.focus subwidget listbox]
	    set sel [$lbox curselection]
	    set id [lindex [lindex ${Debugger:threadlist} [expr $sel - 1]] 0]
	    set Debugger:focus($debugfrm) $id
	    set Debugger:lockview($debugfrm) 1
	}
    }

    if {$oldfocus != [set Debugger:focus($debugfrm)] &&
	[Debugger:resume $context] != "false"} {
	Debugger:updateFocus $debugfrm {} false
	Debugger:suspend $context
    }
}

proc Debugger:resume {context {focuscmd {}} {fnum {}}} {

    TkRequest $context HoldSimulation
    return [gdb:getctl $context $focuscmd $fnum]
}

proc Debugger:suspend {context {focuscmd {}}} {

    gdb:relctl $context $focuscmd
}

proc Debugger:listen {context {state Running}} {

    global Debugger:state Debugger:c2f
    global Debugger:operating Project:settings

    foreach debugfrm [set Debugger:c2f($context)] {
	$debugfrm.messages.location configure -text ($state)
    }
    pushEvent Application:event DebuggeeReleasedEvent
    gdb:release $context

    # The debug session may have been aborted while listening to GDB:
    # check for this condition before actually sending an event
    # telling that we hold the debuggee...

    if {${Debugger:state} == "alive"} {
	pushEvent Application:event DebuggeeHeldEvent
	if {[set Project:settings(Options,forceFocusOnBreak)] == 1} {
	    global Monitor:initState Monitor:stopCond
	    if {${Monitor:initState} == "ok" && ${Monitor:stopCond} >= 5} {
		# stopCond 5/6 == breakpoint/watchpoint"
		Debugger:setThreadLock ${Debugger:operating}
	    }
	}
    }
}

proc Debugger:progress {context} {

    global Debugger:ptimer Debugger:workspace

    catch {
	set meter [set Debugger:workspace($context)].mtoolbar.progress
	set v [$meter cget -value]
	set msg [$meter cget -text]

	if {$v < 1.0} {
	    set v [expr $v + 0.025]
	    $meter config -value $v
	} {
	    set v 0.025
	    set fg [$meter cget -fillcolor]
	    $meter config -value $v -fillcolor [$meter cget -background]
	    $meter config -fillcolor $fg
	}

	if {$msg == " "} {
	    set msg "Loading..."
	} {
	    set msg " "
	}
	$meter config -value $v -text $msg
	set Debugger:ptimer [after 250 "Debugger:progress $context"]
    }
}

proc Debugger:postSourceMenu {debugfrm rootx rooty} {

    global Debugger:childState Debugger:f2w
    global Debugger:focus Debugger:f2s
    global Debugger:hotSymbol

    if {${Debugger:childState} != "held" &&
	${Debugger:childState} != "zombie"} {
	# no source menu is available until the debuggee
	# is under control (i.e. in a held or zombie state)
	return false
    }

    # clear last warning (if any)
    $debugfrm.messages.warning configure -text {}

    set file [set Debugger:f2s($debugfrm)]

    if {$file == {}} {
	# no source file displayed
	return false
    }

    set w [set Debugger:f2w($debugfrm,source)]
    # turn root coordinates into text widget coordinates
    set x [expr $rootx - [winfo rootx $w]]
    set y [expr $rooty - [winfo rooty $w]]
    # compute line number from pixel coordinates
    set lineno [lindex [split [$w index @$x,$y] .] 0]
    set menu [$w.popup subwidget menu]
    $menu delete 0 end

    # try using the hot symbol first (shut down the evaluation
    # bubble to stop noise)
    set sel ${Debugger:hotSymbol}
    Debugger:stopPointerNoise $debugfrm $w

    if {$sel == {} && [catch {set sel [$w get sel.first sel.last]}] == 1} {
	# try using the scratchpad value if no selection is active
	# in the source buffer...
	set sel [$debugfrm.selectors.scratchpad cget -selection]
    }

    if {$sel != {} && ![regexp -- "^ +$" $sel]} {
	# truncate the expr to a reasonable length for displaying
	# a label (e.g. 25c)
	if {[string length $sel] > 25} {
	    set selabel [string range $sel 0 24]...
	} {
	    set selabel $sel
	}
	$menu add command -label "Display `$selabel'" \
	    -command "DataDisplay:displayExprLocal $debugfrm [list $sel]"
	$menu add command -label "Display `*$selabel'" \
	    -command "DataDisplay:dereferenceExprLocal $debugfrm [list $sel]"
	$menu add command -label "Type of `$selabel'" \
	    -command "DataDisplay:showTypeWorker $debugfrm [winfo toplevel $debugfrm] [list $sel]"
	$menu add separator
	$menu add command -label "Seek `$selabel'" \
	    -command "Debugger:lookupSymbol $debugfrm [list $sel]"
	$menu add command -label "Find `$selabel'" \
	    -command "Debugger:doFindString $debugfrm [list $sel]"
	$menu add separator
    }

    if {${Debugger:childState} == "held"} {
	# no break in zombie state
	Debugger:selectBreakAtLine $debugfrm $menu $file $lineno
	$menu add separator
    }

    $menu add command -label "Search string" \
	-command "Debugger:findString $debugfrm"

    return true
}

proc Debugger:findString {debugfrm} {

    global Debugger:searchinfo Debugger:f2w

    set textw [set Debugger:f2w($debugfrm,source)]

    if {[catch {set sel [$textw get sel.first sel.last]}] == 0} {
	set pretyped $sel
    } {
	set pretyped {}
    }

    set w $debugfrm.find

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
    cascadeWindow $w

    set f [frame $w.f -bd 1 -relief sunken]
    pack $f -side top -fill both -expand yes

    tixLabelEntry $f.re -label "Find:" \
	-options {
	    label.anchor w
	    entry.width 22
	}

    set e [$f.re subwidget entry]
    pack $f.re -pady 5 -anchor w -padx 5
    bind $e <Return> "Debugger:doFindString $debugfrm"
    bind $e <Escape> "wm withdraw $w"
    $e insert end $pretyped

    set f2 [frame $f.opt -relief flat -bd 0]
    pack $f2 -fill both -expand yes

    set Debugger:searchinfo($debugfrm,searchwhence) -forward
    set Debugger:searchinfo($debugfrm,searchindex) @0,0

    radiobutton $f2.bck -text backward \
	-variable Debugger:searchinfo($debugfrm,searchwhence) \
	-relief flat -bd 2 -pady 0 -anchor w \
	-value -backward

    radiobutton $f2.fwd -text forward \
	-variable Debugger:searchinfo($debugfrm,searchwhence) \
	-relief flat -bd 2 -pady 0 -anchor w \
	-value -forward

    pack $f2.fwd $f2.bck -side right -padx 5

    set status [frame $w.status -height 20 -relief sunken -bd 1]
    pack $w.status -fill x -expand no
    label $w.status.msg
    pack $w.status.msg -side left

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add search -text Search -command "Debugger:doFindString $debugfrm"
    $w.bbox add clear -text Clear -command "$e delete 0 end"
    $w.bbox add dismiss -text Close -command "wm withdraw $w"
    pack $w.bbox -expand no -fill x

    focus $e
}

proc Debugger:doFindString {debugfrm {s {}}} {

    global Debugger:searchinfo Debugger:f2w

    set textw [set Debugger:f2w($debugfrm,source)]

    if {$s == {}} {
	# using find window to specify the search string...
	set w $debugfrm.find
	set e [$w.f.re subwidget entry]
	set s [$e get]
	if {$s == {}} {
	    return
	}
	set whence [set Debugger:searchinfo($debugfrm,searchwhence)]
	set sow [set Debugger:searchinfo($debugfrm,searchindex)]
    } {
	set w {}
	set whence -forward
	if {[catch { set sow [set Debugger:searchinfo($debugfrm,searchindex)] }] == 1} {
	    set sow @0,0
	}
    }

    if {[catch { set sow \
 		     [$textw search $whence -exact -count n -- $s $sow] }] == 0} {
	if {$sow != {}} {
	    set eow [lindex [split $sow .] 0].[expr [lindex [split $sow .] 1] + $n]
	    $textw tag remove sel 1.0 end
	    $textw tag add sel $sow $eow
	    $textw see $sow
	    if {$whence == "-forward"} {
		set Debugger:searchinfo($debugfrm,searchindex) $eow
	    } {
		set Debugger:searchinfo($debugfrm,searchindex) $sow
	    }
	    if {$w != {}} {
		$w.status.msg config -text {}
	    }
	    return
	}
    }

    if {$w != {}} {
	$w.status.msg config -text "`$s' not found."
    }
    bell
}

proc Debugger:getThreadName {tid} {

    global Debugger:threadlist

    set ndx [lsearch -regexp ${Debugger:threadlist} "^$tid .*"]

    if {$ndx < 0} {
	set name $tid
    } {
	set name [lindex [lindex ${Debugger:threadlist} $ndx] 1]
    }

    return $name
}

proc Debugger:setThreadLock {debugfrm} {

    global Debugger:xcontext Debugger:threadlist Debugger:lockview

    set xcontext [set Debugger:xcontext($debugfrm)]
    set type [lindex $xcontext 0]
    set tid [lindex $xcontext 1]

    if {$type == "thread"} {
	# +1 to bypass (system) entry at the beginning of the combo
	set nth [expr [lsearch -regexp ${Debugger:threadlist} "^$tid .*"] + 1]
    } {
	# "0" stands for "system" focus
	set nth 0
    }

    $debugfrm.selectors.focus pick $nth
}

proc Debugger:getThreadTypeName {} {

    global Debugger:syspecs
    return [lindex ${Debugger:syspecs} 0]
}

proc Debugger:routeMainStatus {context name1 name2 op} {
    global Workspace:statusMsg $context:statusMsg
    set Workspace:statusMsg [set $context:statusMsg]
}

proc Debugger:saveGeometry {context} {
    set srch [$context.window panecget p1 -size]
    set loch [$context.window panecget p2 -size]
    Project:setResource DebuggerGeometry [list $srch $loch]
}

proc Debugger:restoreGeometry {context} {

    set geometry [Project:getResource DebuggerGeometry]
    if {$geometry != {}} {
	set srch [lindex $geometry 0]
	set loch [lindex $geometry 1]
	$context.window paneconfigure p1 -size $srch
	$context.window paneconfigure p2 -size $loch
    }
}

proc Debugger:saveSwitches {context} {

    global Debugger:f2w $context:switches

    set panew [set Debugger:f2w($context,data)] 
    set stackpsize [$panew panecget stack -size]
    set localpsize [$panew panecget locals -size]

    Project:setResource DebuggerSwitches \
	[list [set $context:switches] [list $stackpsize $localpsize]]
}

proc Debugger:restoreSwitches {context} {

    global Debugger:f2w

    set info [Project:getResource DebuggerSwitches]
    set switches [lindex $info 0]
    set geometries [lindex $info 1]

    foreach sw $switches {
	Debugger:forceSwitchOn $context $sw
    }

    set panew [set Debugger:f2w($context,data)] 
    $panew paneconfigure stack -size [lindex $geometries 0]
    $panew paneconfigure locals -size [lindex $geometries 1]
}

proc Debugger:saveScratchPad {context} {

    set pad $context.selectors.scratchpad
    # save the first 20 historized items from the main scratchpad --
    # note that we cannot use the "history limit" attribute from a combo.
    # It does prevent more than 20 items to be entered in the history,
    # but it does not behave in a FIFO manner with the oldest strings
    # but rather locks out the newest one!... :-(
    set history [$pad subwidget listbox]
    set strings [lrange [$history get 0 end] 0 19]
    Project:setResource DebuggerScratchPad $strings
}

proc Debugger:restoreScratchPad {context} {

    set pad $context.selectors.scratchpad
    set strings [Project:getResource DebuggerScratchPad]
    foreach e $strings {
	$pad appendhistory $e
    }
}

proc Debugger:lookupWord {debugfrm textw x y X Y} {

    global Debugger:hotSymbol $debugfrm:statusMsg

    set bow [$textw index "@$x,$y wordstart"]
    set eow [$textw index "@$x,$y wordend"]
    set hotword [string trim [$textw get $bow $eow]]

    ## YM
    ## Now, let's see... don't we have a "->" before us ??
    ##
    set temparrow [$textw get [$textw index "$bow -2 chars"] $bow]
    if {$temparrow == "->"} {
	## Yes we do !!
	## Now, let's find our class pointer...
	set index [$textw index "$bow -3 chars"]
	set bow [$textw index "$index wordstart"]
	set eow [$textw index "$index wordend"]
	set classptr [string trim [$textw get $bow $eow]]
	set hotword "$classptr->$hotword"
    }

    if {$hotword != {}} {
	if {$hotword == ${Debugger:hotSymbol}} {
	    return
	}
	global Debugger:childState

	if {${Debugger:childState} == "held" ||
	    ${Debugger:childState} == "zombie"} {
	    # Lookup functions can only perform when 
	    # the debuggee is under control.
	    set Debugger:hotSymbol $hotword
	    if {[gdb:lookup $hotword] != {}} {
		global Project:settings
		set $debugfrm:statusMsg "Control+Mouse<1> seeks `$hotword'..."
		$textw config -cursor hand2
		if {[set Project:settings(Options,evalBubbles)] == 1} {
		    # try to evaluate the symbol after a full second pointing at it
		    Debugger:resetEvalTimer $debugfrm 500 $X $Y
		}
		return
	    }
	}
    }

    Debugger:stopPointerNoise $debugfrm $textw
}

proc Debugger:stopPointerNoise {debugfrm textw} {

    global Debugger:hotSymbol $debugfrm:statusMsg

    if {${Debugger:hotSymbol} != {}} {
	$textw config -cursor xterm
	set Debugger:hotSymbol {}
	set $debugfrm:statusMsg {}
	Debugger:resetEvalTimer $debugfrm
    }
}

proc Debugger:lookupSymbol {debugfrm {symbol {}}} {

    global $debugfrm:statusMsg Debugger:f2w
    global Debugger:hotSymbol

    if {$symbol == {}} {
	set symbol ${Debugger:hotSymbol}
	if {$symbol == {}} {
	    return
	}
    }

    set location [DataDisplay:lookupExpr $debugfrm $symbol]
    set filepath [lindex $location 0]
    set lineno [lindex $location 1]
    set textw [set Debugger:f2w($debugfrm,source)]
    Debugger:stopPointerNoise $debugfrm $textw

    if {$filepath != {}} {
	Debugger:displaySource $debugfrm $filepath
	$textw tag remove sel 1.0 end
	catch {
	    $textw tag add sel $lineno.2 $lineno.end
	    $textw see $lineno.0
	}
    } {
	# set a strange cursor to tell about the failure
	# (the normal xterm cursor will be reinstated when
	# the mouse leaves the unreachable symbol area)
	$textw config -cursor spider
    }

    set $debugfrm:statusMsg {}
}

proc Debugger:resetEvalTimer {debugfrm {nextime 0} {X -1} {Y -1}} {

    global Debugger:symbolEvalTimer
	
    set etimer [set Debugger:symbolEvalTimer($debugfrm)]

    if {$etimer != {}} {
	# cancel the currently running timer
	after cancel $etimer
	set Debugger:symbolEvalTimer($debugfrm) {}
    } {
	# if no timer is running, an eval bubble may be visible --
	# destroy it.
	global Debugger:f2w
	set w [set Debugger:f2w($debugfrm,source)].evalbubble
	catch { destroy $w }
    }

    if {$nextime != 0} {
	set Debugger:symbolEvalTimer($debugfrm) \
	    [after $nextime "Debugger:evaluateHotSymbol $debugfrm $X $Y"]
    }
}

proc Debugger:evaluateHotSymbol {debugfrm X Y} {
    
    global Debugger:hotSymbol Debugger:f2w
    global Debugger:symbolEvalTimer

    # timer has elapsed -- forget its id.
    set Debugger:symbolEvalTimer($debugfrm) {}
    set w [set Debugger:f2w($debugfrm,source)].evalbubble

    if {${Debugger:hotSymbol} != {} &&
	![winfo exists $w]} {
	set symbol ${Debugger:hotSymbol}
	set value [DataDisplay:evalExpr $debugfrm $symbol "no_format"]
	if {$value == {}} {
	    # muhh? nothing valuable to display
	    return
	}
	# build the bubble frame to display the value
	toplevel $w
	wm overrideredirect $w 1
	incr X 5
	incr Y 15
	wm geometry $w +${X}+${Y}
	if {[string length $value] > 80} {
	    # truncate the value to a reasonable length
	    set value [string range $value 0 79]...
	}
	label $w.l -text "$symbol = $value" -border 1 -relief solid \
	    -bg \#ccffcc -padx 5
	pack $w.l
    }
}

proc Debugger:applyConfigUpdate {context} {

    global Debugger:childState
    global Debugger:configHasChanged
    global Debugger:c2f Project:settings

    set filter {}

    if {[set Project:settings(Options,traceKernel)] == 1} {
	append filter 0
    }
    if {[set Project:settings(Options,traceIface)] == 1} {
	append filter 1
    }
    if {[set Project:settings(Options,traceApp)] == 1} {
	append filter 2
    }

    TkRequest $context SetDebugFilter $filter

    if {${Debugger:childState} == "held" ||
	${Debugger:childState} == "zombie"} {
	# if debuggee is under control, perform the update now.
	if {[Debugger:resume $context] != "false"} {
	    gdb:setsrc [set Project:settings(SourceDirs)]
	    foreach debugfrm [set Debugger:c2f($context)] {
		# resync the frame displays with the new directory setting
		Debugger:updateFocus $debugfrm {} true
	    }
	    Debugger:resynchBreakpoints $context
	    Debugger:suspend $context
	}
    } {
	# Otherwise, raise the flag telling notifyBreak() to apply
	# the changes to GDB before attempting to update the focus.
	set Debugger:configHasChanged true
    }
}

proc Debugger:applyOptionUpdate {context} {

    global Debugger:childState Debugger:c2f

    if {${Debugger:childState} != "dead"} {
	foreach debugfrm [set Debugger:c2f($context)] {
	    # reload thread selector
	    Debugger:updateThreads $debugfrm
	}
    }
}

proc Debugger:processGlobalEvent {context name1 name2 op} {

    global Debugger:c2f
    global Debugger:f2w

    global Monitor:simulationState Debugger:childState

    while {[popEvent globalEventQueue:$context e] == "true"} {
	switch $e {
	    InitDebuggerEvent {
		# disable main debug frame toolbars
		$context.toolbar.tools configure -state disabled
		$context.toolbar.switches configure -state disabled
		$context.selectors.focus configure -state disabled
		$context.selectors.scratchpad configure -state disabled
	    }
	    
	    ConfigureWallpaperEvent {
		Debugger:removeWallPaper $context
		if {${Monitor:simulationState} == "dead"} {
		    Debugger:displayWallPaper $context
		}
	    }

	    DebuggerStartedEvent {
		global Debugger:ptimer Debugger:workspace Application:visualType
		set progressbar [set Debugger:workspace($context)].mtoolbar.progress
		tixMeter $progressbar -value 0 -text "Loading..." -width 110
		if {${Application:visualType} == "color"} {
		    $progressbar config -fillcolor white
		}
		Debugger:removeWallPaper $context
		pack $progressbar -side right -padx 6
		set Debugger:ptimer [after 250 "Debugger:progress $context"]
		# ensure the source/data panedwin is last in the packing
		# order to have it laid on the remaining cavity space
		# after all other frames.
		pack forget $context.window
		pack $context.toolbar -side top -expand no -fill x
		pack $context.selectors -after $context.toolbar -expand no -fill x
		pack $context.messages -after $context.selectors -expand no -fill x
		pack $context.window -expand yes -fill both
		# freeze the source actions until the debugger is up
		foreach slave [pack slaves $context.toolbar.srcmd] {
		    $slave config -state disabled
		}
	    }

	    DebuggerAbortEvent -
	    DebuggerStoppedEvent {

		# cancel startup timer (if any)
		global Debugger:workspace
		set progressbar [set Debugger:workspace($context)].mtoolbar.progress
		if {[winfo exists $progressbar] == 1} {
		    global Debugger:ptimer
		    after cancel ${Debugger:ptimer}
		    destroy $progressbar
		}

		if {$e == "DebuggerStoppedEvent"} {
		    Debugger:saveBreakpoints $context
		    Debugger:saveWatchpoints $context
		    Debugger:saveGeometry $context
		    Debugger:saveSwitches $context
		    Debugger:saveScratchPad $context

		    # destroy all secondary debug frames
		    foreach debugfrm [set Debugger:c2f($context)] {
			if {$debugfrm != $context} {
			    Debugger:destroySecondaryFrame $debugfrm
			}
		    }

		    # cancel eval timer for main frame
		    Debugger:resetEvalTimer $context

		    # delete main source window contents
		    set textw [set Debugger:f2w($context,source)]
		    $textw tag delete hotspot
		    $textw configure -state normal
		    $textw delete 1.0 end
		    $textw configure -state disabled
		    # redraw wallpaper
		    Debugger:displayWallPaper $context
		
		    # hide stack display for main debug frame (if open)
		    global $context:switches
		    set dataw [set Debugger:f2w($context,data)]
		    foreach disp [set $context:switches] {
			if {$disp != "asynch"} {
			    $dataw forget $disp
			}
		    }
		    if {[lsearch -exact [set $context:switches] locals] != -1} {
			DataDisplay:hideLocals $context [set Debugger:f2w($context,locals)]
		    }
		    set $context:switches {}
		} {
		    $context.messages.location configure -text (Aborted)
		    bell
		    global Project:settings
		    tk_messageBox -parent $context \
			-message "Failed to load/start [set Project:settings(GdbPath)]." \
			-type ok -icon error -title Error
		    Debugger:displayWallPaper $context
		}
	    
		# disable main debug frame toolbars
		$context.toolbar.tools configure -state disabled
		$context.toolbar.switches configure -state disabled
		global $context:focus $context:scratchpad
		global $context:tickval
		# reset thread list - keep the first entry unaltered
		# (i.e. "(system)")
		set $context:focus {}
		set $context:tickval {}
		Debugger:clearFocus $context
		$context.selectors.focus configure -state disabled
		set $context:scratchpad {}
		$context.selectors.scratchpad subwidget entry delete 0 end
		$context.selectors.scratchpad subwidget listbox delete 0 end
		$context.selectors.scratchpad configure -state disabled
		pack forget $context.toolbar
		pack forget $context.selectors
		pack forget $context.messages

		# destroy globals datawatch frame (if any)
		DataDisplay:destroyGlobals $context

		# close examiner
		Examiner:destroy $context

		# destroy file pick window
		catch { destroy $context.srcpick }

		# clear main debug frame variables
		global Debugger:bplist Debugger:f2s
		global Debugger:pcfile Debugger:pcline
		global Debugger:xcontext Debugger:focus
		global Debugger:stackinfo
		global Debugger:stacklength Debugger:stacklevel
		global Debugger:localinfo Debugger:fserial
		global Debugger:scratchpad
		global Debugger:hotSymbol
		global Debugger:bpOneshot

		set Debugger:bplist {}
		set Debugger:f2s($context) {}
		set Debugger:pcfile($context) {}
		set Debugger:pcline($context) 0
		set Debugger:focus($context) system
		set Debugger:scratchpad($context) {}
		set Debugger:xcontext($context) {init 0 0 0}
		set Debugger:stackinfo($context) {}
		set Debugger:stacklength($context) {}
		set Debugger:stacklevel($context) 0
		set Debugger:hotSymbol {}
		set Debugger:bpOneshot {}
		catch { unset Debugger:localinfo }
		set Debugger:fserial 2

		# clear message line
		$context.messages.location configure -text {}
		$context.messages.warning configure -text {}

		global Debugger:childState
		set Debugger:childState dead
	    }

	    DebuggeeHeldEvent {
		global Debugger:childState
		foreach debugfrm [set Debugger:c2f($context)] {
		    # enable debug frames toolbars
		    # Note: a held state always follows a zombie
		    # state: we have to take care of this.
		    if {${Debugger:childState} == "released"} {
			$debugfrm.toolbar.tools configure -state normal
		    } {
			# allow stack browsing only if in "zombie" state
			foreach button {up down} {
			    $debugfrm.toolbar.tools subwidget $button config -state normal
			}
		    }
		    $debugfrm.toolbar.switches configure -state normal
		    $debugfrm.selectors.focus configure -state normal
		    $debugfrm.selectors.scratchpad configure -state normal
		    # Working around a Tix bug: the entry's
		    # selectforeground color seems to be spuriously
		    # overwritten by the disableforeground attribute
		    # whenever the combo is disabled. So, reset it by
		    # hand.
		    $debugfrm.selectors.focus subwidget entry configure -selectforeground white
		    $debugfrm.selectors.scratchpad subwidget entry configure -selectforeground white
		    # may not break debuggee
		    $debugfrm.toolbar.tools subwidget xbreak config -state disabled

		    # enable access to locals while held
		    DataDisplay:setTreeState $debugfrm normal \
			[set Debugger:f2w($debugfrm,locals)]
		}
		if {${Debugger:childState} == "released"} {
		    set Debugger:childState held
		}
		# if a oneshot breakpoint is pending, remove it after the first break
		global Debugger:bpOneshot
		if {${Debugger:bpOneshot} != {}} {
		    global $debugfrm:statusMsg
		    Debugger:removeBreakAtLine $debugfrm ${Debugger:bpOneshot}
		    set Debugger:bpOneshot {}
		    set $debugfrm:statusMsg {}
		}
		# enable access to globals
		DataDisplay:setTreeState $context normal
		# enable access to memory examination
		Examiner:setState $context normal
	    }

	    DebuggeeReleasedEvent {
		global Debugger:childState Monitor:channel
		set Debugger:childState released
		foreach debugfrm [set Debugger:c2f($context)] {

		    # disable debug frames toolbar and switches
		    # toolbar buttons must be handled manually to
		    # differenciate xbreak from other buttons...

		    foreach button {stepover stepinto stepout cont up down \
					breakpoints watchpoints thrlock newframe} {
			$debugfrm.toolbar.tools subwidget $button config -state disabled
		    }

		    if {${Monitor:channel} != {}} {
			# may break debuggee (if the channel is up)
			$debugfrm.toolbar.tools subwidget xbreak config -state normal
		    }

		    $debugfrm.toolbar.switches configure -state disabled
		    $debugfrm.selectors.focus configure -state disabled
		    $debugfrm.selectors.scratchpad configure -state disabled

		    # disable access to locals while running
		    DataDisplay:setTreeState $debugfrm disabled \
			[set Debugger:f2w($debugfrm,locals)]

		    # hide tick counter when released
		    global $debugfrm:tickval
		    set $debugfrm:tickval {}
		    }
		# disable access to globals
		DataDisplay:setTreeState $context disabled
		# disable access to memory examination
		Examiner:setState $context disabled
	    }

	    SimulationWarmEvent {

		global Monitor:standaloneRun

		# affect toolbar state only if the simulation
		# is traced...

		if {${Monitor:standaloneRun} == 0} {

		    # update the toolbar state
		    $context.toolbar.tools config -state normal
		    # may not access any debug toolbar actions yet...
		    foreach button {stepover stepinto stepout cont up down \
					breakpoints watchpoints thrlock newframe} {
			$context.toolbar.tools subwidget $button config -state disabled
		    }
		    # ..except the "Break" command 
		    $context.toolbar.tools subwidget xbreak config -state normal
		    # instantiate data display tree for globals
		    DataDisplay:makeGlobalsTree $context
		    # create examiner
		    Examiner:initialize $context
		    # make the source actions sensitive
		    foreach slave [pack slaves $context.toolbar.srcmd] {
			$slave config -state normal
		    }
		}
	    }

	    DebuggerExceptionEvent -
	    SimulationFinishedEvent {
		global Debugger:childState
		set Debugger:childState zombie
		global Debugger:zombieCause
		set Debugger:zombieCause $e
		foreach debugfrm [set Debugger:c2f($context)] {
		    foreach button {stepover stepinto stepout cont up down \
					breakpoints watchpoints thrlock newframe} {
			$debugfrm.toolbar.tools subwidget $button config -state disabled
		    }
		    $debugfrm.toolbar.switches configure -state disabled
		}
	    }

	    SimulationColdEvent {
		global Debugger:syspecs
		set specs [TkRequest $context GetSpecs]
		set Debugger:syspecs $specs
	    }

	    ThreadCreatedEvent -
	    ThreadDeletedEvent {
		foreach debugfrm [set Debugger:c2f($context)] {
		    Debugger:updateThreads $debugfrm
		}
	    }

	    MonitorConnectEvent {
		global Debugger:childState
		global Debugger:ptimer Debugger:workspace
		# Debugger state switches from "Busy" to "Ready" when
		# the debuggee (or debugger) connects to the monitor socket port...
		if {${Debugger:childState} == "released"} {
		    foreach debugfrm [set Debugger:c2f($context)] {
			$debugfrm.messages.location configure -text (Running)
		    }
		    after cancel ${Debugger:ptimer}
		    set progressbar [set Debugger:workspace($context)].mtoolbar.progress
		    $progressbar configure -value 1.0 -text Ready
		    update idletasks
		    after 250
		    destroy $progressbar
		}
	    }

	    MonitorDisconnectEvent {
		global Debugger:state
		if {${Debugger:state} == "alive"} {
		    # If the debuggee has exited, GDB must be aware of
		    # it. Restart dispatching the messages from it to
		    # get the cause of the exit.
		    gdb:release $context
		}
	    }

	    SimulationStartedEvent {
		# simulation started without debugging support --
		# hide the main debug frame
		pack forget $context
		# remove wallpaper
		Debugger:removeWallPaper $context
	    }

	    SimulationKilledEvent {
		# standalone simulation has exited --
		# restore the main debug frame
		global Workspace:statusBar
		pack $context -before ${Workspace:statusBar} -expand yes -fill both
		Debugger:displayWallPaper $context
	    }

	    ConfigurationChanged {
		# we are interested in any change to the source
		# directory list.
		Debugger:applyConfigUpdate $context
 	    }

	    OptionChanged {
		Debugger:applyOptionUpdate $context
 	    }

	    WorkspaceQuitEvent {
		global Debugger:state
		if {${Debugger:state} == "alive"} {
		    Debugger:stop $context
		}
	    }
	}
    }
}
