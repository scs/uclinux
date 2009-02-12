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

set Debugger:bpToolTips {}

proc Debugger:computeBPFocus {bpid w X Y} {

    global Debugger:bplist

    set bpinfo [lindex ${Debugger:bplist} $bpid]
    set focuscmd [lindex $bpinfo 0]
    set state [lindex $bpinfo 1]
    set condition [lindex $bpinfo 5]
    set tip [Debugger:getBreakpointFocus $focuscmd]

    if {$condition != {}} {
	append tip ", if $condition"
    }

    if {$state == "disabled"} {
	append tip " (disabled)"
    }

    return $tip
}

proc Debugger:getBreakpointFocus {focuscmd} {

    switch [lindex $focuscmd 0] {
	SYSTEM_SCOPE {
	    set focusinfo system
	}
	THREAD_SCOPE {
	    set tid [lindex $focuscmd 1]
	    set tsktype [string tolower [Debugger:getThreadTypeName]]
	    set focusinfo "$tsktype [Debugger:getThreadName $tid]"
	}
	HARD_SCOPE {
	    set focusinfo hard
	}
	default {
	    set focusinfo {}
	}
    }

    return $focusinfo
}

proc Debugger:selectBreakAtLine {debugfrm menu file lineno} {

    global Debugger:bplist Debugger:focus

    # a breakpoint is: { focus state bpnum file lineno condition }

    if {[winfo exists $menu.cond]} {
	destroy $menu.cond
    }

    set bpfound {}

    foreach bpinfo ${Debugger:bplist} {
	set bpfile [lindex $bpinfo 3]
	set bpline [lindex $bpinfo 4]
	if {$file == $bpfile && $bpline == $lineno} {
	    set bpfound $bpinfo
	    break
	}
    }

    set scope [lindex [set Debugger:focus($debugfrm)] 0]

    switch $scope {
	system {
	    $menu add command -label "Break here" \
		-command "Debugger:setBreakAtLine $debugfrm $lineno {SYSTEM_SCOPE 0}"
	}

	default {
	    # some thread context...
	    $menu add cascade -label "Break here" -menu $menu.cond
	    menu $menu.cond -tearoff 0
	    set tsktype [Debugger:getThreadTypeName]
	    $menu.cond add command -label "unconditionally" \
		-command "Debugger:setBreakAtLine $debugfrm $lineno {SYSTEM_SCOPE 0}"
	    $menu.cond add command -label "if $tsktype \"[Debugger:getThreadName $scope]\" runs" \
		-command "Debugger:setBreakAtLine $debugfrm $lineno \"[list THREAD_SCOPE $scope]\""
	}
    }

    $menu add command -label "Disable breakpoint"
    set disndx [$menu index end]
    $menu add command -label "Enable breakpoint"
    set enbndx [$menu index end]
    $menu add command -label "Remove breakpoint"
    set remndx [$menu index end]

    if {$bpfound == {}} {
	# may not disable/remove a previously set (active) bp
	$menu entryconfigure $disndx -state disabled
	$menu entryconfigure $enbndx -state disabled
	$menu entryconfigure $remndx -state disabled
    } {
	if {[lindex $bpfound 1] == "disabled"} { 
	    # BP is currently disabled: one may enable it
	    # or remove it definitively...
	    $menu entryconfigure $disndx -state disabled
	    $menu entryconfigure $enbndx \
		-command "Debugger:toggleBreakAtLine $debugfrm \"$bpfound\" enabled"
	} {
	    # BP is currently enabled: one may disable it
	    # or remove it definitively...
	    $menu entryconfigure $enbndx -state disabled
	    $menu entryconfigure $disndx \
		-command "Debugger:toggleBreakAtLine $debugfrm \"$bpfound\" disabled"
	}
	$menu entryconfigure $remndx \
	    -command "Debugger:removeBreakAtLine $debugfrm \"$bpfound\""
    }

    $menu add separator
    $menu add command -label "Run until..." \
	-command "Debugger:runUntil $debugfrm $file $lineno"
}

proc Debugger:runUntil {debugfrm file lineno} {

    global Debugger:f2c Debugger:focus
    global $debugfrm:statusMsg
    
    # A "run until" command is a step out command combined
    # with a temporary breakpoint on the designated line.
    # This implies locking the focus on the current thread.

    # give some feed back, the operation could be slow...
    set $debugfrm:statusMsg "Running until [file tail $file]:$lineno..."

    set scope [lindex [set Debugger:focus($debugfrm)] 0]
    if {$scope == "system"} {
	Debugger:setThreadLock $debugfrm
	# reread the scope which may have changed
	set scope [lindex [set Debugger:focus($debugfrm)] 0]
    }

    # set the temporary breakpoint -- remember that a thread lock is
    # pending, thus the focus must be "system" (an ISR or a callout
    # was active), or any valid real-time thread.
    if {$scope == "system"} {
	set schedbp [list SYSTEM_SCOPE 0]
    } {
	set schedbp [list THREAD_SCOPE $scope]
    }
    Debugger:setBreakAtLine $debugfrm $lineno $schedbp oneshot

    # then perform the step out...
    set context [set Debugger:f2c($debugfrm)]
    set focuscmd [Debugger:buildStepCmd $debugfrm]
    TkRequest $context StepOut $focuscmd
}

proc Debugger:setBreakAtLine {debugfrm lineno focuscmd {state enabled}} {

    global Debugger:bplist
    global Debugger:f2w Debugger:f2c Debugger:f2s

    set context [set Debugger:f2c($debugfrm)]

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set file [set Debugger:f2s($debugfrm)]
    set emsg {}
    set bpnum [gdb:setsoftbp $context $focuscmd $file $lineno]
    Debugger:suspend $context

    if {$bpnum == {}} {
	global gdb:lasterror
	$debugfrm.messages.warning configure \
	    -text [set gdb:lasterror]
	bell -displayof $debugfrm
	return
    }

    set bpinfo [list $focuscmd $state $bpnum $file $lineno {}]

    if {$state == "oneshot"} {
	global Debugger:bpOneshot
	set Debugger:bpOneshot $bpinfo
    }
    lappend Debugger:bplist $bpinfo

    Debugger:plotBreakpoints $context
}

proc Debugger:removeBreakAtLine {debugfrm bpinfo} {

    global Debugger:bplist Debugger:f2c

    set context [set Debugger:f2c($debugfrm)]

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set bpnum [lindex $bpinfo 2]
    gdb:removebp $bpnum

    Debugger:suspend $context

    # remove BP from the bplist
    set rmid [lsearch -exact ${Debugger:bplist} $bpinfo]
    set Debugger:bplist [lreplace ${Debugger:bplist} $rmid $rmid]

    # remove BP tag from the source windows
    Debugger:unplotBreakpoint $context $bpinfo
}

proc Debugger:toggleBreakAtLine {debugfrm bpinfo {status {}}} {

    global Debugger:bplist Debugger:f2c

    set context [set Debugger:f2c($debugfrm)]

    if {$status == {}} {
	# default action -- complement the current bp state
	if {[lindex $bpinfo 1] == "enabled"} {
	    set status disabled
	} {
	    set status enabled
	}
    }

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set bpnum [lindex $bpinfo 2]

    if {$status == "enabled"} {
	gdb:enablebp $bpnum
    } {
	if {[gdb:disablebp $bpnum] == "false"} {
	    # Failed to disable -- don't change status
	    set status enabled
	}
    }

    Debugger:suspend $context

    # find BP to update in the bplist
    set id [lsearch -exact ${Debugger:bplist} $bpinfo]

    # update enabled/disabled status
    set bpinfo [lreplace $bpinfo 1 1 $status]
    set Debugger:bplist [lreplace ${Debugger:bplist} $id $id $bpinfo]

    # update BP tag in the source windows
    Debugger:plotBreakpoints $context
}

proc Debugger:plotBreakpoints {context {debugfrm {}}} {

    global Debugger:bplist Debugger:c2f Debugger:f2s
    global Debugger:f2w

    if {$debugfrm != {}} {
	set framelist $debugfrm
    } {
	set framelist [set Debugger:c2f($context)]
    }

    set bpid 0

    foreach bpinfo ${Debugger:bplist} {
	foreach {focus state bpnum bpfile lineno cond supp} $bpinfo {
	    foreach debugfrm $framelist {
		set filepath [set Debugger:f2s($debugfrm)]
		if {$bpfile != $filepath} {
		    continue
		}
		set textw [set Debugger:f2w($debugfrm,source)]
		$textw configure -state normal
		$textw delete $lineno.0
		set bpwin $textw.$bpnum
		switch -- $state {
		    enabled {
			set image [fetchImage stopenb]
		    }
		    disabled {
			set image [fetchImage stopdis]
		    }
		    oneshot {
			set image [fetchImage stoptmp]
		    }
		}
		# we could have used an embedded image here...
		label $bpwin -bd 0 -relief flat -padx 0 -pady 0 \
		    -image $image -background [$textw cget -background]
		setDynamicTooltip $bpwin "Debugger:computeBPFocus $bpid" 0
		$textw window create $lineno.0 -window $bpwin
		$textw configure -state disabled
	    }
	}
	incr bpid
    }
}

proc Debugger:unplotBreakpoint {context bpinfo} {

    global Debugger:c2f Debugger:f2s Debugger:f2w

    set framelist [set Debugger:c2f($context)]
    set bpnum [lindex $bpinfo 2]
    set bpfile [lindex $bpinfo 3]

    foreach debugfrm $framelist {
	set filepath [set Debugger:f2s($debugfrm)]
	if {$bpfile == $filepath} {
	    set textw [set Debugger:f2w($debugfrm,source)]
	    catch { destroy $textw.$bpnum }
	}
    }
}

proc Debugger:editBreakpoints {debugfrm} {

    global Debugger:bplist Debugger:f2c
    global Debugger:bpToolTips Debugger:bpLocation

    set context [set Debugger:f2c($debugfrm)]

    set w $context.editbp
    toplevel $w
    wm title $w "Debug Breakpoints"
    bind $w <Escape> "destroy $w"
    cascadeWindow $w

    set toolbar [frame $w.toolbar -bd 1 -relief groove]
    pack $toolbar -side top -fill x

    set toggles $toolbar.toggles
    tixSelect $toggles -allowzero true -radio true
    pack $toggles -expand no -anchor w -padx 4 -pady 4 -side left

    set inputfield $toolbar.inputfield
    set Debugger:bpLocation {}
    tixComboBox $inputfield -dropdown true -label "Stop at: " \
	-editable true \
	-grab local \
	-history true \
	-prunehistory true \
	-variable Debugger:bpLocation \
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

    $toggles add addbp -image [fetchImage stopadd]
    Workspace:addToolTip $toggles addbp Debugger:bpToolTips \
	"Add breakpoint" "Create a new breakpoint in program"
    $toggles add rembp -image [fetchImage stoprem]
    Workspace:addToolTip $toggles rembp Debugger:bpToolTips \
	"Remove breakpoint(s)" "Remove selected/all breakpoint(s) from program"
    $toggles add togglebp -image [fetchImage stoptoggle]
    Workspace:addToolTip $toggles togglebp Debugger:bpToolTips \
	"Toggle breakpoint(s)" "Enable/Disable selected/all breakpoint(s)"

    tixScrolledHList $lbf.list -options {
	hlist.columns 4
	hlist.header true
	hlist.selectmode single
	hlist.drawbranch 0
	hlist.indent 5
	hlist.height 10
	hlist.width 85
    }

    pack $lbf.list -expand yes -fill both
    set hlist [$lbf.list subwidget hlist]
    $hlist column width 0 -char 10
    $hlist column width 1 -char 25
    $hlist column width 2 -char 20
    $hlist column width 3 -char 30
    $hlist header create 0 -itemtype text -text State/ID \
	-style rootTextStyle
    $hlist header create 1 -itemtype text -text Location \
	-style rootTextStyle
    $hlist header create 2 -itemtype text -text Scope \
	-style rootTextStyle
    $hlist header create 3 -itemtype text -text Condition \
	-style rootTextStyle

    $toggles config -command "Debugger:bpToolbarExec $debugfrm $hlist $toggles $inputfield"

    backmenu $lbf.popup -tearoff 0
    set menu [$lbf.popup subwidget menu]
    $menu add command -label "Enable/Disable" -command \
	 "Debugger:toggleBP $debugfrm $hlist $toggles"
    $menu add command -label "Set condition" -command \
	 "Debugger:condBP $debugfrm $hlist $toggles"
    $menu add command -label "Remove" -command \
	 "Debugger:removeBP $debugfrm $hlist $toggles"
    $lbf.popup validate \
	"Debugger:bpBackMenu $debugfrm $hlist $menu $toggles"
    $lbf.popup bind $hlist

    Debugger:buildBPDisplay $debugfrm $hlist $toggles
    bind $e <Return> "Debugger:addBP $debugfrm $hlist $toggles $inputfield"

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "destroy $w"
    pack $w.bbox -fill x

    set statusbar [frame $w.status -height 20 -relief sunken -bd 1]
    pack $w.status -fill x
    set Debugger:bpToolTips {}
    label $statusbar.message -textvariable Debugger:bpToolTips
    pack $statusbar.message -side left

    tkwait visibility $w
    grab $w
}

proc Debugger:toggleBP {debugfrm hlist toggles} {

    global Debugger:bplist

    set sel [$hlist info selection]

    if {$sel != {}} {
	# toggle the selected breakpoint
	set bpinfo [lindex ${Debugger:bplist} $sel]
	Debugger:toggleBreakAtLine $debugfrm $bpinfo
    } {
	# toggle all breakpoints
	for {set bpnum [expr [llength [$hlist info children]] - 1]} {$bpnum >= 0} {incr bpnum -1} {
	    set bpinfo [lindex ${Debugger:bplist} $bpnum]
	    Debugger:toggleBreakAtLine $debugfrm $bpinfo
	}
    }

    Debugger:buildBPDisplay $debugfrm $hlist $toggles
}

proc Debugger:condBP {debugfrm hlist toggles} {

    global Debugger:bplist

    set sel [$hlist info selection]

    if {$sel == {}} {
	return
    }

    set bpinfo [lindex ${Debugger:bplist} $sel]
    set condition [lindex $bpinfo 5]

    set w [winfo toplevel $hlist].cond
    toplevel $w
    wm title $w "Conditional Breakpoint"
    cascadeWindow $w [winfo toplevel $hlist]
    set lbf [frame $w.lbf -relief raised -bd 1]
    tixLabelEntry $lbf.entry -label "Stop if: " \
	-options {
	    entry.width 30
	}
    set e [$lbf.entry subwidget entry]
    $e configure -textvariable $e:value
    global $e:value
    set $e:value $condition
    bind $e <Return> "Debugger:condBPOk $debugfrm $hlist $sel"
    bind $e <Escape> "destroy $w"
    pack $lbf.entry -pady 5 -padx 15 -anchor w
    $e selection range 0 end
    $e icursor end
    pack $w.lbf -expand yes -fill both

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add ok -text OK -command \
	"Debugger:condBPOk $debugfrm $hlist $sel"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus $e
    tkwait visibility $w
    grab $w
}

proc Debugger:condBPOk {debugfrm hlist sel} {

    global Debugger:bplist

    set bpinfo [lindex ${Debugger:bplist} $sel]
    set bpnum [lindex $bpinfo 2]
    set w [winfo toplevel $hlist].cond
    set lbf $w.lbf
    set e [$lbf.entry subwidget entry]

    global $e:value
    set condition [set $e:value]
    set cmd "setbpcondition $bpnum [list $condition]"

    # the stop condition should be set in the current program scope: so use
    # the evaluation worker to reinstate it and perform the command.
    if {[DataDisplay:evalWorker $debugfrm $cmd false] != {}} {
	global gdb:lastexpr
	set condition [set gdb:lastexpr]
	set bpinfo [lreplace $bpinfo 5 5 $condition]
	set Debugger:bplist [lreplace ${Debugger:bplist} $sel $sel $bpinfo]
	$hlist item config $sel 3 -text $condition
    } {
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

proc Debugger:removeBP {debugfrm hlist toggles} {

    global Debugger:bplist

    set sel [$hlist info selection]

    if {$sel != {}} {
	# remove the selected breakpoint
	set bpinfo [lindex ${Debugger:bplist} $sel]
	Debugger:removeBreakAtLine $debugfrm $bpinfo
    } {
	# remove all breakpoints
	set bpcount [llength [$hlist info children]]

	if {$bpcount == 0} {
	    return
	}
	if {[tk_messageBox \
		 -message "About to delete all breakpoints...\nAre you sure? Please confirm." \
		 -type yesno -icon warning -title Warning] != "yes"} {
	    return
	}
	while {$bpcount > 0} {
	    set bpinfo [lindex ${Debugger:bplist} 0]
	    Debugger:removeBreakAtLine $debugfrm $bpinfo
	    incr bpcount -1
	}
    }

    Debugger:buildBPDisplay $debugfrm $hlist $toggles
}

proc Debugger:addBP {debugfrm hlist toggles inputfield} {

    global Debugger:bplist
    global Debugger:f2w Debugger:f2c
    global Debugger:bpToolTips

    set stoploc [$inputfield subwidget entry get]

    if {$stoploc == {}} {
	return
    }
    
    $inputfield subwidget entry delete 0 end
    set context [set Debugger:f2c($debugfrm)]

    # get "hard" control over debuggee
    if {[Debugger:resume $context] == "false"} {
	return
    }

    set bpnum [gdb:sethardbp $stoploc]
    
    if {$bpnum != {}} {
	set bploc [gdb:getbpinfo $bpnum]
	if {[llength $bploc] == 4} {
	    # convert "hard" breakpoints to "soft" (synchronized) breakpoints
	    # if we have access to the source. Note that the file path
	    # returned by GDB must already be absolute.
	    # Calling getAbsolutePath canonicalizes the path.
	    set file [getAbsolutePath [lindex $bploc 2]]
	    set lineno [lindex $bploc 3]
	    gdb:removebp $bpnum
	    set bpnum [gdb:setsoftbp $context \
			   {SYSTEM_SCOPE 0} $file $lineno]
	    set bpinfo [list {SYSTEM_SCOPE 0} enabled $bpnum $file $lineno {}]
	} {
	    # "hard" breakpoints have a supplemental info. field tacked
	    # to the regular bpinfo list. This field should give the system
	    # address of the breakpoint as defined by the debugger.
	    set bpinfo [list HARD_SCOPE enabled $bpnum {} 0 {} $bploc]
	}
    }

    Debugger:suspend $context

    if {$bpnum == {}} {
	global gdb:lasterror
	set Debugger:bpToolTips [set gdb:lasterror]
	bell -displayof $debugfrm
	return
    }

    lappend Debugger:bplist $bpinfo
    Debugger:plotBreakpoints $context
    Debugger:buildBPDisplay $debugfrm $hlist $toggles
}

proc Debugger:buildBPDisplay {debugfrm hlist toggles} {

    global Debugger:bplist

    $hlist delete all
    set nth 0

    foreach bpinfo ${Debugger:bplist} {
	foreach {focuscmd state bpnum file lineno condition systeminfo} $bpinfo {
	    set filename [file tail $file]
	    if {$focuscmd != "HARD_SCOPE"} {
		# not a hard bp
		set focusinfo [Debugger:getBreakpointFocus $focuscmd]
		set location "at $filename:$lineno"
	    } {
		# hard breakpoints have a misc. information member
		# ending the bpinfo list
		set addr [lindex $systeminfo 0]
		set spot [lindex $systeminfo 1]
		set location "in $spot ($addr)"
		if {$filename != {}} {
		    # got source
		    append location " at $filename:$lineno"
		}
		set focusinfo hard
	    }

	    if {$state == "enabled"} {
		set img stopenb
	    } {
		set img stopdis
	    }

	    $hlist add $nth -itemtype imagetext \
		-image [fetchImage $img] -text $bpnum \
		-style leafImageStyle
	    $hlist item create $nth 1 -itemtype text -text $location \
		-style leafTextStyle
	    $hlist item create $nth 2 -itemtype text -text $focusinfo \
		-style leafTextStyle
	    $hlist item create $nth 3 -itemtype text -text $condition \
		-style leafTextStyle
	}
	incr nth
    }
}

proc Debugger:bpToolbarExec {debugfrm hlist toggles inputfield button state} {
    # a little trick to have the tix select widget
    # behave like a toolbar: a selected button is
    # immediately re-invoked to restore its initial
    # graphic state. This is why the button state is
    # checked to filter out "off" invocations.
    if {$state == 1} {
	global Debugger:bpToolTips
	set Debugger:bpToolTips {}
	$toggles invoke $button
	switch -- $button {
	    addbp {
		Debugger:addBP $debugfrm $hlist $toggles $inputfield
	    }
	    rembp {
		Debugger:removeBP $debugfrm $hlist $toggles
	    }
	    togglebp {
		Debugger:toggleBP $debugfrm $hlist $toggles
	    }
	}
    }
}

proc Debugger:bpBackMenu {debugfrm hlist menu toggles rootx rooty} {

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

proc Debugger:saveBreakpoints {context} {

    global Debugger:bplist
    Project:setResource DebuggerBreakpoints ${Debugger:bplist}
}

# Resynchronizing breakpoints means recalculating their
# symbolic location (i.e. file and linenum). For instance, this
# information may become obsolete after the source directory
# information has been changed at GDB level.

proc Debugger:resynchBreakpoints {context} {

    global Debugger:bplist

    set bplist {}

    foreach bpinfo ${Debugger:bplist} {
	set focuscmd [lindex $bpinfo 0]
	if {$focuscmd != "HARD_SCOPE"} {
	    # only resynchronize "soft" breakpoints for which we
	    # have symbolic information...
	    foreach {focuscmd status bpnum file lineno condition} $bpinfo {
		set bploc [gdb:getbpinfo $bpnum]
		if {$bploc != {}} {
		    set file [lindex $bploc 2]
		    set lineno [lindex $bploc 3]
		    lappend bplist [list $focuscmd $status $bpnum $file $lineno $condition]
		} {
		    lappend bplist $bpinfo
		}
	    }
	} {
	    lappend bplist $bpinfo
	}
    }

    set Debugger:bplist $bplist
}

proc Debugger:restoreBreakpoints {context} {

    global Debugger:bplist

    set bplist [Project:getResource DebuggerBreakpoints]
    set Debugger:bplist {}

    foreach bpinfo $bplist {
	foreach {focuscmd status bpnum file lineno condition} $bpinfo {
	    # validate focus command validity before trying to reinstate
	    # the breakpoint.
	    set focusinfo [Debugger:getBreakpointFocus $focuscmd]
	    if {$focusinfo != {} && $focuscmd != "HARD_SCOPE"} {
		# only reinstate "soft" breakpoints for which we
		# have symbolic information...
		set bpnum [gdb:setsoftbp $context \
			       $focuscmd $file $lineno]
		if {$bpnum == {}} {
		    global gdb:lasterror
		    $context.messages.warning configure \
			-text [set gdb:lasterror]
		    bell -displayof $context
		} {
		    if {$condition != {}} {
			if {[gdb:setbpcondition $bpnum $condition] == {}} {
			    global gdb:lasterror
			    $context.messages.warning configure \
				-text [set gdb:lasterror]
			    bell -displayof $context
			    set condition {}
			}
		    }
		    lappend Debugger:bplist [list $focuscmd $status $bpnum \
						 $file $lineno $condition]
		    if {$status == "disabled"} {
			gdb:disablebp $bpnum
		    }
		}
	    }
	}
    }
}
