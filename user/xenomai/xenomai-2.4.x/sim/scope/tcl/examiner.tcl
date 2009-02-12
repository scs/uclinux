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
#  - Adapted to XENOMAI by Philippe Gerum.
#  - "Instruction" formatting by Viktor Tarasov <vtarasov@idealx.com>.

# this variable tells if the examiner was popped up
# during the current debug session.
set Examiner:poppedUp false

proc Examiner:initialize {context} {

    global Examiner:poppedUp

    set Examiner:poppedUp false
    set w $context.examiner
    toplevel $w
    wm title $w Examiner
    wm protocol $w WM_DELETE_WINDOW "wm withdraw $w"
    bind $w <Escape> "wm withdraw $w"
    cascadeWindow $w
    wm withdraw $w

    # build the menubar

    set mbar [frame $w.mbar -relief groove]
    pack $mbar -side top -fill x

    menubutton $mbar.file -text File \
	-menu $mbar.file.m \
	-underline 0 \
	-takefocus 0
    menu $mbar.file.m -tearoff false

    $mbar.file.m add command -label "Save log" \
	-command "Examiner:saveLog $context" \
	-underline 0

    $mbar.file.m add command -label "Clear log" \
	-command "Examiner:clearLog $context" \
	-underline 0

    $mbar.file.m add sep

    $mbar.file.m add command -label Close \
	-command "wm withdraw $w" \
	-underline 0

    pack $mbar.file -side left

    # build the display buffer 
    tixScrolledText $w.text -scrollbar auto -takefocus 0 -options {
	text.width 80
	text.height 24
    }
    set textw [$w.text subwidget text]
    $textw tag config highlight -foreground blue
    $textw tag config error -foreground red
    $textw config -state disabled
    pack $w.text -expand yes -fill both

    # build base selectors

    set format $w.format

    tixLabelFrame $format -label Format \
	-labelside acrosstop -options {
	    label.padX 5
	}

    pack $format -expand no -fill x -anchor nw -side top
    set lbf [$format subwidget frame]

    set subf1 [frame $lbf.col0 -relief flat -bd 0]
    pack $subf1 -side left -expand yes -fill both
    set i 0

    foreach button {hex octal decimal} {
	radiobutton $subf1.$i -text $button \
	    -variable $w.base:value -value $button \
	    -relief flat -pady 0 -padx 10
	pack $subf1.$i -side top -pady 0 -anchor w -padx 5
	incr i
    }

    set subf2 [frame $lbf.col1 -relief flat -bd 0]
    pack $subf2 -side left -expand yes -fill both
    set i 0

    foreach button {binary unsigned string} {
	radiobutton $subf2.$i -text $button \
	    -variable $w.base:value -value $button \
	    -relief flat -pady 0
	pack $subf2.$i -side top -pady 0 -anchor w -padx 5
	incr i
    }

    set subf3 [frame $lbf.col2 -relief flat -bd 0]
    pack $subf3 -side left -expand yes -fill both
    set i 0

    foreach button {char float address} {
	radiobutton $subf3.$i -text $button \
	    -variable $w.base:value -value $button \
	    -relief flat -pady 0
	pack $subf3.$i -side top -pady 0 -anchor w -padx 5
	incr i
    }

    set subf4 [frame $lbf.col3 -relief flat -bd 0]
    pack $subf4 -side left -expand yes -fill both
    set i 0

    foreach button {instruction native} {
	radiobutton $subf4.$i -text $button \
	    -variable $w.base:value -value $button \
	    -relief flat -pady 0
	pack $subf4.$i -side top -pady 0 -anchor w -padx 5
	incr i
    }

    # build the expression frame

    tixLabelFrame $w.expr -labelside none
    pack $w.expr -expand no -fill x
    set lbf [$w.expr subwidget frame]

    ## display mode

    tixOptionMenu $lbf.mode \
 	-options {
 	    menubutton.bd 0
 	    menubutton.relief flat
 	}

    $lbf.mode add command dump  -label Dump
    $lbf.mode add command eval -label Eval
    pack $lbf.mode -expand no -fill none -pady 0 -anchor e -side left

    tixComboBox $lbf.combo \
	-label {} \
	-labelside left \
	-dropdown true \
	-editable true \
	-grab local \
	-history true \
	-prunehistory true \
	-options {
	    slistbox.scrollbar auto
	    listbox.height 8
	    listbox.width 20
	    label.padX 0
	    entry.width 45
	}

    focus [$lbf.combo subwidget entry]
    pack $lbf.combo -pady 8 -padx 0 -anchor w -side left

    # note: there is a bug in the tixControl (and tixCombo) widget(s)
    # which blows when none value of the labelside attribute.
    # Kludge:: assign an empty label on the left side of the widget.

    tixControl $lbf.count \
	-label {} \
	-labelside left \
	-integer true \
	-min 1 \
	-max [expr 64 * 1024] \
	-padx 2 \
	-allowempty false \
	-options {
	    entry.width 5
	}

    tixOptionMenu $lbf.size -labelside none \
 	-options {
 	    menubutton.bd 0
 	    menubutton.relief flat
 	}

    foreach unit {byte short long giant} {
	$lbf.size add command $unit -label ${unit}s
    }

    # size and count will be packed by switchMode when needed

    Examiner:restoreSettings $context

    # note: bindings for the combo entry is set inside setState()
    $lbf.mode config -command "Examiner:switchMode $context"
    $lbf.mode config -variable $w.mode:value
    $lbf.combo config -variable $w.expr:value
    $lbf.size config -variable $w.size:value
    $lbf.count config -variable $w.count:value

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add examine -text Examine -command "Examiner:apply $context"
    $w.bbox add clear -text Clear -command "$lbf.combo subwidget entry delete 0 end"
    $w.bbox add dismiss -text Close -command "wm withdraw $w"
    pack $w.bbox -side bottom -expand no -fill x
}

proc Examiner:popup {context} {

    global Examiner:poppedUp
    set Examiner:poppedUp true
    set w $context.examiner
    wm deiconify $w
    raise $w
}

proc Examiner:setState {context state} {
    
    set w $context.examiner
    if {[winfo exists $w]} {
	set entry [[$w.expr subwidget frame].combo subwidget entry]
	# Note: we override the default binding for <Return> on the
	# combo box entry field to prevent the command callback from
	# being fired when TAB is used to navigate between the fields. This
	# way, picking a value from the history won't trigger the evaluation
	# either (which would be a disturbing behavior in this context).
	# FIXME: a brain-dead bug in Tix makes one of its internal
	# binding on Escape trigger a Tcl error when the combo is
	# disabled -- to work around this, just inhibit the command
	# when disabled.
	if {$state == "normal"} {
	    bind $entry <Return> "Examiner:apply $context"
	    if {[wm state $w] == "normal"} {
		global Project:settings
		# try refreshing the current evaluation results -- note that we
		# do not use the last debugger break context for evaluating data,
		# as this context is global and we may track expressions containing
		# references to local symbols... This is a bit slower due to the resynch
		# operation involved, but this is more user-friendly...
		Examiner:apply $context {} false
		if {[set Project:settings(Options,autoRaise)] == 1} {
		    raise $w
		}
	    }
	} {
	    bind $entry <Return> {}
	}
	$w.bbox subwidget examine config -state $state
    }
}

proc Examiner:destroy {context} {

    set w $context.examiner

    if {[winfo exists $w]} {
	Examiner:saveSettings $context
	destroy $w
    }
}

proc Examiner:switchMode {context mode} {

    set w $context.examiner
    set lbf [$w.expr subwidget frame]

    if {$mode == "eval"} {
	pack forget $lbf.count
	pack forget $lbf.size
    } {
	pack $lbf.count -expand no -fill none -pady 5 -anchor w -side left
	pack $lbf.size -expand no -fill none -pady 0 -anchor w -side left
    }
}

proc Examiner:apply {context {expr {}} {inctl false}} {

    set w $context.examiner

    global $w.mode:value

    set mode [set $w.mode:value]
    set combo [$w.expr subwidget frame].combo
    set expr [string trim [$combo subwidget entry get]]

    if {$expr == {} || [wm state $w] != "normal"} {
	return
    }

    if {$mode == "eval"} {
	Examiner:eval $context $expr $inctl
    } {
	Examiner:dump $context $expr $inctl
    }
}

proc Examiner:dump {context expr {inctl false}} {

    global Debugger:operating
    global gdb:lastexpr

    set w $context.examiner

    global $w.base:value
    global $w.size:value
    global $w.count:value

    set format [set $w.base:value]
    set size [set $w.size:value]
    set count [set $w.count:value]

    set value [DataDisplay:dumpExpr ${Debugger:operating} $expr $format $count $size $inctl]
    set textw [$w.text subwidget text]
    $textw config -state normal
    $textw insert end "Dumping $count ${size}(s) from [set gdb:lastexpr]:\n"
    if {$value == {}} {
	global gdb:lasterror
	set value [set gdb:lasterror]
	set valtag error
    } {
	set valtag highlight
    }
    foreach l $value {
	$textw insert end "$l\n" $valtag
    }
    $textw insert end "\n"
    $textw config -state disabled
    $textw see end
}

proc Examiner:eval {context expr {inctl false}} {

    global Debugger:operating
    global gdb:lastexpr

    set w $context.examiner

    global $w.base:value
    set format [set $w.base:value]
    set value [DataDisplay:evalExpr ${Debugger:operating} $expr $format $inctl]
    set textw [$w.text subwidget text]
    $textw config -state normal
    $textw insert end "[set gdb:lastexpr] = "
    if {$value == {}} {
	global gdb:lasterror
	set value [set gdb:lasterror]
	set valtag error
    } {
	set valtag highlight
    }
    foreach l $value {
	$textw insert end "$l\n" $valtag
    }
    $textw insert end "\n"
    $textw config -state disabled
    $textw see end
}

proc Examiner:saveLog {context} {

    set w $context.examiner.savelog

    if {[winfo exists $w]} {
	wm deiconify $w
	raise $w
	return
    }

    toplevel $w
    wm title $w "Save Examiner Log"
    cascadeWindow $w
    
    set f [frame $w.f -relief sunken -bd 1]
    pack $f

    tixFileEntry $f.logfile -label "To file: " \
 	-variable $w.logfile \
	-validatecmd "Examiner:valLogFileName" \
	-dialogtype tixFileSelectDialog \
 	-options {
 	    entry.width 25
 	    label.anchor e
	}
    pack $f.logfile -side top -anchor e -padx 10 -pady 10
    set e [$f.logfile subwidget entry]
    bind $e <Return> "Examiner:saveLogOk $context"
    bind $e <Escape> "destroy $w"

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add update -text Save \
 	-command "Examiner:saveLogOk $context"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus $e
}

proc Examiner:saveLogOk {context} {

    set w $context.examiner.savelog
    $w.f.logfile update
    global $w.logfile
    set filename [set $w.logfile]

    if {$filename == ""} {
	tk_messageBox -parent $context.examiner \
	    -message "No log file selected" \
	    -type ok -icon error -title " "
	return
    }

    if {[file exists $filename] == 1} {
    	if {[tk_messageBox -parent $context.examiner \
		 -message "File already exists. Overwrite it?" \
		 -type yesnocancel -icon error -title " "] != "yes"} {
	    return
	}
    }

    if {[catch {open $filename w} fh]} {
	# File can't be written.
    	tk_messageBox -parent $context.examiner \
	    -message "Cannot write to file $filename" \
	    -type ok -icon error -title " "
	return
    }

    set textw [$context.examiner.text subwidget text]
    puts -nonewline $fh [$textw get 1.0 end]
    close $fh
    destroy $w
}

proc Examiner:valLogFileName {path} {

    if {$path != ""} {
	if {[file isdirectory $path] == 1} {
	    return ""
	}
	if {[file extension $path] == {}} {
	    append path ".exa"
	}
    }

    return $path
}

proc Examiner:clearLog {context} {

    if {[tk_messageBox -parent $context.examiner \
	     -message "Are you sure? Please confirm." \
	     -type okcancel -icon error -title " "] != "ok"} {
	return
    }

    set textw [$context.examiner.text subwidget text]
    $textw configure -state normal
    $textw delete 1.0 end
    $textw configure -state disabled
}

proc Examiner:saveSettings {context} {

    global Examiner:poppedUp

    set w $context.examiner

    global $w.base:value
    global $w.size:value
    global $w.count:value
    global $w.expr:value
    global $w.mode:value

    if {${Examiner:poppedUp} == "true"} {
	set geometry [wm geometry $w]
    } {
	# otherwise, it has no valid geometry, so don't
	# try to save it.
	set geometry {}
    }

    set settings [list [set $w.base:value] \
		      [set $w.size:value] \
		      [set $w.count:value] \
		      [set $w.expr:value] \
		      [set $w.mode:value] \
		      [wm state $w] \
		      $geometry]

    # save the first 20 historized items -- note that we cannot use the "history limit"
    # attribute from a combo. It does prevent more than 20 items to be entered in
    # the history, but it does not behave in a FIFO manner with the oldest strings
    # but rather locks out the newest one!... :-(
    set history [[$w.expr subwidget frame].combo subwidget listbox]
    lappend settings [lrange [$history get 0 end] 0 19]
    Project:setResource DebuggerExaminer $settings
}

proc Examiner:restoreSettings {context} {

    set w $context.examiner

    global $w.base:value
    global $w.size:value
    global $w.count:value
    global $w.expr:value
    global $w.mode:value

    set settings [Project:getResource DebuggerExaminer]
    set $w.base:value [lindex $settings 0]
    set $w.size:value [lindex $settings 1]
    set $w.count:value [lindex $settings 2]
    set $w.expr:value [lindex $settings 3]
    set $w.mode:value [lindex $settings 4]
    set state [lindex $settings 5]
    set geometry [lindex $settings 6]
    set histlist [lindex $settings 7]

    # set reasonable defaults if none exists

    if {[set $w.base:value] == {}} {
	set $w.base:value hex
    }
    if {[set $w.size:value] == {}} {
	set $w.size:value byte
    }
    if {[set $w.count:value] == {}} {
	set $w.count:value 16
    }
    if {[set $w.mode:value] == {}} {
	set $w.mode:value eval
    }

    set combo [$w.expr subwidget frame].combo

    foreach e $histlist {
	$combo appendhistory $e
    }

    if {$geometry != {}} {
	wm geometry $w $geometry
    }

    if {$state == "normal"} {
	Examiner:popup $context
    }
}
