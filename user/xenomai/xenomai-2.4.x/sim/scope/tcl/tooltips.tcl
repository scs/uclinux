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

proc setDynamicTooltip {w validatecmd {delay 1000}} {

    bind $w <Motion> "+tooltipDynamicPopUp %W \"$validatecmd\" $delay %X %Y"
    bind $w <Leave> {+tooltipPopDown %W}
}

proc setStaticTooltip {w msg {delay 800} {showtime 3500}} {

    bind $w <Enter> "tooltipStaticPopUp %W [list $msg] $delay $showtime %X %Y"
    bind $w <Leave> {tooltipPopDown %W}
}

proc tooltipDynamicPopUp {w cmd delay X Y} {

    global $w:timer

    set msg [eval $cmd $w $X $Y]
    set exists [winfo exists $w.tooltip]

    if {$msg == {}} {
	if {$exists} {
	    after cancel $w:timer
	    destroy $w.tooltip
	}
	return
    }

    # add a small offset to make tooltips fall below the cursor
    set Y [expr $Y+15]

    if {$exists} {
	if {[$w.tooltip.l cget -text] != $msg} {
	    # make the tooltip window follow the mouse
	    # only if the message actually changed in
	    # respect to the currently displayed label.
	    $w.tooltip.l config -text $msg
	    wm geometry $w.tooltip +${X}+${Y}
	}
    } {
	toplevel $w.tooltip
	# Now pop up the new widgetLabel
	wm overrideredirect $w.tooltip 1
	wm geometry $w.tooltip +${X}+${Y}
	label $w.tooltip.l -text $msg -border 1 -relief solid -bg \#ccffcc -padx 5
	pack $w.tooltip.l
	wm withdraw $w.tooltip
	set $w:timer [after $delay "catch { wm deiconify $w.tooltip }"]
    }
}

proc tooltipStaticPopUp {w msg delay showtime X Y} {

    global $w:timer

    if {[winfo exists $w.tooltip]} {
	return
    }

    # substract a small offset to make tooltips raise above the cursor
    set Y [expr $Y-20]
    set X [expr $X+3]
    toplevel $w.tooltip
    # Now pop up the new widgetLabel
    wm overrideredirect $w.tooltip 1
    wm geometry $w.tooltip +${X}+${Y}
    wm withdraw $w.tooltip
    label $w.tooltip.l -text $msg -border 1 -relief solid -bg \#ffff60 -padx 5
    pack $w.tooltip.l
    set $w:timer [after $delay "tooltipStaticRaise $w $showtime"]
}

proc tooltipStaticRaise {w showtime} {

    global $w:timer

    if {[catch {wm deiconify $w.tooltip}] == 0} {
	if {$showtime > 0} {
	    set $w:timer [after $showtime "destroy $w.tooltip"]
	}
    }
}

proc tooltipPopDown {w} {
    if {[catch {destroy $w.tooltip}] == 0} {
	global $w:timer
	catch { after cancel [set $w:timer] }
    }
}
