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

proc psosqueue:attach {context name private} {

    global $context.info
    set $context.info(present) yes
    set $context.info(changed) no
    return [list [list {pSOS+ emulation} Queues $name] queue]
}

proc psosqueue:detach {context} {

    global $context.info
    unset $context.info
    catch { destroy $context }
}

proc psosqueue:show {context name} {

    if {[winfo exists $context]} {
	wm deiconify $context
	raise $context
    }

    psosqueue:pollInfo $context
}

proc psosqueue:event {context event} {

    switch $event {
	SimulationHeldEvent {
	    if {[catch { wm state $context } state] == 0} {
		if {$state != "withdrawn"} {
		    psosqueue:pollInfo $context
		}
	    }
	}
    }
}

proc psosqueue:update {context name info} {

    global $context.info

    # dispatch the information block contents
    # to the per-context data array...
    foreach e $info {
	set item [lindex $e 0]
	set value [lindex $e 1]
	set $context.info($item) $value
    }

    set $context.info(current) $info
    set $context.info(changed) no

    if {[winfo exists $context]} {
	set msgfrm [$context.sw1 subwidget frame]
	set lbox [$msgfrm.list subwidget listbox]
	$lbox delete 0 end

	foreach msg [set $context.info(messages)] {
	    $lbox insert end $msg
	}

	set taskfrm [$context.sw2 subwidget frame]
	psostask:fillWaitList $context $taskfrm.list
	return
    }

    # if the queue object has never been displayed before,
    # build a brand new toplevel for it...

    toplevel $context
    wm title $context "pSOS+ queue: $name"
    cascadeWindow $context
    wm protocol $context WM_DELETE_WINDOW \
	"wm withdraw $context"

    # Messages

    tixLabelFrame $context.sw1 -label Messages \
	-labelside acrosstop -options {
	    label.padx 5
	}

    pack $context.sw1 -expand true -fill both
    set msgfrm [$context.sw1 subwidget frame]
    tixScrolledListBox $msgfrm.list -scrollbar auto
    pack $msgfrm.list -expand true -fill both
    set lbox [$msgfrm.list subwidget listbox]
    $lbox config -height 5 -bd 2

    foreach msg [set $context.info(messages)] {
	$lbox insert end $msg
    }

    set type [set $context.info(type)]

    # can alter fixed-message queue contents only.

    if {$type == "fixed"} {
	backmenu $msgfrm.popup -tearoff 0
	set menu [$msgfrm.popup subwidget menu]
	$menu add command -label "Insert" -command \
	    "psosqueue:insertMsg $context $lbox $name"
	$menu add command -label "Append" -command \
	    "psosqueue:insertMsg $context $lbox $name append"
	$menu add command -label "Remove" -command \
	    "psosqueue:removeMsg $context $lbox"
	$msgfrm.popup validate \
	    "psosqueue:msgBackMenu $context $lbox $menu"
	$msgfrm.popup bind $lbox
    }

    # Pending tasks

    tixLabelFrame $context.sw2 -label "Pending list" \
	-labelside acrosstop -options {
	    label.padx 5
	}

    pack $context.sw2 -expand true -fill both
    set taskfrm [$context.sw2 subwidget frame]
    tixScrolledListBox $taskfrm.list -scrollbar auto \
	-command "psostask:pickWaitList $context $taskfrm.list"
    pack $taskfrm.list -expand true -fill both
    $taskfrm.list subwidget listbox config -height 5 -bd 2
    psostask:fillWaitList $context $taskfrm.list

    # Button box

    tixButtonBox $context.bbox -orientation horizontal -relief flat -bd 0
    $context.bbox add update -text Update \
	-command "psosqueue:pollInfo $context"
    $context.bbox add apply -text Apply \
	-command "psosqueue:applyChanges $context"
    $context.bbox add cancel -text Dismiss \
	-command "wm withdraw $context"
    pack $context.bbox -side bottom -fill x
}

proc psosqueue:pollInfo {context} {
    TkRequest $context GetDashboardInfo all
}

proc psosqueue:applyChanges {context} {

    global $context.info

    set status [set $context.info(changed)]

    if {$status == "yes"} {
	set $context.info(changed) no
	TkRequest $context ConfigureDashboard \
	    [list messages [set $context.info(messages)]]
    }
}

proc psosqueue:msgBackMenu {context lbox menu rootx rooty} {

    $lbox selection clear 0 end
    # turn root coordinates into local coordinates
    set y [expr $rooty - [winfo rooty $lbox]]
    set msgnum [$lbox nearest $y]

    if {$msgnum != -1} {
	$lbox selection set $msgnum
	$menu entryconfigure 2 -state normal
    } {
	$menu entryconfigure 2 -state disabled
    }

    return true
}

proc psosqueue:insertMsg {context lbox name {mode prepend}} {

    set msgnum [$lbox curselection]

    if {$msgnum == {}} {
	set msgnum 0
    }

    if {$mode == "append"} {
	incr msgnum
    }

    set w $context.newmsg
    toplevel $w
    wm title $w "Insert Message #$msgnum"
    cascadeWindow $w

    tixLabelEntry $w.msg -label "Message value:" -state normal
    $w.msg subwidget entry configure -width 20
    pack $w.msg -anchor w -pady 5 -padx 5
    set e [$w.msg subwidget entry]
    bind $e <Return> "psosqueue:validateMsg $context $lbox $w.msg $msgnum"
    bind $e <Escape> "destroy $w"
    focus $e

    ## Button box

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add insert -text Insert -command "psosqueue:validateMsg $context $lbox $w.msg $msgnum"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    tkwait visibility $w
    grab $w
}

proc psosqueue:validateMsg {context lbox entry msgnum} {

    global $context.info
    
    set s [$entry subwidget entry get]

    if {$s == {}} {
	# no value -- ignore
	destroy $context.newmsg
	return
    }

    set msg {}

    foreach mstring [split $s " ,"] {
	if {$mstring == {}} {
	    continue
	}
	if {[regexp "^0\[xX\]\[0-9a-fA-F\]+\[Ll\]?$" $mstring val] == 1} {
	    scan $mstring "%x" val
	} elseif {[regexp "^\[0-9\]+\[Ll\]?$" $mstring val] == 1} {
	    scan $mstring "%d" val
	} {
	    # not a valid message value
	    tk_messageBox -parent $context.newmsg \
		-message "Bad message value: $mstring" \
		-type ok -icon error -title Error
	    raise $context.newmsg
	    return
	}

	# normalize value to an hexadecimal integer
	lappend msg [format "0x%x" $val]
    }

    # keep first four values for fixed-message
    set msg [lrange $msg 0 3]
    while {[llength $msg] < 4} {
	# pad incomplete msg
	lappend msg 0x0
    }

    set $context.info(messages) \
	[linsert [set $context.info(messages)] $msgnum $msg]
    $lbox insert $msgnum $msg
    set $context.info(changed) yes
    destroy $context.newmsg
}

proc psosqueue:removeMsg {context lbox} {

    global $context.info

    set msgnum [$lbox curselection]

    if {$msgnum != {}} {
	set $context.info(messages) \
	    [lreplace [set $context.info(messages)] $msgnum $msgnum]
	$lbox delete $msgnum

	set $context.info(changed) yes
    }
}
