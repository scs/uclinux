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

#  global tcl_traceExec
#  set tcl_traceExec 1

set DataDisplay:hiddenExprList(0,0,0,0) {}
set DataDisplay:userExprList(0,0,0,0) {}
set DataDisplay:tracedEntryList(0,0,0,0) {}
set DataDisplay:localNatives(0,0,0,0) {}
set DataDisplay:seqNum 0
set DataDisplay:typeTagNum 0

proc DataDisplay:makeGlobalsTree {context} {

    global Application:treeSeparator
    global DataDisplay:tracedEntryList DataDisplay:hiddenExprList

    set w $context.gbldisp
    toplevel $w
    wm title $w "Globals Display"
    wm protocol $w WM_DELETE_WINDOW "wm withdraw $w"
    bind $w <Escape> "wm withdraw $w"
    cascadeWindow $w $context
    TkRequest $context CacheWindowIn $w Globals

    frame $w.f
    pack $w.f -expand yes -fill both
    set tree $w.f.tree

    tixTree $tree -options {
	hlist.width 50
	hlist.height 25
    }

    pack $tree -fill both -expand yes
    set hlist [$tree subwidget hlist]
    $hlist config -separator ${Application:treeSeparator}
    $tree config -opencmd "DataDisplay:openDataNode $context $tree" \
	          -closecmd "DataDisplay:clearDataNode $context $tree"

    $hlist add Globals -style rootTextStyle -itemtype text \
	-text Globals

    DataDisplay:setBackMenu $context $tree

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "wm withdraw $w"
    pack $w.bbox -side bottom -fill x

    set DataDisplay:tracedEntryList($context,Globals,system,0) {}
    set DataDisplay:hiddenExprList($context,Globals,system,0) {}
    DataDisplay:restoreGlobals $context

    $tree setmode Globals none
    wm withdraw $context.gbldisp
}

proc DataDisplay:makeLocalsTree {debugfrm tree} {

    global Application:treeSeparator

    tixTree $tree
    pack $tree -fill both -expand yes
    set hlist [$tree subwidget hlist]
    $hlist config -separator ${Application:treeSeparator}
    $tree config -opencmd "DataDisplay:openDataNode $debugfrm $tree" \
	          -closecmd "DataDisplay:clearDataNode $debugfrm $tree"
    $hlist add Locals -itemtype text -text Locals -style rootTextStyle
    $tree setmode Locals none

    DataDisplay:setBackMenu $debugfrm $tree
}

proc DataDisplay:setBackMenu {debugfrm tree} {

    set hlist [$tree subwidget hlist]
    backmenu $tree.popup -tearoff 0
    set menu [$tree.popup subwidget menu]
    $menu add command -label "Display *" -command \
	"DataDisplay:followData $debugfrm $tree"
    $menu add command -label "Show type" -command \
	"DataDisplay:showType $debugfrm $tree"
    $menu add command -label "Set value" -command \
	"DataDisplay:setExpr $debugfrm $tree"
    $menu add command -label "Remove" -command \
	"DataDisplay:remExpr $debugfrm $tree"
    $menu add sep
    $menu add command -label "Select..." -command \
	"DataDisplay:addExpr $debugfrm $tree"
    $tree.popup validate  \
	"DataDisplay:postBackMenu $debugfrm $menu $hlist"
    $tree.popup bind $hlist
}

proc DataDisplay:postBackMenu {debugfrm menu hlist rx ry} {

    set sensitivity [$hlist cget -command]

    if {$sensitivity == {}} {
	# simulation is running -- (see setTreeState)
	# backmenu is locked down
	return false
    }

    $hlist selection clear
    set top [$hlist info children]
    # turn root coordinates into local coordinates
    set y [expr $ry - [winfo rooty $hlist]]
    set entry [$hlist nearest $y]

    if {$entry != {} && $entry != $top} {
	$hlist selection set $entry
	set ndata [$hlist info data $entry]

	if {$ndata != {}} {
	    # some leaf data (such as unnamed bitfield
	    # members) cannot be reached directly through
	    # a valid name -- do not allow them to be changed
	    # this way.
	    set ntype [lindex $ndata 0]
	    $menu entryconfig 1 -state normal
	    $menu entryconfig 2 -state normal
	    $menu entryconfig 3 -state normal
	    if {$ntype != "node"} {
		# allow dereferencing root and leaf nodes
		# (i.e. all but intermediate "node"-typed entries)
		$menu entryconfig 0 -state normal
	    } {
		$menu entryconfig 0 -state disabled
	    }
	} {
	    $menu entryconfig 0 -state disabled
	    $menu entryconfig 1 -state disabled
	    $menu entryconfig 2 -state disabled
	    $menu entryconfig 3 -state disabled
	}
    } {
	# no expression selected for change.
	$menu entryconfig 0 -state disabled
	$menu entryconfig 1 -state disabled
	$menu entryconfig 2 -state disabled
	$menu entryconfig 3 -state disabled
    }

    return true
}

proc DataDisplay:setExpr {debugfrm tree} {

    set hlist [$tree subwidget hlist]
    set sel [$hlist info selection]

    if {$sel == {}} {
	# Yes! This happened.
	return
    }

    set entry [lindex $sel 0]
    set ndata [$hlist info data $entry]
    set name [lindex $ndata 1]

    set w $tree.set
    toplevel $w
    wm title $w "Set `$name'"
    cascadeWindow $w [winfo toplevel $tree]

    set lbf [frame $w.lbf -relief raised -bd 1]

    tixLabelEntry $lbf.entry -label "New value: " \
	-options {
	    entry.width 20
	}

    set e [$lbf.entry subwidget entry]
    $e configure -textvariable $e:value
    global $e:value
    set $e:value {}
    bind $e <Return> "DataDisplay:setExprOk $debugfrm $tree [list $entry]"
    bind $e <Escape> "destroy $w"
    pack $lbf.entry -pady 5 -padx 15 -anchor w
    pack $w.lbf -expand yes -fill both

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add ok -text OK -command \
	"DataDisplay:setExprOk $debugfrm $tree [list $entry]"
    $w.bbox add cancel -text Cancel -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    focus $e
    tkwait visibility $w
    grab $w
}

proc DataDisplay:setExprOk {debugfrm tree entry} {

    global Debugger:stackinfo Debugger:stacklevel
    global Debugger:f2c

    set context [set Debugger:f2c($debugfrm)]
    set hlist [$tree subwidget hlist]
    set ndata [$hlist info data $entry]
    set w $tree.set
    set lbf $w.lbf
    set e [$lbf.entry subwidget entry]

    global $e:value

    if {[set $e:value] == {}} {
	# silently abort operation on empty input
	destroy $w
	return
    }

    set scope [lindex $ndata 2]
    set gdbvar [lindex $ndata 3]

    if {$scope == "local"} {
	set focuscmd [Debugger:buildFocusCmd $debugfrm]
	set level [set Debugger:stacklevel($debugfrm)]
	set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    } {
	set focuscmd {}
	set fnum {}
    }

    # get control over the debugger (update routines assume this)
    if {[Debugger:resume $context $focuscmd $fnum] == "false"} {
	set log "internal error"
    } {
	set log [gdb:setdata $gdbvar [set $e:value]]
	Debugger:suspend $context $focuscmd
    }

    if {$log != {}} {
	# the "set" command log should be empty -- otherwise, and error occured.
	tk_messageBox -parent $debugfrm \
	    -message [lindex $log 0] \
	    -type ok -icon error -title Error
	raise $w
	return
    } {
	DataDisplay:closeDataNode $debugfrm $tree $entry
	DataDisplay:openDataNode $debugfrm $tree $entry
    }
    
    raise [winfo toplevel $tree]
    destroy $w
}

proc DataDisplay:buildRefPath {hlist entry rootvar} {

    upvar $rootvar root
    set root $entry
    set refpath {}

    while {$root != {}} {
	set ndata [$hlist info data $root]
	set ntype [lindex $ndata 0]
	if {$ntype != "leaf" && $ntype != "node"} {
	    # i.e. must be "native" or "user" in this case:
	    # thus we've found the entry's root...
	    break
	}
	set parent [$hlist info parent $root]
	set refpath [linsert $refpath 0 \
			 [lsearch -exact [$hlist info children $parent] $root]]
	set root $parent
    }

    return $refpath
}

proc DataDisplay:followData {debugfrm tree} {

    global Debugger:f2c
    global Debugger:stackinfo Debugger:stacklevel

    set context [set Debugger:f2c($debugfrm)]
    set hlist [$tree subwidget hlist]
    set sel [$hlist info selection]
    set entry [lindex $sel 0]

    if {[$tree getmode $entry] == "open"} {
	# node to follow is closed -- open it before dereferencing
	DataDisplay:openDataNode $debugfrm $tree $entry
    }

    # Update the reference path list stored in the root entry.
    # Each member of this list is a reference path.
    # This path is a list of dereferenced members on a per-level basis,
    # outer first, inner (deeper) last. Each member is a sub-list of
    # the node positions to follow.
    # For instance, the expressions "*global_var.link->next->link"
    # and "*global_var.next" could generate the following reference
    # path (pretending "next" and "link" respectively are the 4th and
    # 5th members from the top of the "global_var" type (0-based)):
    # {4 3 4} {3}

    set root {}
    set refpath [DataDisplay:buildRefPath $hlist $entry root]
    if {$refpath == {}} {
	# i.e. root entry? put it on the reference path as item no. -1
	set refpath -1
    }
    set rdata [$hlist info data $root]
    set pathlist [lindex $rdata 5]

    if {[lsearch -exact $pathlist $refpath] == -1} {
	lappend pathlist $refpath
	$hlist entryconfig $root -data [concat [lrange $rdata 0 4] [list $pathlist]]
    }

    DataDisplay:dereferenceData $debugfrm $tree $entry
}

proc DataDisplay:dereferenceData {debugfrm tree entry {inctl false}} {

    global Debugger:f2c
    global Debugger:stackinfo Debugger:stacklevel

    set context [set Debugger:f2c($debugfrm)]
    set hlist [$tree subwidget hlist]
    set ndata [$hlist info data $entry]
    set ntype [lindex $ndata 0]
    set ident [lindex $ndata 1]
    set scope [lindex $ndata 2]
    set gdbvar [lindex $ndata 3]

    if {$scope == "local"} {
	set focuscmd [Debugger:buildFocusCmd $debugfrm]
	set level [set Debugger:stacklevel($debugfrm)]
	set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    } {
	set focuscmd {}
	set fnum {}
    }

    # get control over the debugger (if not "in control")

    if {$inctl == "true" ||
	[Debugger:resume $context $focuscmd $fnum] != "false"} {

	set vlist [gdb:followdata $gdbvar]

	if {$inctl == "false"} {
	    Debugger:suspend $context $focuscmd
	}

	if {[lindex $vlist 0] != "@node"} {
	    # the datum accessed by dereferencing a pointer is always
	    # displayed as a sub-tree of the source pointer.
	    set vlist [list @node [list [concat *$ident $vlist]]]
	}

	DataDisplay:displayAggr $debugfrm $tree $entry $gdbvar $vlist
	$tree setmode $entry close
    }

    $hlist entryconfig $entry -style highlightedLeafStyle
}

proc DataDisplay:showTypeWorker {debugfrm hostw expr} {

    global DataDisplay:typeTagNum Debugger:f2c

    set cmd "typeinfo [list $expr]"
    set typeinfo [DataDisplay:evalWorker $debugfrm $cmd false]

    if {$typeinfo == {}} {
	tk_messageBox -parent $debugfrm \
	    -message "No type information available for `$expr'" \
	    -type ok -icon error -title Error
	return {}
    }

    # all typeinfo windows are children of the global data display so
    # that they are destroyed when the simulation is killed.
    set context [set Debugger:f2c($debugfrm)]
    set w $context.gbldisp.typeinfo[incr DataDisplay:typeTagNum]
    toplevel $w
    wm title $w "Type of `$expr'"
    cascadeWindow $w $hostw

    tixScrolledText $w.text -scrollbar auto
    set textw [$w.text subwidget text]
    set lines 0
    set cols 0
    foreach l $typeinfo {
	$textw insert end "$l\n"
	incr lines
	set len [string length $l]
	if {$cols < $len} {
	    set cols $len
	}
    }
    if {$lines < [$textw cget -height]} {
	$textw config -height $lines
    } {
	if {$lines > 40} {
	    # set a reasonable max. height for the text buffer
	    $textw config -height 40
	}
    }
    if {$cols < [$textw cget -width]} {
	$textw config -width $cols
    } {
	if {$width > 80} {
	    # set a reasonable max. width for the text buffer
	    $textw config -width 80
	}
    }
    $textw config -state disabled
    pack $w.text -expand yes -fill both

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add dismiss -text Close -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    bind $w <Escape> "destroy $w"
    focus $w

    return $w
}

proc DataDisplay:showType {debugfrm tree} {

    set hlist [$tree subwidget hlist]
    set sel [$hlist info selection]

    if {$sel == {}} {
	# Yes! This happened.
	return
    }

    set entry [lindex $sel 0]
    set ndata [$hlist info data $entry]
    set gdbvar [lindex $ndata 3]
    DataDisplay:showTypeWorker $debugfrm [winfo toplevel $tree] $gdbvar
}

proc DataDisplay:evalWorker {debugfrm cmd inctl} {

    global Debugger:f2c Debugger:stackinfo Debugger:stacklevel
    global Debugger:xcontext

    set context [set Debugger:f2c($debugfrm)]
    set level [set Debugger:stacklevel($debugfrm)]
    set focuscmd [Debugger:buildFocusCmd $debugfrm]
    set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    set vlist {}

    # get control over the debugger (if not already held)

    if {$inctl == "true" ||
	[Debugger:resume $context $focuscmd $fnum] != "false"} {
	set vlist [eval gdb:$cmd]
	if {$inctl == "false"} {
	    Debugger:suspend $context $focuscmd
	}
    }

    return $vlist
}

proc DataDisplay:evalExpr {debugfrm expr format {inctl false}} {

    set cmd "getdata [list $expr] $format false"
    return [DataDisplay:evalWorker $debugfrm $cmd $inctl]
}

proc DataDisplay:dumpExpr {debugfrm expr format count size {inctl false}} {

    set cmd "dumpdata [list $expr] $format $count $size"
    return [DataDisplay:evalWorker $debugfrm $cmd $inctl]
}

proc DataDisplay:lookupExpr {debugfrm expr {inctl false}} {

    global Debugger:f2c
    global Debugger:stackinfo Debugger:stacklevel
    global Debugger:stacklength

    set context [set Debugger:f2c($debugfrm)]
    set level [set Debugger:stacklevel($debugfrm)]

    catch {
	set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
    }

    set focuscmd [Debugger:buildFocusCmd $debugfrm]
    set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    set location {}

    # get control over the debugger (if not "in control")

    if {$inctl == "true" ||
	[Debugger:resume $context $focuscmd $fnum] != "false"} {
	set location [gdb:locate $expr]
	if {$inctl == "false"} {
	    Debugger:suspend $context $focuscmd
	}
    }

    return $location
}

proc DataDisplay:remExpr {debugfrm tree} {

    global DataDisplay:hiddenExprList DataDisplay:userExprList

    set hlist [$tree subwidget hlist]
    set top [$hlist info children]
    set sel [$hlist info selection]
    set entry [lindex $sel 0]
    set ndata [$hlist info data $entry]
    set ntype [lindex $ndata 0]
    set scope [lindex $ndata 2]

    DataDisplay:clearDataNode $debugfrm $tree $entry

    if {$ntype == "native" || $ntype == "user"} {
	# forgetting a toplevel entry means removing
	# the corresponding expression.
	$tree subwidget hlist delete entry $entry

	if {$top == "Locals"} {
	    global Debugger:stackinfo Debugger:stacklevel
	    global Debugger:stacklength Debugger:xcontext
	    set level [set Debugger:stacklevel($debugfrm)]
	    set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
	    set xcontext [set Debugger:xcontext($debugfrm)]
	} {
	    set depth 0
	    set xcontext system
	}

	if {$ntype == "user"} {
	    set nth [lsearch -exact \
			 [set DataDisplay:userExprList($debugfrm,$top,$xcontext,$depth)] $ndata]
	    if {$nth != -1} {
		set DataDisplay:userExprList($debugfrm,$top,$xcontext,$depth) \
		    [lreplace [set DataDisplay:userExprList($debugfrm,$top,$xcontext,$depth)] $nth $nth]
	    }
	    # forget user-defined expressions
	} {
	    lappend DataDisplay:hiddenExprList($debugfrm,$top,$xcontext,$depth) $ndata
	}
    }
}

proc DataDisplay:addExpr {debugfrm tree} {

    global DataDisplay:hiddenExprList

    set w [winfo toplevel $tree].addexpr
    set top [$tree subwidget hlist info children]
    toplevel $w
    wm title $w "Auto-Display $top"
    cascadeWindow $w

    if {$top == "Locals"} {
	global Debugger:stackinfo Debugger:stacklevel
	global Debugger:stacklength Debugger:xcontext
	    
	set level [set Debugger:stacklevel($debugfrm)]
	set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
	set xcontext [set Debugger:xcontext($debugfrm)]
    } {
	set depth 0
	set xcontext system
    }

    set lbf1 [frame $w.lbf1 -relief raised -bd 1]
    pack $lbf1 -side top -expand yes -fill both

    tixScrolledListBox $lbf1.list -scrollbar auto \
	-command "DataDisplay:pickExpr $debugfrm $tree $lbf1.list \"$xcontext\" $depth"
    set lbox [$lbf1.list subwidget listbox]
    $lbox config -height 15 -width 30
    pack $lbf1.list -expand yes -fill both

    tixLabelFrame $w.lbf2 -label "Auto-display expression" \
	-labelside acrosstop
    pack $w.lbf2 -expand no -fill x
    set lbf2 [$w.lbf2 subwidget frame]
    
    set e $lbf2.entry
    entry $e -width 20
    pack $e -expand no -fill x
    bind $e <Return> "DataDisplay:readExpr $debugfrm $tree $w $e"
    bind $e <Escape> "destroy $w"
    focus $e

    tixButtonBox $w.bbox -orientation horizontal -relief flat -bd 0
    $w.bbox add update -text Close -command "destroy $w"
    pack $w.bbox -side bottom -fill x

    if {[catch {set exprinfo \
		    [set DataDisplay:hiddenExprList($debugfrm,$top,$xcontext,$depth)]}] == 1} {
	set exprinfo {}
    }

    foreach vinfo $exprinfo {
	set ident [lindex $vinfo 1]
	$lbox insert end $ident
    }

    tkwait visibility $w
    grab $w
}

proc DataDisplay:displayVariable {debugfrm tree xcontext depth nth} {

    global DataDisplay:hiddenExprList Application:treeSeparator

    set top [$tree subwidget hlist info children]
    set vinfo [lindex [set DataDisplay:hiddenExprList($debugfrm,$top,$xcontext,$depth)] $nth]
    set DataDisplay:hiddenExprList($debugfrm,$top,$xcontext,$depth) \
	[lreplace [set DataDisplay:hiddenExprList($debugfrm,$top,$xcontext,$depth)] $nth $nth]

    set ntype [lindex $vinfo 0]
    set ident [lindex $vinfo 1]
    set scope [lindex $vinfo 2]
    set gdbvar [lindex $vinfo 3]
    set file [lindex $vinfo 4]
    set entry $top${Application:treeSeparator}$ident

    $tree subwidget hlist add $entry \
	-itemtype text \
	-style leafTextStyle \
	-data [list $ntype $ident $scope $gdbvar $file] \
	-text $ident

    $tree setmode $entry open
    DataDisplay:openDataNode $debugfrm $tree $entry

    return $entry
}

proc DataDisplay:displayExpr {debugfrm tree expr} {

    global DataDisplay:hiddenExprList
    global Application:treeSeparator DataDisplay:seqNum
    global Debugger:stackinfo Debugger:stacklevel
    global Debugger:stacklength Debugger:xcontext
    global Debugger:f2w DataDisplay:userExprList
    global gdb:lastexpr
    
    set hlist [$tree subwidget hlist]
    set top [$hlist info children]

    if {$top == "Locals"} {
	set level [set Debugger:stacklevel($debugfrm)]
	set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
	set xcontext [set Debugger:xcontext($debugfrm)]
    } {
	set depth 0
	set xcontext system
    }

    set gdb:lastexpr $expr

    # Search in the hidden variables
    if {[catch {set exprinfo \
	    [set DataDisplay:hiddenExprList($debugfrm,$top,$xcontext,$depth)]}] == 1} {
	set exprinfo {}
    }

    set nth 0

    foreach vinfo $exprinfo {
	set gdbvar [lindex $vinfo 3]
	if {$gdbvar == $expr} {
	    return [DataDisplay:displayVariable $debugfrm $tree $xcontext $depth $nth]
	}
	incr nth
    }

    # Not a hidden variable -- try among visible user-defined expr.
    # (Remember that user-defined expr. are not stored in the hiding list
    # when removed)
    set allEntries [getHListEntries $hlist $top]

    foreach entry $allEntries {
	set ndata [$hlist info data $entry]
	set ntype [lindex $ndata 0]
	if {$ntype == "user"} {
	    set gdbvar [lindex $ndata 3]
	    if {$gdbvar == $expr} {
		DataDisplay:openDataNode $debugfrm $tree $entry
		return $entry
	    }
	}
    }

    # Not a known variable -- display the expression as a user-defined
    # one inside the target tree. Note that user-defined expr. are
    # assumed to be locally-scoped; this way openDataNode will always
    # reinstate the local context before sending the request to GDB,
    # thus enforcing a local scope precedence over the global one when
    # evaluating such expression.

    set ndata [list user $expr local $expr {}]
    lappend DataDisplay:userExprList($debugfrm,$top,$xcontext,$depth) $ndata
    set entry $top${Application:treeSeparator}@[incr DataDisplay:seqNum]

    $tree subwidget hlist add $entry \
	-itemtype text \
	-style leafTextStyle \
	-data $ndata \
	-text $expr \
	-at 0

    $tree setmode $entry open
    DataDisplay:openDataNode $debugfrm $tree $entry
    update idletasks
    $tree subwidget hlist see $entry 

    return $entry
}

proc DataDisplay:displayExprLocal {debugfrm expr} {

    global Debugger:f2w
    set tree [set Debugger:f2w($debugfrm,locals)]
    Debugger:forceSwitchOn $debugfrm locals
    DataDisplay:displayExpr $debugfrm $tree $expr
}

proc DataDisplay:dereferenceExprLocal {debugfrm expr} {

    global Debugger:f2w
    set tree [set Debugger:f2w($debugfrm,locals)]
    Debugger:forceSwitchOn $debugfrm locals
    set entry [DataDisplay:displayExpr $debugfrm $tree $expr]
    DataDisplay:dereferenceData $debugfrm $tree $entry
}

proc DataDisplay:pickExpr {debugfrm tree slist xcontext depth} {

    global DataDisplay:hiddenExprList Application:treeSeparator

    set lbox [$slist subwidget listbox]
    set nth [$lbox curselection]

    if {$nth != {}} {
	$lbox delete $nth
	DataDisplay:displayVariable $debugfrm $tree $xcontext $depth $nth
    }
}

proc DataDisplay:readExpr {debugfrm tree w e} {

    set expr [$e get]

    if {$expr == {}} {
	# this makes double-Return react as
	# if a Validate+Close sequence has
	# just been entered.
	destroy $w
	return
    }

    $e delete 0 end

    DataDisplay:displayExpr $debugfrm $tree $expr
}

proc DataDisplay:showGlobals {context} {

    global DataDisplay:tracedEntryList

    set w $context.gbldisp
    set oldstate [wm state $w]
    wm deiconify $w

    if {$oldstate != "normal" &&
	[set DataDisplay:tracedEntryList($context,Globals,system,0)] != {}} {
	# window was dismissed - resynch display
	# get control over debugger
	if {[Debugger:resume $context] != "false"} {
	    DataDisplay:updateGlobalData $context
	    Debugger:suspend $context
	}
    }

    raise $w
}

proc DataDisplay:visibleGlobals {context} {
    set w $context.gbldisp
    set state [wm state $w]
    if {$state != "normal"} {
	return false
    }
    return true
}

proc DataDisplay:destroyGlobals {context} {
    global DataDisplay:tracedEntryList
    global DataDisplay:hiddenExprList
    global DataDisplay:userExprList
    # hiding means destroying in this case
    catch { DataDisplay:saveGlobals $context }
    catch { destroy $context.gbldisp }
    catch { unset DataDisplay:tracedEntryList($context,Globals,system,0) }
    catch { unset DataDisplay:hiddenExprList($context,Globals,system,0) }
    catch { unset DataDisplay:userExprList($context,Globals,system,0) }
}

proc DataDisplay:hideLocals {debugfrm tree} {
    global DataDisplay:tracedEntryList
    global DataDisplay:hiddenExprList
    global DataDisplay:userExprList

    set hlist [$tree subwidget hlist]
    set top [$hlist info children]
    $hlist delete offsprings $top

    foreach subscript \
	[array names DataDisplay:tracedEntryList $debugfrm,Locals,*,*] {
	set DataDisplay:tracedEntryList($subscript) {}
    }
    foreach subscript \
	[array names DataDisplay:hiddenExprList $debugfrm,Locals,*,*] {
	set DataDisplay:hiddenExprList($subscript) {}
    }
    foreach subscript \
	[array names DataDisplay:userExprList $debugfrm,Locals,*,*] {
	set DataDisplay:userExprList($subscript) {}
    }
}

proc DataDisplay:updateGlobalData {context} {

    # do not actually update the tree if the window is dismissed
    # or does not even exist (e.g. fatal error at startup)
    if {[winfo exists $context.gbldisp] == 1 &&
	[wm state $context.gbldisp] == "normal"} {
	global DataDisplay:tracedEntryList Project:settings
	set tree $context.gbldisp.f.tree
	if {[set Project:settings(Options,autoRaise)] == 1} {
	    raise $context.gbldisp
	}
	foreach entry [set DataDisplay:tracedEntryList($context,Globals,system,0)] {
	    DataDisplay:displayDataNode $context $tree $entry
	}
    }
}

proc DataDisplay:updateLocalData {debugfrm tree {autofocus true}} {

    global DataDisplay:tracedEntryList Debugger:stacklevel
    global Debugger:stackinfo Debugger:stacklength
    global Debugger:xcontext DataDisplay:hiddenExprList
    global DataDisplay:userExprList DataDisplay:localNatives
    global DataDisplay:seqNum Application:treeSeparator
    global Debugger:localinfo Debugger:f2c

    set hlist [$tree subwidget hlist]
    set context [set Debugger:f2c($debugfrm)]

    # determine the local context
    set level [set Debugger:stacklevel($debugfrm)]
    set xcontext [set Debugger:xcontext($debugfrm)]
    set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
    # build the display list and pass the local information to GDB.
    set localinfo [set Debugger:localinfo($xcontext,$level)]
    set displayList [TkRequest $context BuildLocalInfo $localinfo]

    # fetch currently hidden expressions; because this list may not exist for
    # the current level, catch substitution error silently.
    set hiddenList {}
    catch {
	set hiddenList \
	    [set DataDisplay:hiddenExprList($debugfrm,Locals,$xcontext,$depth)]
    }

    # automatically promote currently defined user expressions
    # to the next auto-display list.
    set userList {}
    catch {
	set userList \
	    [set DataDisplay:userExprList($debugfrm,Locals,$xcontext,$depth)]
    }

    if {$userList != {}} {
	set displayList [concat $userList $displayList]
    }

    # destroy previous tree
    $hlist delete offsprings Locals
    set pollList {}
    set DataDisplay:localNatives($debugfrm,$xcontext,$depth) {}

    foreach expr $displayList {
	if {[lsearch $hiddenList $expr] != -1} {
	    # expr was explicitly undisplayed -- ignore it
	    continue
	}

	foreach {ntype ident scope gdbvar} $expr {
	    if {$ntype == "user"} {
		set entry Locals${Application:treeSeparator}@[incr DataDisplay:seqNum]
		lappend pollList $entry
	    } {
		set entry Locals${Application:treeSeparator}$ident

		if {$ntype == "native"} {
		    lappend DataDisplay:localNatives($debugfrm,$xcontext,$depth) $gdbvar
		}
	    }

	    catch {
		$hlist add $entry \
		    -itemtype text \
		    -style leafTextStyle \
		    -data [list $ntype $ident $scope $gdbvar {}] \
		    -text $ident
	    }

	    $tree setmode $entry open
	}
    }

    # filter the obsolete variables out of the poll list (i.e.
    # those variables which used to be displayed but are
    # no more defined in the current lexical scope). Remember
    # that user-defined expressions have new names which may
    # never conflict with variable names.

    set oldList {}

    catch {
	set oldList \
	    [set DataDisplay:tracedEntryList($debugfrm,Locals,$xcontext,$depth)]
    }

    foreach entry $oldList {
	if {[$hlist info exists $entry] == 1} {
	    lappend pollList $entry
	}
    }

    if {$pollList != {}} {
	if {$autofocus == "true"} {
	    set focuscmd [Debugger:buildFocusCmd $debugfrm]
	    # direct stack context to the current focus -- unlike
	    # Debugger:resume{} entry context, we already control
	    # the debuggee. So there is no need for a HoldSimulation
	    # request to be issued.
	    set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
	    gdb:switchin $context $focuscmd $fnum
	}
	foreach entry $pollList {
	    DataDisplay:displayDataNode $debugfrm $tree $entry
	}
	if {$autofocus == "true"} {
	    gdb:switchout $context
	}
    }

    # reset the poll list to what is really viewable at
    # this point of execution from this context.
    set DataDisplay:tracedEntryList($debugfrm,Locals,$xcontext,$depth) $pollList
}

proc DataDisplay:openDataNode {debugfrm tree entry} {

    global Debugger:f2c DataDisplay:tracedEntryList
    global DataDisplay:hiddenExprList
    global Debugger:stackinfo Debugger:stacklevel
    global Debugger:stacklength Debugger:xcontext

    set hlist [$tree subwidget hlist]
    set top [$hlist info children]
    set context [set Debugger:f2c($debugfrm)]
    set ndata [$hlist info data $entry]
    set scope [lindex $ndata 2]

    if {$scope == "local"} {
	set focuscmd [Debugger:buildFocusCmd $debugfrm]
	set level [set Debugger:stacklevel($debugfrm)]
	set fnum [lindex [lindex [set Debugger:stackinfo($debugfrm)] $level] 0]
    } {
	set focuscmd {}
	set fnum 0
    }

    if {$top == "Locals"} {
	set level [set Debugger:stacklevel($debugfrm)]
	set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
	set xcontext [set Debugger:xcontext($debugfrm)]
    } {
	set depth 0
	set xcontext system
    }

    set pollList {}
    catch { set pollList [set DataDisplay:tracedEntryList($debugfrm,$top,$xcontext,$depth)] }
    if {[lsearch -exact $pollList $entry] != -1} {
	# this can occur as we reenter the Tk notifier
	# when regaining control over the debugger...
	return
    }
    if {[Debugger:resume $context $focuscmd $fnum] == "false"} {
	return
    }

    DataDisplay:displayDataNode $debugfrm $tree $entry

    set ntype [lindex $ndata 0]
    if {$ntype == "native" || $ntype == "user"} {
	# only register root nodes for polling
	lappend DataDisplay:tracedEntryList($debugfrm,$top,$xcontext,$depth) $entry
    }
    Debugger:suspend $context $focuscmd
}

proc DataDisplay:closeDataNode {debugfrm tree entry} {

    global DataDisplay:tracedEntryList Debugger:stacklength

    if {[$tree getmode $entry] == "open"} {
	# already closed -- ignore silently
	return
    }

    set hlist [$tree subwidget hlist]
    set top [$hlist info children]
    set ndata [$hlist info data $entry]
    set ntype [lindex $ndata 0]
    set ident [lindex $ndata 1]
    set scope [lindex $ndata 2]
    set gdbvar [lindex $ndata 3]

    if {$top == "Locals"} {
	global Debugger:stacklevel Debugger:xcontext
	global Debugger:stackinfo

	set level [set Debugger:stacklevel($debugfrm)]
	set depth [expr [set Debugger:stacklength($debugfrm)] - $level]
	set xcontext [set Debugger:xcontext($debugfrm)]
    } {
	set depth 0
	set xcontext system
    }

    set n [lsearch -exact \
	       [set DataDisplay:tracedEntryList($debugfrm,$top,$xcontext,$depth)] $entry]
    set DataDisplay:tracedEntryList($debugfrm,$top,$xcontext,$depth) \
	[lreplace [set DataDisplay:tracedEntryList($debugfrm,$top,$xcontext,$depth)] $n $n]

    if {[$hlist info children $entry] != {}} {
	# entry has children, we have to destroy its offsprings
	$hlist delete offsprings $entry
    }

    # just in case the value is listed beside the identifier, reset the
    # entry label to the expression name, except if this is not a
    # toplevel node (i.e. not a "user" or "native" entry).

    if {$ntype != "leaf" && $ntype != "node"} {
	$hlist entryconfig $entry -text [lindex $ndata 1] \
	    -style leafTextStyle
    }
}

proc DataDisplay:clearDataNode {debugfrm tree entry} {

    DataDisplay:closeDataNode $debugfrm $tree $entry

    set hlist [$tree subwidget hlist]
    set ndata [$hlist info data $entry]
    set ntype [lindex $ndata 0]

    if {$ntype != "node" && $ntype != "leaf"} {
	# closing a root -- discard all reference pathes
	$hlist entryconfig $entry -data [lrange $ndata 0 4]
	return
    }

    # remove intermediate entry from reference path list,
    # and all its offsprings.

    set root {}
    set parent [$hlist info parent $entry]
    set refpath [DataDisplay:buildRefPath $hlist $parent root]
    set rdata [$hlist info data $root]
    set pathlist [lindex $rdata 5]

    if {$refpath == {}} {
	# empty path found? we are closing a member which is
	# directly hooked below the root entry.
	if {[lindex $pathlist 0] == -1} {
	    # this one is an absolute kludge:: i wonder if i just remember
	    # how it works! Anyway, this is relevant with the special value
	    # of -1 which can be set by followDataNode to force the root
	    # entry to be dereferenced (pretending it's a pointer). The
	    # resulting expr (of the dereference) which is fold has rank
	    # number 0 in the root child list, but we need to match -1
	    # to have it removed from this list. So help ourselves, and
	    # hack a bit to force the reference path value to -1, if the
	    # first dereferenced member of the root entry was itself...
	    set refpath -1
	} {
	    set refpath [lsearch [$hlist info children $root] $entry]
	}
    }

    # closing a sub-node or leaf -- try removing its path from the list
    set rmid [lsearch -exact $pathlist $refpath]
    set l [expr [llength $refpath] - 1]

    if {$rmid != -1} {
	set newlist {}
	foreach path $pathlist {
	    if {[lrange $path 0 $l] != $refpath} {
		lappend newlist $path
	    }
	}
	$hlist entryconfig $root -data [concat [lrange $rdata 0 4] [list $newlist]]
    }

    # Now, update the entry indicator according to its new state --
    # it should be noted that all actions on the entry are
    # postponed until the notifier is idle using an "after" clause.
    # This way, Tix can return from the running callback without
    # having to complain about inexistent indicator or entry it
    # tries to update, after we've just deleted it.

    set ident [lindex $ndata 1]

    if {[string index $ident 0] == "*"} {
	# folding a dereference node means deleting it
	after idle "catch { $hlist delete entry $entry }"
	set pdata [$hlist info data $parent]
	set ptype [lindex $pdata 0]
	if {$ptype == "leaf"} {
	    # if parent used to be a leaf entry, remove the indicator
	    after idle "catch { $tree setmode $parent none }"
	}
	$hlist entryconfig $parent -style leafTextStyle
    } {
	if {$ntype == "leaf"} {
	    # if this used to be a leaf entry, remove the indicator
	    after idle "catch { $tree setmode $entry none }"
	    $hlist entryconfig $entry -style leafTextStyle
	} {
	    # otherwise, finish updating the indicator to reflect
	    # the new state fold state.
	    after idle "catch { $tree setmode $entry open }"
	    $hlist entryconfig $entry -style leafTextStyle
	}
    }
}

proc DataDisplay:displayDataNode {debugfrm tree entry} {

    set hlist [$tree subwidget hlist]

    if {![$hlist info exists $entry]} {
	# This may happen when global data are tracked
	# in the local variable window...
	return
    }

    set ndata [$hlist info data $entry]
    set ntype [lindex $ndata 0]
    set scope [lindex $ndata 2]
    set gdbvar [lindex $ndata 3]
    set refpath [lindex $ndata 5]

    set vlist [gdb:getdata $gdbvar "no_format" true]
    DataDisplay:displayAggr $debugfrm $tree $entry $gdbvar $vlist

    if {$ntype == "leaf"} {
	$hlist entryconfig $entry -style leafTextStyle
	$tree setmode $entry none
    } {
	$hlist entryconfig $entry -style leafTextStyle
	$tree setmode $entry close
    }

    # now, automatically dereference followed pointers

    foreach path $refpath {
	set subentry $entry
	foreach pos $path {
	    if {$pos < 0} {
		DataDisplay:dereferenceData $debugfrm $tree $entry true
	    } {
		set children [$hlist info children $subentry]
		set subentry [lindex $children $pos]
		if {$subentry != {}} {
		    DataDisplay:dereferenceData $debugfrm $tree $subentry true
		}
	    } 
	}
    }
}

proc DataDisplay:displayAggr {debugfrm tree entry gdbvar vlist} {

    set hlist [$tree subwidget hlist]
    catch { $hlist delete offsprings $entry }

    if {[lindex $vlist 0] == "@node"} {
	foreach member [lindex $vlist 1] {
	    DataDisplay:displayMember $debugfrm $tree $entry $gdbvar $member
	}
    } {
	set ndata [$hlist info data $entry]
	set ident [lindex $ndata 1]
	append ident " = " $vlist
	$hlist entryconfig $entry -text $ident
    }
}

proc DataDisplay:displayMember {debugfrm tree entry gdbvar value} {

    global Application:treeSeparator DataDisplay:seqNum

    set hlist [$tree subwidget hlist]
    set ndata [$hlist info data $entry]
    set ident [lindex $ndata 1]
    set scope [lindex $ndata 2]
    set file [lindex $ndata 4]
    set name [lindex $value 0]
    set info [lindex $value 1]

    if {$name == "@node"} {
	# Partial struct requests do not print out their
	# head member -- thus trap the case when the
	# member name is in fact the @node keyword and
	# assume that we are processing a sub-aggregate
	# of a global struct.
	DataDisplay:displayAggr $debugfrm $tree $entry \
	    $gdbvar [list @node $info]
	return
    }

    append entry ${Application:treeSeparator}@[incr DataDisplay:seqNum]

    # FIXME: the following lines should be moved to the GDB helper
    # since they are language dependent.  However, '*' should be kept
    # as a generic "dereference" marker.

    set strictid [string trimleft $name *]

    if {$name != $strictid} {
	set gdbvar *($gdbvar)
    } {
	append gdbvar . $name
    }

    # ENDFIXME

    if {$info == "@node"} {
	set info [lindex $value 2]
	$hlist add $entry -itemtype text -text $name \
	    -style leafTextStyle \
	    -data [list node $name $scope $gdbvar $file]
	$tree setmode $entry close
	DataDisplay:displayAggr $debugfrm $tree $entry \
	    $gdbvar [lrange $value 1 end]
	return
    }

    if {$info == {}} {
	set label [format " = %s" $name]
	$hlist add $entry -itemtype text -text $label \
	    -style leafTextStyle
    } {
	set label [format "%s = %s" $name $info]
	$hlist add $entry -itemtype text -text $label \
	    -style leafTextStyle \
	    -data [list leaf $name $scope $gdbvar $file]
    }

    $tree setmode $entry none
}

proc DataDisplay:setTreeState {debugfrm state {tree {}}} {

    if {$tree == {}} {
	# no tree specified means "globals" tree
	set tree $debugfrm.gbldisp.f.tree
    }

    # kludge: there is no easy method to globally invalidate
    # the sensitivity of a tixTree widget, thus we just assign
    # a void -command callback at the HList level to disable the
    # whole tree.

    if {[winfo exists $tree]} {
	set hlist [$tree subwidget hlist]
	set top [$hlist info children]
	if {$state == "disabled"} {
	    set cmd [$hlist cget -command]
	    $hlist entryconfig $top -data $cmd
	    $hlist config -command {}
	} {
	    set cmd [$hlist info data $top]
	    if {$cmd != {}} {
		$hlist config -command $cmd
	    }
	}
    }
}

proc DataDisplay:saveGlobals {context} {

    set hlist [$context.gbldisp.f.tree subwidget hlist]
    set settings {}
    # Note: we save the contents of the global data tree
    # instead of using the tracedEntryList array variable
    # because we want every variable pinned on the watch
    # board being remembered, including those which are
    # currently collapsed.
    set tracelist [$hlist info children Globals]

    foreach entry $tracelist {
	set ndata [$hlist info data $entry]
	# don't save the reference path list
	lappend settings [lrange $ndata 0 4]
    }

    Project:setResource DebuggerGlobals $settings
}

proc DataDisplay:restoreGlobals {context} {

    global DataDisplay:hiddenExprList Application:treeSeparator
    global DataDisplay:userExprList

    set settings [Project:getResource DebuggerGlobals]
    set tree $context.gbldisp.f.tree

    foreach ndata $settings {
	set ntype [lindex $ndata 0]
	if {$ntype == "user"} {
	    lappend DataDisplay:userExprList($context,Globals,system,0) $ndata
	} {
	    set nth [lsearch -exact \
			 [set DataDisplay:hiddenExprList($context,Globals,system,0)] $ndata]
	    if {$nth != -1} {
		set DataDisplay:hiddenExprList($context,Globals,system,0) \
		    [lreplace [set DataDisplay:hiddenExprList($context,Globals,system,0)] $nth $nth]
	    } {
		# variable is no more defined -- forget it.
		continue
	    }
	}
	set ident [lindex $ndata 1]
	set gdbvar [lindex $ndata 3]
	set top [$tree subwidget hlist info children]
	set entry $top${Application:treeSeparator}$ident

	$tree subwidget hlist add $entry \
	    -itemtype text \
	    -style leafTextStyle \
	    -data $ndata \
	    -text $ident
	
	$tree setmode $entry open
    }
}
