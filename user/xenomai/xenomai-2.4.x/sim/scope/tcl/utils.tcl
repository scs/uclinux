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

package require Tkimg

set Workspace:ImageCache(0) {}

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

proc reverseList {l} {

    set rl {}

    foreach e $l {
	set rl [linsert $rl 0 $e]
    }

    return $rl
}

proc cascadeWindow {w {src {}}} {

    set toplevel [winfo toplevel $w]
    if {$src == {}} {
	set src [winfo toplevel [winfo parent $w]]
    }
    set geometry [winfo geometry $src]
    set l [split $geometry +]
    set x [lindex $l 1]
    set y [lindex $l 2]
    incr x 40
    incr y 20
    wm geometry $toplevel +$x+$y
}

proc _backmenupost {name x y} {

    global $name:postcmd

    if {[info exists $name:postcmd]} {
	set status [eval [set $name:postcmd] $x $y]
    } {
	set status true
    }

    if {$status == "true"} {
	tk_popup $name $x $y
    }
}

proc _backmenu {name args} {

    set cmd [lindex $args 0]
    switch $cmd {
	bind {
	    bind [lindex $args 1] <3> "_backmenupost $name %X %Y"
	}
	unbind {
	    bind [lindex $args 1] <3> ""
	}
	subwidget {
	    if {[lindex $args 1] == "menu"} {
		return $name
	    }
	}
	validate {
	    global $name:postcmd
	    set $name:postcmd [lindex $args 1]
	}
	default {
	    eval $name:genuine $args
	}
    }
}

proc backmenu {name args} {
    global $name:postcmd
    catch { unset $name:postcmd }
    eval menu $name [lrange $args 0 end]
    rename $name $name:genuine
    set body [list "eval _backmenu $name \$args"]
    eval proc $name {args} $body
}

proc getAbsolutePath {filename} {

    if {$filename == {}} {
	# keep empty name --- empty!
	return {}
    }

    if {[catch {set nativename [file nativename $filename]}] == 1} {
	# may be an invalid ~user syntax
	return $filename
    }

    set cwd [pwd]
    
    if {[catch { cd [file dirname $filename]; set dir [pwd] }] == 1} {
	# cannot determine absolute path
	return $nativename
    }

    cd $cwd

    return $dir/[file tail $filename]
}

proc getHListEntries {hlist root} {

    set children [$hlist info children $root]
    foreach child $children {
	set _children [getHListEntries $hlist $child]
	if {$_children != {}} {
	    eval lappend children $_children
	}
    }
    return $children
}

proc FIFOput {fifoName val args} {
    upvar 1 $fifoName fifo
    lappend fifo $val 
    if {[llength $args] > 0} {
	set fifo [concat $fifo $args]  
    }
}

proc FIFOget {fifoName} {
    upvar 1 $fifoName fifo
    
    if {! [FIFOisEmpty fifo]} {
	set val [lindex $fifo 0] 
	set fifo [lreplace $fifo 0 0] 
	return $val
    } else {
	return ""
    }
}

proc FIFOisEmpty {fifoName} {
    upvar 1 $fifoName fifo
    if {[llength $fifo] >  0} {
	return 0
    } else {
	return 1
    }
}

proc FIFOerase {fifoName} {
    upvar 1 $fifoName fifo
    set fifo ""
}

proc LISTget {listName index} {
    upvar 1 $listName list
  
    if {! [FIFOisEmpty list]} {
	set val [lindex $list $index] 
	set list [lreplace $list $index $index] 
    return $val
    } else {
	return ""
    }
}

proc stringMap {map string} {

    global tcl_version

    if {$tcl_version >= 8.2} {
	return [string map $map $string]
    }

    # Do it the old and very long way...

    foreach {old new} $map {
	while {[set i [string first $old $string]] != -1} {
	    set string [string range $string 0 [expr $i - 1]]$new[string range $string [expr $i + 1] end]
	}
    }

    return $string
}

proc makeCompoundImage {text img} {

    return [image create compoundimg -contents \
		[list [list text -text "$text " ] [list image -image $img]]]
}

proc fetchImage {name} {

    global tkbridge_prefixdir Workspace:imageCache

    if {[info exists Workspace:imageCache($name)]} {
	return [set Workspace:imageCache($name)]
    }
    foreach subdir {icons images} {
	set path $tkbridge_prefixdir/share/xenosim/$subdir/$name.png
	if {[file exists $path]} {
	    set img [image create photo -file $path]
	    set Workspace:imageCache($name) $img
	    return $img
	}
    }

    error "Image $name does not exist"
    return {}
}

proc globDir {dir} {

    global tcl_version

    if {$tcl_version >= 8.2} {
	return [glob -nocomplain -types d -directory $dir *]
    }

    set dirlist {}

    foreach file [glob -nocomplain $dir/*] {
	if {[file isdirectory $file] == 1} {
	    lappend dirlist $file
	}
    }

    return $dirlist
}