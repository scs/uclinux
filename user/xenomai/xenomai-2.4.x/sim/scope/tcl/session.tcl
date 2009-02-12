#  This file is part of the XENOMAI project.
#
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

set Workspace:optNames {ktrace itrace utrace brkwarn popwarn linenums \
			evbubbles autoraise brkalert threadqual \
			glyphcursor forcefocus vtime}

set Workspace:opt2var(ktrace)      Project:settings(Options,traceKernel)
set Workspace:opt2var(itrace)      Project:settings(Options,traceIface)
set Workspace:opt2var(utrace)      Project:settings(Options,traceApp)
set Workspace:opt2var(brkwarn)     Project:settings(Options,breakOnWarnings)
set Workspace:opt2var(popwarn)     Project:settings(Options,popupOnWarnings)
set Workspace:opt2var(linenums)    Project:settings(Options,lineNumbering)
set Workspace:opt2var(evbubbles)   Project:settings(Options,evalBubbles)
set Workspace:opt2var(autoraise)   Project:settings(Options,autoRaise)
set Workspace:opt2var(brkalert)    Project:settings(Options,breakOnAlerts)
set Workspace:opt2var(threadqual)  Project:settings(Options,threadQualify)
set Workspace:opt2var(glyphcursor) Project:settings(Options,useGlyphCursor)
set Workspace:opt2var(forcefocus)  Project:settings(Options,forceFocusOnBreak)
set Workspace:opt2var(vtime)       Project:settings(Options,virtualTime)

# An associative array storing the session settings.
set Workspace:session(CurrentProject) {}
set Workspace:session(RecentProjects) {}
set Workspace:session(DefaultProjectDir) {}
set Workspace:session(DefaultExecdir) {}
set Workspace:session(DesktopGeometry) 800x600+150+80

proc Project:resetSettings {} {

    global Project:settings

    # Project:settings is an associative array storing the
    # miscellaneous simulation and system settings for the current
    # project.

    set Project:settings(SimulationTime) {0 usc}
    set Project:settings(WarmupTime) {0 usc}
    set Project:settings(SampleCount) 1 
    set Project:settings(DisplayTick) {0 usc}
    set Project:settings(TimeUnit) usc
    set Project:settings(WarpFactor) 3.0
    set Project:settings(ServerPort) 6545
    set Project:settings(Watchdog) 30
    set Project:settings(WorkingDir) {}
    set Project:settings(SourceDirs) {}
    set Project:settings(PrintCmd) "lpr -c %f"
    set Project:settings(Options,traceKernel)        0
    set Project:settings(Options,traceIface)         0
    set Project:settings(Options,traceApp)           1
    set Project:settings(Options,breakOnWarnings)    1
    set Project:settings(Options,popupOnWarnings)    1
    set Project:settings(Options,lineNumbering)      0
    set Project:settings(Options,evalBubbles)        1
    set Project:settings(Options,autoRaise)          0
    set Project:settings(Options,breakOnAlerts)      1
    set Project:settings(Options,threadQualify)      1
    set Project:settings(Options,useGlyphCursor)     0
    set Project:settings(Options,forceFocusOnBreak)  0
    set Project:settings(Options,virtualTime)        0
    set Project:settings(LocalArgs) {}
    set Project:settings(GdbPath) gdb
    set Project:settings(TraceLogSize) 200
    set Project:settings(Preferences,displaywp) 1
    set Project:settings(Preferences,wallpaper) bgndDefault
    set Project:settings(Executable) {}
}

proc Session:save {context {updateGeometry true}} {

    global Workspace:session

    if {$updateGeometry == "true"} {
	# Save desktop geometry
	set Workspace:session(DesktopGeometry) [wm geometry $context]
    }

    set rcfile [glob ~]/.mvmrc

    if {[catch {open $rcfile w} fh]} {
	# File can't be written.
	return
    }

    foreach name [array names Workspace:session *] {
	puts $fh "$name [list [set Workspace:session($name)]]"
    }

    close $fh
}

proc Session:restore {context {projfile {}}} {

    global Workspace:session

    set rcfile [glob ~]/.mvmrc

    if {$projfile == {}} {
	if {[catch {open $rcfile r} fh]} {
	    # File can't be read.
	    return {}
	}
	while {[gets $fh s] >= 0} {
	    if {$s != {}} {
		set name [lindex $s 0]
		set value [lindex $s 1]
		set Workspace:session($name) $value
	    }
	}
	close $fh
    }

    if {[set Workspace:session(DesktopGeometry)] != {}} {
	wm geometry $context [set Workspace:session(DesktopGeometry)]
    }

    if {$projfile == {}} {
	set projfile [set Workspace:session(CurrentProject)]
    } {
	set projfile [getAbsolutePath $projfile]
    }

    Workspace:updateRecentProjects $context

    if {$projfile != {}} {
	Workspace:openProject $context $projfile
    }
}

proc Workspace:saveProject {context {projfile {}} {execfile {}}} {

    global Workspace:session Project:settings

    if {$projfile == {}} {
	set projfile [set Workspace:session(CurrentProject)]
    } {
	set projfile [getAbsolutePath $projfile]
	set Workspace:session(CurrentProject) $projfile
    }

    if {$execfile != {}} {
	set Project:settings(Executable) [getAbsolutePath $execfile]
    }

    if {$projfile == {}} {
	return true
    }

    if {[catch {open $projfile w} fh]} {
	return false
    }

    foreach name [array names Project:settings *] {
	puts $fh "$name [list [set Project:settings($name)]]"
    }

    close $fh

    return true
}

proc Workspace:restoreProject {context projfile} {

    global Workspace:session Project:settings

    if {[catch {open $projfile r} fh]} {
	return false
    }

    while {[gets $fh s] >= 0} {
	if {$s != {}} {
	    set name [lindex $s 0]
	    set value [lindex $s 1]
	    set Project:settings($name) $value
	}
    }

    close $fh

    set Workspace:session(CurrentProject) $projfile

    return true
}

proc Project:setResource {name value} {

    global Project:settings
    set name [stringMap {" " _} $name]
    set Project:settings(Resources,$name) $value
}

proc Project:getResource {name} {

    global Project:settings
    set name [stringMap {" " _} $name]
    if {![info exists Project:settings(Resources,$name)]} {
	return {}
    }
    return [set Project:settings(Resources,$name)]
}
