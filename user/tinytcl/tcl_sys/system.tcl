#
# system - system code
#
# $Id$
#

#
# beep -- beep the speaker
#
proc beep {} {
    sound 1000
    wait 300
    sound 0
}

#
# unload_procs pattern - unload all procs matching pattern
#
proc unload_procs {pattern} {
    foreach name [info procs $pattern] {
        rename $name ""
    }
}

proc snapshot {} {
    global procs globals

    foreach proc [info procs] {
        set procs($proc) ""
    }

    foreach global [info globals] {
        set globals($global) ""
    }
    set globals(globals) ""
}

proc revert_snapshot {} {
    global procs globals

    foreach proc [info procs] {
        if {![info exists procs($proc)]} {
            rename $proc ""
        }
    }

    foreach global [info globals] {
        if {![info exists globals($global)]} {
            global $global
            unset $global
        }
    }
}
