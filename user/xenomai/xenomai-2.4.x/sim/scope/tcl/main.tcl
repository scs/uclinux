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
#  Revamped for XENOMAI by Philippe Gerum.

set Application:eventQueues(0) {}
set Application:inSignal false
set Application:treeSeparator "`"
set Application:visualType {}

proc send {} {
    # inhibit send command
}

proc setScheme-Color:Scope {} {


    global tixOption

    set tixOption(bg)           \#a4aa94
    set tixOption(fg)           black

    set tixOption(dark1_bg)     \#acb69c
    set tixOption(dark1_fg)     black
    set tixOption(dark2_bg)     \#acb69c
    set tixOption(dark2_fg)     black
    set tixOption(inactive_bg)  \#acb69c
    set tixOption(inactive_fg)  black

    set tixOption(light1_bg)    white
    set tixOption(light1_fg)    white
    set tixOption(light2_bg)    white
    set tixOption(light2_fg)    white

    set tixOption(active_bg)    $tixOption(dark1_bg)
    set tixOption(active_fg)    $tixOption(fg)
    set tixOption(disabled_fg)  \#626162

    set tixOption(input1_bg)    white
    set tixOption(input2_bg)    white
    set tixOption(output1_bg)   $tixOption(dark1_bg)
    set tixOption(output2_bg)   $tixOption(bg)

    set tixOption(select_fg)    white
    set tixOption(select_bg)    \#6a7962

    set tixOption(selector)	yellow

    option add *background 		$tixOption(bg) 10
    option add *Background		$tixOption(bg) $tixOption(prioLevel)
    option add *background		$tixOption(bg) $tixOption(prioLevel)
    option add *Foreground		$tixOption(fg) $tixOption(prioLevel)
    option add *foreground		$tixOption(fg) $tixOption(prioLevel)
    option add *activeBackground	$tixOption(active_bg) $tixOption(prioLevel)
    option add *activeForeground	$tixOption(active_fg) $tixOption(prioLevel)
    option add *HighlightBackground	$tixOption(bg) $tixOption(prioLevel)
    option add *selectBackground	$tixOption(select_bg) $tixOption(prioLevel)
    option add *selectForeground	$tixOption(select_fg) $tixOption(prioLevel)
    option add *selectBorderWidth	0 $tixOption(prioLevel)
    option add *disabledForeground 	$tixOption(disabled_fg) $tixOption(prioLevel)
    option add *Menu.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *TixMenu.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *Menubutton.padY			5 $tixOption(prioLevel)
    option add *Button.borderWidth		2 $tixOption(prioLevel)
    option add *Button.anchor		c $tixOption(prioLevel)
    option add *Checkbutton.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *Radiobutton.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *Entry.relief		sunken $tixOption(prioLevel)
    option add *Entry.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *Entry.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *Entry.foreground		black $tixOption(prioLevel)
    option add *Entry.insertBackground	black $tixOption(prioLevel)
    option add *Label.anchor		w $tixOption(prioLevel)
    option add *Label.borderWidth		0 $tixOption(prioLevel)
    option add *Listbox.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *Listbox.relief		sunken $tixOption(prioLevel)
    option add *Scale.foreground		$tixOption(fg) $tixOption(prioLevel)
    option add *Scale.activeForeground	$tixOption(bg) $tixOption(prioLevel)
    option add *Scale.background		$tixOption(bg) $tixOption(prioLevel)
    option add *Scale.sliderForeground	$tixOption(bg) $tixOption(prioLevel)
    option add *Scale.sliderBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *Scrollbar.relief		sunken $tixOption(prioLevel)
    option add *Scrollbar.borderWidth		1 $tixOption(prioLevel)
    option add *Scrollbar.width			11 $tixOption(prioLevel)
    option add *Text.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *Text.relief		sunken $tixOption(prioLevel)
    option add *TixBalloon*background 			#ffff60 $tixOption(prioLevel)
    option add *TixBalloon*foreground 			black $tixOption(prioLevel)
    option add *TixBalloon.background 			black $tixOption(prioLevel)
    option add *TixBalloon*Label.anchor 			w $tixOption(prioLevel)
    option add *TixControl*entry.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixControl*entry.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixControl*entry.foreground		black $tixOption(prioLevel)
    option add *TixControl*entry.insertBackground	black $tixOption(prioLevel)
    option add *TixDirTree*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirTree*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixDirTree*f1.relief			sunken $tixOption(prioLevel)
    option add *TixDirList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixDirList*f1.relief			sunken $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixScrolledHList*f1.relief			sunken $tixOption(prioLevel)
    option add *TixTree*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixTree*f1.relief			sunken $tixOption(prioLevel)
    option add *TixFileEntry*Entry.background 		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixHList.background			$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixHList.activeBackground		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixHList.disabledBackground		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixLabelEntry*entry.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixLabelEntry*entry.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixLabelEntry*entry.foreground		black $tixOption(prioLevel)
    option add *TixLabelEntry*entry.insertBackground	black $tixOption(prioLevel)
    option add *TixMultiList*Listbox.borderWidth		0 $tixOption(prioLevel)
    option add *TixMultiList*Listbox.highlightThickness	0 $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.relief		sunken $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.width		11 $tixOption(prioLevel)
    option add *TixMultiList*f1.borderWidth		2 $tixOption(prioLevel)
    option add *TixMultiList*f1.relief			sunken $tixOption(prioLevel)
    option add *TixMultiList*f1.highlightThickness		2 $tixOption(prioLevel)
    option add *TixMDIMenuBar*menubar.relief		raised $tixOption(prioLevel)
    option add *TixMDIMenuBar*menubar.borderWidth		2 $tixOption(prioLevel)
    option add *TixMDIMenuBar*Menubutton.padY 		2 $tixOption(prioLevel)
    option add *TixNoteBook.Background			$tixOption(bg) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.Background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.backPageColor		$tixOption(bg) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.inactiveBackground	$tixOption(inactive_bg) $tixOption(prioLevel)
    option add *TixPanedWindow.handleActiveBg 		$tixOption(active_bg) $tixOption(prioLevel)
    option add *TixPanedWindow.seperatorBg    		$tixOption(bg) $tixOption(prioLevel)
    option add *TixPanedWindow.handleBg       		$tixOption(dark1_bg) $tixOption(prioLevel)
    option add *TixPopupMenu*menubutton.background 	$tixOption(dark1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledTList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledTList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledTList*tlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledTList*tlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*listbox.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*listbox.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledText*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledText*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledWindow*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledWindow*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledWindow.frame.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.borderWidth		1 $tixOption(prioLevel)
    option add *TixComboBox*Entry.highlightBacground		$tixOption(bg) $tixOption(prioLevel)
    option add *TixComboBox*Entry.background			$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixComboBox*Entry.foreground			black $tixOption(prioLevel)
    option add *TixComboBox*Entry.insertBackground		black $tixOption(prioLevel)
}

proc setScheme-Mono:Scope {} {


    global tixOption

    set tixOption(bg)           lightgray
    set tixOption(fg)           black

    set tixOption(dark1_bg)     gray70
    set tixOption(dark1_fg)     black
    set tixOption(dark2_bg)     gray60
    set tixOption(dark2_fg)     white
    set tixOption(inactive_bg)  lightgray
    set tixOption(inactive_fg)  black

    set tixOption(light1_bg)    gray90
    set tixOption(light1_fg)    white
    set tixOption(light2_bg)    gray95
    set tixOption(light2_fg)    white

    set tixOption(active_bg)    gray90
    set tixOption(active_fg)    $tixOption(fg)
    set tixOption(disabled_fg)  gray55

    set tixOption(input1_bg)    $tixOption(light1_bg)
    set tixOption(input2_bg)    $tixOption(light1_bg)
    set tixOption(output1_bg)   $tixOption(light1_bg)
    set tixOption(output2_bg)   $tixOption(light1_bg)

    set tixOption(select_fg)    white
    set tixOption(select_bg)    black

    set tixOption(selector)	black

    option add *background 		$tixOption(bg) 10
    option add *Background		$tixOption(bg) $tixOption(prioLevel)
    option add *background		$tixOption(bg) $tixOption(prioLevel)
    option add *Foreground		$tixOption(fg) $tixOption(prioLevel)
    option add *foreground		$tixOption(fg) $tixOption(prioLevel)
    option add *activeBackground	$tixOption(active_bg) $tixOption(prioLevel)
    option add *activeForeground	$tixOption(active_fg) $tixOption(prioLevel)
    option add *HighlightBackground	$tixOption(bg) $tixOption(prioLevel)
    option add *selectBackground	$tixOption(select_bg) $tixOption(prioLevel)
    option add *selectForeground	$tixOption(select_fg) $tixOption(prioLevel)
    option add *selectBorderWidth	0 $tixOption(prioLevel)
    option add *Menu.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *TixMenu.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *Menubutton.padY			5 $tixOption(prioLevel)
    option add *Button.borderWidth		2 $tixOption(prioLevel)
    option add *Button.anchor		c $tixOption(prioLevel)
    option add *Checkbutton.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *Radiobutton.selectColor		$tixOption(selector) $tixOption(prioLevel)
    option add *Entry.relief		sunken $tixOption(prioLevel)
    option add *Entry.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *Entry.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *Entry.foreground		black $tixOption(prioLevel)
    option add *Entry.insertBackground	black $tixOption(prioLevel)
    option add *Label.anchor		w $tixOption(prioLevel)
    option add *Label.borderWidth		0 $tixOption(prioLevel)
    option add *Listbox.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *Listbox.relief		sunken $tixOption(prioLevel)
    option add *Scale.foreground		$tixOption(fg) $tixOption(prioLevel)
    option add *Scale.activeForeground	$tixOption(bg) $tixOption(prioLevel)
    option add *Scale.background		$tixOption(bg) $tixOption(prioLevel)
    option add *Scale.sliderForeground	$tixOption(bg) $tixOption(prioLevel)
    option add *Scale.sliderBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *Scrollbar.relief		sunken $tixOption(prioLevel)
    option add *Scrollbar.borderWidth		1 $tixOption(prioLevel)
    option add *Scrollbar.width			11 $tixOption(prioLevel)
    option add *Text.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *Text.relief		sunken $tixOption(prioLevel)
    option add *TixBalloon*background 			#ffff60 $tixOption(prioLevel)
    option add *TixBalloon*foreground 			black $tixOption(prioLevel)
    option add *TixBalloon.background 			black $tixOption(prioLevel)
    option add *TixBalloon*Label.anchor 			w $tixOption(prioLevel)
    option add *TixControl*entry.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixControl*entry.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixControl*entry.foreground		black $tixOption(prioLevel)
    option add *TixControl*entry.insertBackground	black $tixOption(prioLevel)
    option add *TixDirTree*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirTree*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirTree*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixDirTree*f1.relief			sunken $tixOption(prioLevel)
    option add *TixDirList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixDirList*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixDirList*f1.relief			sunken $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixScrolledHList*f1.relief			sunken $tixOption(prioLevel)
    option add *TixTree*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.activeBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.disabledBackground	$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*f1.borderWidth		1 $tixOption(prioLevel)
    option add *TixTree*f1.relief			sunken $tixOption(prioLevel)
    option add *TixFileEntry*Entry.background 		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixHList.background			$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixHList.activeBackground		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixHList.disabledBackground		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixLabelEntry*entry.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixLabelEntry*entry.background		$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixLabelEntry*entry.foreground		black $tixOption(prioLevel)
    option add *TixLabelEntry*entry.insertBackground	black $tixOption(prioLevel)
    option add *TixMultiList*Listbox.borderWidth		0 $tixOption(prioLevel)
    option add *TixMultiList*Listbox.highlightThickness	0 $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.relief		sunken $tixOption(prioLevel)
    option add *TixMultiList*Scrollbar.width		11 $tixOption(prioLevel)
    option add *TixMultiList*f1.borderWidth		2 $tixOption(prioLevel)
    option add *TixMultiList*f1.relief			sunken $tixOption(prioLevel)
    option add *TixMultiList*f1.highlightThickness		2 $tixOption(prioLevel)
    option add *TixMDIMenuBar*menubar.relief		raised $tixOption(prioLevel)
    option add *TixMDIMenuBar*menubar.borderWidth		2 $tixOption(prioLevel)
    option add *TixMDIMenuBar*Menubutton.padY 		2 $tixOption(prioLevel)
    option add *TixNoteBook.Background			$tixOption(bg) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.Background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.backPageColor		$tixOption(bg) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.inactiveBackground	$tixOption(inactive_bg) $tixOption(prioLevel)
    option add *TixPanedWindow.handleActiveBg 		$tixOption(active_bg) $tixOption(prioLevel)
    option add *TixPanedWindow.seperatorBg    		$tixOption(bg) $tixOption(prioLevel)
    option add *TixPanedWindow.handleBg       		$tixOption(dark1_bg) $tixOption(prioLevel)
    option add *TixPopupMenu*menubutton.background 	$tixOption(dark1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledHList*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledTList*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledTList*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledTList*tlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledTList*tlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*listbox.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledListBox*listbox.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledText*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledText*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledWindow*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixScrolledWindow*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixScrolledWindow.frame.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*Scrollbar.background		$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*Scrollbar.troughColor		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.highlightBacground	$tixOption(bg) $tixOption(prioLevel)
    option add *TixTree*hlist.background		$tixOption(light1_bg) $tixOption(prioLevel)
    option add *TixTree*hlist.borderWidth		1 $tixOption(prioLevel)
    option add *TixComboBox*Entry.highlightBacground		$tixOption(bg) $tixOption(prioLevel)
    option add *TixComboBox*Entry.background			$tixOption(input1_bg) $tixOption(prioLevel)
    option add *TixComboBox*Entry.foreground			black $tixOption(prioLevel)
    option add *TixComboBox*Entry.insertBackground		black $tixOption(prioLevel)
}

proc initFontSet:Scope {} {

    global tixOption

    set tixOption(font)         -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*
    set tixOption(bold_font)    -*-helvetica-bold-r-normal--12-*-*-*-*-*-*-*
    set tixOption(menu_font)    -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*
    set tixOption(italic_font)  -*-helvetica-medium-o-normal--12-*-*-*-*-*-*-*
    set tixOption(fixed_font)   -*-courier-medium-r-normal--12-*-*-*-*-*-*-*

    option add *Font				$tixOption(font) $tixOption(prioLevel)
    option add *font				$tixOption(font) $tixOption(prioLevel)
    option add *Menu.font			$tixOption(menu_font) $tixOption(prioLevel)
    option add *TixMenu.font			$tixOption(menu_font) $tixOption(prioLevel)
    option add *Menubutton.font			$tixOption(menu_font) $tixOption(prioLevel)
    option add *Label.font              	$tixOption(font) $tixOption(prioLevel)
    option add *Scale.font			$tixOption(font) $tixOption(prioLevel)
    option add *TixBalloon*Label.font 		$tixOption(font) $tixOption(prioLevel)
    option add *TixBitmapButton*label.font 	$tixOption(font) $tixOption(prioLevel)
    option add *TixControl*label.font           $tixOption(font) $tixOption(prioLevel)
    option add *TixLabelEntry*label.font        $tixOption(font) $tixOption(prioLevel)
    option add *TixLabelFrame*label.font 	$tixOption(font) $tixOption(prioLevel)
    option add *TixMwmClient*title.font		$tixOption(font) $tixOption(prioLevel)
    option add *TixNoteBook.nbframe.font	$tixOption(bold_font) $tixOption(prioLevel)
    option add *TixOptionMenu*menubutton.font	$tixOption(font) $tixOption(prioLevel)
    option add *TixComboBox*Entry.font		$tixOption(font) $tixOption(prioLevel)
    option add *TixFileSelectBox*Label.font     $tixOption(font) $tixOption(prioLevel)

    eval font create SourceFont [font actual -*-courier-medium-r-normal--12-*-*-*-*-*-*-*]
}

proc appInitProc {} {

    wm withdraw .
    tk appname xenoscope
 
    option clear

    global Application:visualType
    switch -- [winfo screenvisual .] {

	grayscale -
	staticgray {

	    set Application:visualType monochrome

	    setScheme-Mono:Scope
	    initFontSet:Scope

	    tixDisplayStyle text \
		-stylename rootTextStyle \
		-font -*-helvetica-bold-r-normal-12-*-*-*-*-*-*-*

	    tixDisplayStyle text \
		-stylename leafTextStyle \
		-font -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*

	    tixDisplayStyle text \
		-stylename highlightedLeafStyle \
		-padx 0 -pady 2 \
		-font -*-helvetica-medium-o-normal--12-*-*-*-*-*-*-*

	    tixDisplayStyle text \
		-stylename highlightedRootStyle \
		-padx 0 -pady 2 \
		-font -*-helvetica-bold-r-normal-12-*-*-*-*-*-*-*

	    tixDisplayStyle imagetext \
		-stylename rootImageStyle \
		-padx 0 -pady 2 \
		-font -*-helvetica-bold-r-normal-12-*-*-*-*-*-*-*

	    tixDisplayStyle imagetext \
		-stylename leafImageStyle \
		-padx 0 -pady 2 \
		-font -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*
	}

	default {

	    set Application:visualType color

	    setScheme-Color:Scope
	    initFontSet:Scope

	    tixDisplayStyle text \
		-background white \
		-activebackground white \
		-stylename rootTextStyle \
		-font -*-helvetica-bold-r-normal-12-*-*-*-*-*-*-*

	    tixDisplayStyle text \
		-background white \
		-activebackground white \
		-stylename leafTextStyle \
		-font -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*

	    tixDisplayStyle text \
		-background white \
		-activebackground white \
		-stylename highlightedLeafStyle \
		-foreground blue \
		-font -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*
		
	    tixDisplayStyle text \
		-background white \
		-activebackground white \
		-stylename highlightedRootStyle \
		-foreground blue \
		-font -*-helvetica-bold-r-normal-12-*-*-*-*-*-*-*
		
	    tixDisplayStyle imagetext \
		-background white \
		-activebackground white \
		-stylename rootImageStyle \
		-padx 0 -pady 2 \
		-font -*-helvetica-bold-r-normal-12-*-*-*-*-*-*-*

	    tixDisplayStyle imagetext \
		-background white \
		-activebackground white \
		-stylename leafImageStyle \
		-padx 0 -pady 2 \
		-font -*-helvetica-medium-r-normal--12-*-*-*-*-*-*-*
	}
    }

    # remove global binding on F10 (the debugger binds it)
    bind all <Key-F10> {}

    Project:resetSettings
}

proc traceEvent {var queue hdlr} {

    global Application:eventQueues
    global $var $queue

    lappend Application:eventQueues($var) $queue
    set $queue {}
    trace variable $var w $hdlr
}

proc forgetEvent {var queue hdlr} {

    global Application:eventQueues
    global $var $queue

    set qs [set Application:eventQueues($var)]
    set n [lsearch -exact $qs $queue]

    if {$n != -1} {
	set Application:eventQueues($var) [lreplace $qs $n $n]
	trace vdelete $var w $hdlr
	unset $queue
    }
}

proc pushEvent {var event} {

    global Application:eventQueues
    global Application:inSignal
    global $var

    set qs [set Application:eventQueues($var)]

    foreach queue $qs {
	global $queue
	lappend $queue $event
    }

    if {${Application:inSignal} == "false"} {
	# Ensure that all clients will get a trace event, even if
	# the event service routines throw additional events
	# as a part of their work. Because a vtrace only sends
	# one trigger on behalf of a trace event context, we must
	# plan for a flush callback to be called on idle time.
	# This routine will check for unprocessed events in
	# client queues, triggering another trace event if
	# needed, until all events are finally processed.
	set Application:inSignal true
	after idle "flushEvents $var"
    }

    set $var true
}

proc flushEvents {var} {

    global Application:inSignal $var
    global Application:eventQueues
    set Application:inSignal false

    set qs [set Application:eventQueues($var)]
    set ping 0

    foreach queue $qs {
	global $queue
	if {[llength $queue] > 0} {
	    incr ping
	}
    }

    if {$ping > 0} {
	set $var true
    }
}

proc popEvent {queue evar} {

    global $queue

    set v [set $queue]

    if {$v == {}} {
	return false
    }

    upvar $evar event
    set event [lindex $v 0]
    set $queue [lreplace $v 0 0]

    return true
}
