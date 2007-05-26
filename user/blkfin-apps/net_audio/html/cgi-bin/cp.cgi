#!/bin/msh
echo Content-type: text/html
echo
echo "<html><head></head><LINK href=/mpd.css rel=stylesheet>"
#echo "<br><br>"
echo "<script>"
echo "function rStatus(){parent.frames['fstatus'].location.href='/cgi-bin/status.cgi';}"
echo "function cmdctl(cpcmd){parent.frames['fstatus'].location.href='/cgi-bin/status.cgi?'+cpcmd+'+cmd&';}"
echo "</script>"
echo "<body onLoad=rStatus(); leftmargin=0 topmargin=0>"

echo "<div id=scrap style='position:absolute; top:1px; left:1px; width:0px;height:0px;visibility=hidden;'>"

QS=$QUERY_STRING
IFS='+'
set $QS
CMD=$1


case $CMD in
mpcupd)         mpc update;;
mpcprev)        mpc prev ;;
mpcplay)        mpc play ;;
mpcnext)        mpc next ;;
mpcpause)       mpc pause ;;
mpcstop)        mpc stop ;;
mpcclear)       mpc clear ;;
mpcrepeat)      mpc repeat ;;
mpcrandom)      mpc random ;;
welcome)        echo "<b>Control Panel</b>";;
*)              echo "invalid command : " $QUERY_STRING;;
esac

IFS='\s'

echo "</div>"


echo "<div style=\"position:absolute;background-color: #EFEFEC; top:0px; left:0px; width:150px; height:15\">"
echo "<TABLE class=forumwhite align=center border=0 cellspacing=1 cellpadding=0> <TR>"
echo "<TD onclick=cmdctl('mpcprev'); class=cpanel><ACRONYM TITLE=\"Previous Song\"><img src=/img/first.gif align=absMiddle border=0></ACRONYM></TD>"
echo "<TD onclick=cmdctl('mpcplayf'); class=cpanel><ACRONYM TITLE=\"Play\"><img src=/img/next.gif align=absMiddle border=0></ACRONYM></TD>"
echo "<TD onclick=cmdctl('mpcnext'); class=cpanel><ACRONYM TITLE=\"Next Song\"><img src=/img/last.gif align=absMiddle border=0></ACRONYM></TD>"
echo "<TD onclick=cmdctl('mpcstop'); class=cpanel><ACRONYM TITLE=\"Stop\"><img src=/img/stop.gif align=absMiddle border=0></ACRONYM></TD>"
echo "<TD onclick=cmdctl('mpcpause'); class=cpanel><ACRONYM TITLE=\"Pause\"><img src=/img/pause.gif align=absMiddle border=0></ACRONYM></TD>"
echo "<TD onclick=cmdctl('mpcrepeat'); class=cpanel><ACRONYM TITLE=\"Repeat\"><img src=/img/ren.gif align=absMiddle border=0> </ACRONYM></TD>"
echo "<TD onclick=cmdctl('mpcrandom'); class=cpanel><ACRONYM TITLE=\"Random\"><img src=/img/copy.gif align=absMiddle border=0></ACRONYM></TD>"

echo "</TR></TABLE> </div></body></html>"

