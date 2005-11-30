#!/bin/msh
echo Content-type: text/html
echo
echo "<html><head></head><LINK href=/mpd.css rel=stylesheet>"
echo "<script>function hello(){document.getElementById('scrapst').style.display = 'none';}</script><body onLoad=hello(); leftmargin=0 topmargin=0>"

echo "<div id=scrapst style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>"
QS=$QUERY_STRING
IFS='+'
set $QS
CMD=$1
DIRLST=" "
QS=$2
IFS='&'
set $QS
PARADIR=$1
DIRLST=$2

IFS='|'
#IFS='\s'
set `echo $PARADIR`
PARA=$1

case $CMD in
mpcupd)         mpc update;;
mpcpl)          mpc playlist;;
mpcprev)        mpc prev ;;
mpcplayf)       mpc play ;;
mpcplay)        mpc play $PARA;;
mpcnext)        mpc next ;;
mpcpause)       mpc pause ;;
mpcstop)        mpc stop ;;
mpcclear)       mpc clear ;;
mpcrepeat)      mpc repeat ;;
mpcrandom)      mpc random ;;
mpcadd)         mpc add $PARA;;
mpcdel)         mpc del $PARA;;
mpcload)        mpc load $PARA;;
mpcsave)        mpc save $PARA;;
mpcrm)          mpc rm $PARA;;
mpcaddm)        mpc add $PARADIR ;;
mpcdirlist)     QS=$QUERY_STRING
                IFS='+'
                set $QS
                DIRLST=$2;;
                #DIRLST="${QUERY_STRING##*+}";;
mpcdelm)        mpc del $PARADIR;;
welcome)        echo "CP";;
*)              echo "ic: " $QUERY_STRING;;
esac

#IFS='\s'
echo "</div>"

echo "<TABLE align=center border=""0"" cellspacing=""0"" cellpadding=""0""><TR>"
echo "<TD class=status align=center>&nbsp<b><a class=row href=/cgi-bin/status.cgi?welcome+hi&>STATUS</a></b>&nbsp</TD> <TD class=iframe  align=center width=300><MARQUEE SCROLLDELAY=200>`mpc status` </MARQUEE></TD><TR></TABLE></body></html>"
#mpc status
#echo "</MARQUEE> </TD> <TR></TABLE> "
#echo "</body></html>"

