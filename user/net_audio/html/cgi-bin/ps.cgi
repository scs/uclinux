#!/bin/msh
echo Content-type: text/html
echo
echo "<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>"
echo

echo "<script>function hello(){document.getElementById('scrap').style.display = 'none';}</script><body onLoad=hello();>"

echo "<div id=scrap style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>"
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
echo "<br>"

case $CMD in
mpcupd)         mpc update;;
mpcpl)          mpc playlist;;
mpcclear)       mpc clear ;;
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
mpcdelm)     	mpc del $PARADIR;;
welcome)        echo "<b>Control Panel</b>";;
*)              echo "invalid command : " $QUERY_STRING;;
esac
#echo $DIRLST
#mpc ls
SSS=\"
#IFS='\s'
echo "</div>"
echo "<script>"
echo "var currentd = '$DIRLST'; "
echo "var df=$SSS`mpc ls $DIRLST`$SSS;" 
#echo "var df=\"(Arthika)Kaadhal_Yaanai.mp3@|TamilBeat.Com@#Kaadhal Yaanai#|Anniyan||(Radha)Stranger_in_Black.mp3@|TamilBeat.Com@#Stranger in Black#|Anniyan||ILAMAYANUM.mp3@|70'S TO 80'S@#ILAMAYANUM#|PAGALIL ORU IRAVU||\";" 
echo "var lpls=$SSS  `mpc lsplaylists ` $SSS;" 
echo "var pls=$SSS  `mpc playlist` $SSS;" 
#echo "var pls=\" #1) TamilBeat.Com - Kaadhal Yaanai|\";" 
echo "</script><script language=\"javascript\" src=\"/player.js\"></script><script>writepage();</script></body></html>"

