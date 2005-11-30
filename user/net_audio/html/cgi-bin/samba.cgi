#!/bin/msh
echo Content-type: text/html
echo
echo "<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>"

echo "<script>function hello(){document.getElementById('scrap').style.display = 'none';}</script><body onLoad=hello();>"
echo "<br><center><a class=lnk href='/cgi-bin/csamba.cgi'>Check Samba Status</a></center>"
echo "<div id=scrap style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>"
#echo "</div>"
		echo "</div>"
pwdgrab us
echo "shiva:printing us"
echo $us
QS=$us
IFS='&'
set $QS
FULLUSR=$1
FULLPWD=$2
echo $QUERY_STRING
echo "shiva:printing user"
echo $FULLUSR
echo $FULLPWD
echo "shiva:printing user"
#IFS='\s'
if [ "$QUERY_STRING" -eq 0 ]
then
        echo "QUERY_STRING : Failed, Reload the Image"
else
        smbmount $QUERY_STRING /mnt -o $FULLUSR,$FULLPWD
	echo "<center><br>Samba Mount : Done.<br></center>"
fi

echo "<br></center></body></html>"

