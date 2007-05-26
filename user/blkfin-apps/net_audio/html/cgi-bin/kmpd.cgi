#!/bin/msh
echo Content-type: text/html
echo
echo "<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>"

echo "<script>function hello(){document.getElementById('scrap').style.display = 'none';}</script><body onLoad=hello();>"
echo "<div id=scrap style='position:absolute; z-index:-1000;top:1px; left:1px; width:0px; height:0px;visibility=hidden;'>"

echo "`mpc stop `"
echo "`mpc kill `"

echo "</div><center><br>NetAudio : Stopped.<br>Go for Samba UnMount</center></body></html>"

