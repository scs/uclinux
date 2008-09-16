#!/bin/msh
echo Content-type: text/html
echo
echo "<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet>"
echo "<script>function hello(){document.getElementById('smb').style.display = 'none';}</script><body onLoad=hello();>"
echo "<div id=done><center>Samba Mount found.</center></div><div id=failed><center>Samba Mount not found.</center></div>"
echo "<form name=smb id=smb style='position:absolute;visibility=hidden;'><textarea name=ta rows=0 column=0>"
echo "`ps`"
echo "</textarea></form>"
echo "<script language=\"javascript\" src=\"/csmb.js\"></script><center><br>Samba Status</center><br></body></html>"

