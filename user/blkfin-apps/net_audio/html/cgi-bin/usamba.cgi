#!/bin/msh
echo Content-type: text/html
echo
echo "<html><title>NetAudio</title><LINK href=/mpd.css rel=stylesheet><body>"

echo "`mpc stop `"
echo "`mpc kill `"
echo "`smbumount /mnt `"

echo "<br><center><a class=lnk href='/cgi-bin/csamba.cgi'>Check Samba Status</a>"
echo "<br>Samba UnMount : Done.<br></center></body></html>"

