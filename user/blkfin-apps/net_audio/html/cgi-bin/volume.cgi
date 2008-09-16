#!/bin/msh
echo Content-type: text/html
echo
echo "<html><head></head><LINK href=/mpd.css rel=stylesheet>"
echo "<body leftmargin=0 topmargin=0>"
echo "<script language=\"javascript\" src=\"/volumebar.js\"></script>"
echo "<br><br>"
mpc volume $QUERY_STRING


echo "<script>"
echo "function iStatus(){"
#echo "parent.fstatus.location.href='/cgi-bin/status.cgi';"
echo "parent.frames['fstatus'].location.href='/cgi-bin/status.cgi';"
echo "}"
echo "function volume(){"
echo "var rl = location.href;"
echo "var URLparts = rl.split('?');"
#echo "var number = (URLparts[1]-0);"
echo " var vol1=\"  `mpc volume ` \";"
echo "var vol2=vol1.split(\":\");"
echo "var vol3=vol2[1].split(\"%\");"
echo "var number = (vol3[0]-0);"
echo "setCount(number);}"
echo "</script>" 


echo "</body></html>"

