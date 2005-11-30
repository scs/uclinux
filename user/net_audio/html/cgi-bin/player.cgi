#!/bin/msh
echo Content-type: text/html
echo
echo "<html> <title>NetAudio   </title><LINK href=/mpd.css rel=stylesheet>"
echo

echo "<body >"

echo "<TABLE  width=100% align=center border=0 cellspacing=1 cellpadding=0> <TR><td align=left>"
echo "<h1 class=h1 ><b>NetAudio</b></h1></td><td align=center>"
# control panel
echo "<TABLE class=forumline align=center border=0 cellspacing=1 cellpadding=0> <TR>"
echo "<TD class=cpanel><ACRONYM TITLE=Controls><iframe height=20 width=150 frameborder=0 border=0 marginwidth=0 marginheight=0 scrolling=no src=/cgi-bin/cp.cgi?welcome+hi&></iframe></ACRONYM></TD>"

echo "<TD class=cpanel><ACRONYM TITLE=Volume><iframe height=15 width=100 frameborder=0 border=0 marginwidth=0 marginheight=0 scrolling=no src=/cgi-bin/volume.cgi></iframe></ACRONYM></TD>"
echo "</TR></TABLE> </td><td align=right>"

echo "<TABLE class=forumline align=center border=0 cellspacing=0 cellpadding=0> <TR>"
echo "<TD class=cpanel><center><iframe name=\"fstatus\" id=\"fstatus\" height=20 width=300 frameborder=0 border=0 marginwidth=0 marginheight=0 scrolling=no src=/cgi-bin/status.cgi?welcome+hi&></iframe></center>" 
echo "</td></TR></TABLE> </td></TR></TABLE> "


echo "<script>function rez() { if (document.all) {var iframe = document.all.s; "
echo "iframe.height=document.frames('s').document.body.scrollHeight;  } else if(document.getElementById) {"
echo "document.getElementById('s').height=document.getElementById('s').contentDocument.height+20; } }</script>"

#echo "<TABLE  width=100% height=*% align=center border=0 cellspacing=1 cellpadding=0> <TR><td class=cpanel align=left>"
echo "<iframe id=s  width=100% frameborder=0 border=0 marginwidth=0 marginheight=0 onload=rez(); src=/cgi-bin/ps.cgi?welcome+hi&></iframe>"

#echo "</td></TR></TABLE> "

echo "<br><br><br></body></html>"


