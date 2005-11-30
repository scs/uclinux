// supporting functions for creating the dynamic webpage by sivaraman

var pl=pls.split("|");
var dfs=df.split('##');var ls=dfs[dfs.length-1];var ml4=ls.split("||");

function save(){
var filename= prompt('Enter the filename : ','');
if ((filename==null)||(filename==''))
	{alert('Save playlist : No filename (or) Cancelled');} 
else
	{location.href='ps.cgi?mpcsave+'+filename+'&'+currentd;}
}

function rmply(filen){
if (confirm ('Are you sure you want to delete the file?'))
	{location.href='ps.cgi?mpcrm+'+filen+'&'+currentd;}
}

function plays(song){parent.frames['fstatus'].location.href='/cgi-bin/status.cgi?mpcplay+'+song+'&';}

function delf(v){
var cnt=0;var files='';
	for(i=0; i<v; i++){
		var enc=eval('document.cpform.rm'+i+'.checked');
		if(enc){cnt++;files = files+(i+1)+'i'; }
	}
if (cnt){location.href='ps.cgi?mpcdelm+'+files+'&'+currentd; }
}

function addf(v){
var cnt=0;var filesa='';var tp; var tmp='';
	for(i=0; i<v; i++){
		var enc=eval('document.mlform.lc'+i+'.checked');
		if(enc){
			 cnt++;
			 tmp ='@'+eval('document.mlform.lc'+i+'.value')+']'+'@';
			filesa=filesa+tmp;
				}
	    }
	
	
if (cnt){location.href='ps.cgi?mpcaddm+'+filesa+'&'+currentd; }
}

function dothis(v)
{
	var urlstream=v;
	
	location.href='ps.cgi?mpcadd+'+urlstream+']&';
}

function writepage(){

document.write("<TABLE width=100% align=center border=0 cellspacing=1 cellpadding=0> <TR><td valign=top align=left>");
document.write("<TABLE align=center width=100% border=0 cellspacing=0 cellpadding=0 class=forumwhite> <TR>");

document.write("<TD valign=top><TABLE align=left width=600 border=0 cellspacing=1 cellpadding=0 class=forumline> ");

document.write("<tr><TD class=thead align=left>Streaming Server URL:<input type=\"TEXT\" id=\"url\" name=\"url\"  value=\"\" SIZE=\"50\" MAXLENGTH=\"70\"><input type=\"submit\" id=\"button\" name=\"button\" value=\"ADD\"onclick=\"dothis(url.value)\"></TD></TR><tr><TD valign=top>");

document.write("<tr><TD class=thead align=center>Media Library <ACRONYM TITLE='Add Selected to Playlist'>&nbsp[<a href=javascript:addf(ml4.length-1)>ADD</a>]&nbsp</ACRONYM><ACRONYM TITLE='Update Library'>&nbsp[<a  href=ps.cgi?mpcupd+cmd&"+currentd+">UPDATE</a>]</ACRONYM></TD></TR><tr><TD valign=top>");

document.write("<TABLE align=left width=600 border=0 cellspacing=1 cellpadding=4 > ");
document.write("<tr><TD class=thead align=center>Artist</TD><TD class=thead align=left>Title</TD><TD class=thead align=center>Album</TD></TR>");
document.write("<form name=mlform>");
//var dfs=df.split('##');var ls=dfs[dfs.length-1];var ml4=ls.split("||");
for (var i=0; i < ml4.length-1; i++) {
	var tottxt=ml4[i];
	var tmp4=tottxt.split('#|');var album=tmp4[1];var tmp3=tmp4[0].split('@#');var title=tmp3[1];
	var tmp2=tmp3[0].split('@|');var filename=tmp2[0];var artist=tmp2[1];
	if (artist=='(null)'){artist=filename;}
	document.write("<tr><TD class=row2 valign=top>");
	document.write("<input class=checkbox type=checkbox  value="+filename.replace(/\ /g,'%')+" name=lc"+i+"><a class=row href=ps.cgi?mpcadd+"+filename.replace(/\ /g,'%')+"]&"+currentd+"> "+artist+"</a>");

	document.write("</td><td  class=row3 valign=top >"+title+"</td><td  class=row2 valign=top >"+album);
	document.write("</td></tr>");
}

document.write("</form></TABLE></td></tr><tr><td class=thead align=left valign=center>");
document.write(" &nbsp<a class=dirlink href=ps.cgi?welcome+dir&>MediaPath</a>&nbsp/&nbsp ");

var dlink=currentd;dlink.replace(/\ /g,'');
if (dlink!=''){
links=dlink.split('/');
for(var i=0;i<links.length;i++)
{ var mlink='';
for(var j=0;j<=i;j++){
mlink=mlink+links[j]+'/';
}
if(links[i]!=''){document.write('<a class=dirlink href=ps.cgi?welcome+dir&'+mlink+'>'+links[i]+'</a> / ');} 
}}

document.write("</td></TR></TABLE></TD></TR><tr><TD valign=top><br>");
document.write("<TABLE align=left width=300 border=0 cellspacing=1 cellpadding=4 class=forumline> ");
document.write("<tr><TD class=thead align=center>Directory list</TD></TR>");
for (var i=0; i < dfs.length-1; i++) {
	document.write("<tr><TD class=row2 valign=top>");
	document.write("<a class=row href=ps.cgi?welcome+dir&"+ dfs[i].replace(/\ /g,'')+"> "+dfs[i]+"</a>");
	document.write("</td></tr>");
}
if (dfs.length ==1){document.write("<tr><TD class=row2 valign=top>(empty)</td></tr>");} 

document.write("</table><TABLE align=left width=300 border=0 cellspacing=1 cellpadding=4 class=forumline> ");
document.write("<tr><TD class=thead align=center>Playlist</TD></TR>");

var lpl=lpls.split("|");
for (var i=0; i < lpl.length-1; i++) {
	document.write("<tr><TD class=row2 valign=top>");
	document.write("<ACRONYM TITLE='Delete Playlist' ><a class=row href=javascript:rmply('"+lpl[i].replace(/\ /g,'')+"')><img src=/img/delete.gif align=absMiddle border=0></a></ACRONYM><a class=row href=ps.cgi?mpcload+"+ lpl[i].replace(/\ /g,'')+"&"+currentd+"> "+lpl[i]+"</a>");
	document.write("</td></tr>");
}
if (lpl.length ==1){document.write("<tr><TD class=row2 valign=top>(empty)</td></tr>");}

document.write("</TABLE> </td></tr></TABLE> </TD><TD valign=top>");

document.write("<TABLE  width=350 border=0 cellspacing=1 cellpadding=1 class=forumline> ");
document.write("<tr><TD class=thead align=center>Current Playlist &nbsp <ACRONYM TITLE='Remove Selected from Current Playlist'>&nbsp[<a  href=javascript:delf(pl.length-1)>REMOVE</a>]&nbsp</ACRONYM>&nbsp<ACRONYM TITLE='Save Current Playlist'>&nbsp[<a  href='javascript:save()'>SAVE</a>]&nbsp</ACRONYM>&nbsp<ACRONYM TITLE='Clear Current Playlist'>[<a  href='ps.cgi?mpcclear+cmd&"+currentd+"'>CLEAR</a>]</ACRONYM></TD></TR>");
document.write("<tr><td><TABLE  width=350 border=0 cellspacing=1 cellpadding=2 class=forumwhite> ");
document.write("<form name=cpform>");
//var pl=pls.split("|");
for (var i=0; i < pl.length-1; i++) {
	document.write('<tr><TD class=row2 width=10 valign=top><input class=checkbox type=checkbox name=rm'+i+'></td>');
	document.write("<td class=cprow onmouseover=this.style.backgroundColor='#D1D7DC' onmouseout=this.style.backgroundColor='#DEE3E7' onclick=plays("+(i+1)+"); valign=top>"+pl[i]+"</td></tr>");
}
if (pl.length ==1){document.write("<tr><TD class=row2 valign=top>(empty)</td></tr>");}

document.write("</form></TABLE> </td></TR> ");
document.write("</TABLE> </td></TR></TABLE> ");


}// end of writepage
