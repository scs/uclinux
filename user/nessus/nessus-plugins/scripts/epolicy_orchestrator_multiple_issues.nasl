# 
# (C) Tenable Network Security
#


if(description)
{
 script_id(11812);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CAN-2003-0148", "CAN-2003-0149", "CAN-2003-0616");
 

 name["english"] = "ePolicy orchestrator multiple issues";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running ePolicy orchestrator. Multiple
flaws have been found in this system, which may allow an attacker
to gain information on the MSDE installation of this host, or even
to execute arbitrary code.

*** Nessus did not check for the presence of these vulnerabilities,
*** so this might be a false positive. Make sure you are running
*** the latest version of ePolicy Orchestrator

Solution : http://www.nai.com/us/promos/mcafee/epo_vulnerabilities.asp
Risk Factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "ePolicy Orchestrator vulnerable to several issues";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 8081);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function check(port)
{
   	req = http_get(item:"/SERVER.INI", port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if( res != NULL )
	{
	if(("DataSource" >< res && "AgentHttpPort" >< res && "MaxHttpConnection" >< res) ||
	  ("Server: Spipe/1.0" >< res && "MIME-version: 1.0" >< res))
		{
		 security_hole(port);
		}
	return(0);
	}
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8081);
foreach port (ports)
{
 check(port:port);
}
