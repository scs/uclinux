#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11653);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(5563, 5565, 5509, 5504, 5510, 5514, 5515);
 script_cve_id("CAN-2002-1110", "CAN-2002-1111", "CAN-2002-1112", "CAN-2002-1113", "CAN-2002-1114");

 name["english"] = "Mantis Multiple Flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Mantis bug tracker.

The version of Mantis which is being used contains various
flaws which may allow an atacker to view bugs it should not
see, get a list of projects that should be hidden, and
inject SQL commands.

Solution : Upgrade to Mantis 0.17.5 or newer
Risk Factor : High"; 




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "mantis_detect.nasl");
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
vers = get_kb_item(string("www/", port, "/mantis/version"));
if(!vers)exit(0);
if(ereg(pattern:"0\.([0-9]\.|1[0-6]\.|17\.[0-4][^0-9])", string:vers))
	security_hole(port);
	
