#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# changes by rd :
#
#	- script id
#	
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10385);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CAN-2000-1191");
 name["english"] = "ht://Dig's htsearch reveals web server path";
 script_name(english:name["english"]);
 
 desc["english"] = "ht://Dig's htsearch CGI can be 
used to reveal the path location of the its configuration files.
This allows attacker to gather sensitive information about the remote host.
For more information see:
http://www.securiteam.com/exploits/htDig_reveals_web_server_configuration_paths.html

 Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Retrieve the real path using htsearch";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");
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
if(!port)port = 80;
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  req = string(dir, "/htsearch?config=foofighter&restrict=&exclude=&method=and&format=builtin-long&sort=score&words=");
  req = http_get(item:req, port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if( result == NULL ) exit(0);
  
  if("ht://Dig error" >< result)
  {
   resultrecv = strstr(result, "Unable to read configuration file '");
   resultsub = strstr(resultrecv, string("foofighter.conf'\n"));
   resultrecv = resultrecv - resultsub;
   resultrecv = resultrecv - "Unable to read configuration file '";
   resultrecv = resultrecv - "foofighter.conf'\n";

   banner = "ht://Dig's configuration file is located at: ";
   banner = banner + resultrecv;
   banner = banner + string("\n");

   security_warning(port:port, data:banner);
   exit(0);
  }
}

