#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd : 
#  - script_id
#  - family (in french)
#
#
if(description)
{
 script_id(10403);
 script_version ("$Revision: 1.9 $"); 
 script_bugtraq_id(1178);
 script_cve_id("CVE-2000-0381");
 name["english"] = "DBMan CGI server information leakage";
 script_name(english:name["english"]);
 
 desc["english"] = "It is possible to cause the DBMan 
CGI to reveal sensitive information, by requesting a URL such as:

GET /scripts/dbman/db.cgi?db=no-db

Risk factor : Medium
Solution : Upgrade to the latest version";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if webplus reads local files";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 SecuriTeam");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(get_port_state(port))
{
  req = http_get(item:"/scripts/dbman/db.cgi?db=no-db",
  		port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = http_recv(socket:soc);
   http_close_socket(soc);
   backup = result;
   report = string("\nIt is possible to cause the DBMan\n", 
"CGI to reveal sensitive information, by requesting a URL such as:\n\n",
"GET /scripts/dbman/db.cgi?db=no-db\n\n",
"We could obtain the following : \n\n");
   if("CGI ERROR" >< result)
   {
    result = strstr(backup, string("name: no-db at "));
    result = result - strstr(result, string(" line "));
    result = result - "name: no-db at ";
    report = "CGI full path is at: " + result + string("\n");

    result = strstr(backup, string("Perl Version        : "));
    result = result - strstr(result, string("\n"));
    result = result - string("Perl Version        : ");
    report = report + "Perl version: " + result + string("\n");

    result = strstr(backup, string("PATH                : "));
    result = result - strstr(result, string("\n"));
    result = result - string("PATH                : ");
    report = report + "Server path: " + result + string("\n");

    result = strstr(backup, string("SERVER_ADDR         : "));
    result = result - strstr(result, string("\n"));
    result = result - string("SERVER_ADDR         : ");
    report = report + "Server real IP: " + result + string("\n");

    result = strstr(backup, string("SERVER_SOFTWARE     : "));
    result = result - strstr(result, string("\n"));
    result = result - string("SERVER_SOFTWARE     : ");
    report = report + "Server software: " + result + string("\n");
    report = report + string("\nRisk factor : Medium\n",
    			    "Solution : Upgrade to the latest version\n");
    security_warning(port, data: report);
   } 
  }
}

