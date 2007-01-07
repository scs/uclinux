#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#      Could also cover BugtraqID:734, CVE:CVE-1999-0931
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10748);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0776");
 script_bugtraq_id(1568);

 name["english"] = "Mediahouse Statistics Web Server Detect";
 script_name(english:name["english"]);

 desc["english"] = "We detected the remote web server as a 
Mediahouse Statistics web server. This web server suffers from a security 
vulnerability that enables attackers to gain sensitive information on the 
current logged events on the public web server (the server being monitored 
by MediaHouse).
This information includes: who is on (currently surfing users), the user's 
actions, customer's IP addresses, referrer URLs, hidden directories, web 
server usernames and passwords, and more.

Some versions of the product also suffer from a flaw that allows attackers 
to overflow an internal buffer causing it to execute arbitrary code.

Solution: Block the web server's port number on your Firewall, and 
upgrade to the latest version if necessary.

Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Mediahouse Statistics Web Server Detection";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/statistics-server");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_kb_item("Services/www");
if (!port) port = 80;

if(!get_port_state(port))exit(0);

buf  = get_http_banner(port:port);

if (egrep(pattern:"^Server: Statistics Server", string:buf))
{
 buf = strstr(buf, "Location: ");
 buf = buf - "Location: ";
 subbuf = strstr(buf, string("\n"));
 buf = buf - subbuf;
 buf = buf - raw_string(0x0D);
 soc = http_open_socket(port);
 if (soc)
 {
  req = http_get(item:buf, port:port);
  send(socket:soc, data:req);
  buf = http_recv(socket:soc);
  http_close_socket(soc);

  if ("Statistics Server " >< buf)
  {
   buf = strstr(buf, "<TITLE>Statistics Server ");
   buf = buf - "<TITLE>Statistics Server ";
   subbuf = strstr(buf, "</TITLE>");
   buf = buf - subbuf;
   buf = buf - "</TITLE>";
   version = buf;

   buf = "Remote host is running Statistics Server version: ";
   buf = buf + version;
   if(ereg(pattern:"(([0-4]\.[0-9].*)|5\.0[0-2])", string:version))
   {
    # should be a separate plugin ?
    report = string("According to its version number, the remote MediaHouse\n",
        	      "Statistics Server is vulnerable to a buffer overflow that\n",
		      "allows anyone to execute arbitrary code as root.\n\n",
		      "Solution: Upgrade to version 5.03 or newer\n",
		      "Risk factor : High");
   security_hole(data:report, port:port);
   }
   else
   {
    security_warning(port);
   }
  }
 }
}


