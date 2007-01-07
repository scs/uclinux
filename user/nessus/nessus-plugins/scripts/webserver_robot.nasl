#
# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
 head = "
Some Web Servers use a file called /robot(s).txt to make search engines and
any other indexing tools visit their WebPages more frequently and
more efficiently.

By connecting to the server and requesting the /robot(s).txt file, an
attacker may gain additional information about the system they are
attacking.

Such information as, restricted directories, hidden directories, cgi script
directories and etc. Take special care not to tell the robots not to index
sensitive directories, since this tells attackers exactly which of your
directories are sensitive.

";


tail = "

Risk factor : Medium";

if(description)
{
 script_id(10302);
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "robot(s).txt exists on the Web Server";
 script_name(english:name["english"]);
 
 desc["english"] = head + tail;

 script_description(english:desc["english"]);
 
 summary["english"] = "robot(s).txt exists on the Web Server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = is_cgi_installed("/robot.txt");
if(port)
{
 sockwww = http_open_socket(port);
 if (sockwww)
 {
  sendata = http_get(item:"/robot.txt", port:port);
  send(socket:sockwww, data:sendata);
  headers = http_recv_headers(sockwww);
  body = http_recv_body(socket:sockwww, headers:headers, length:0);
  if("llow" >< body || "agent:" >< body)
   {
   if (body)
    {
    body = string("The file 'robot.txt' contains the following:\n", body);
    security_warning(port:port, data:head + body + tail);
    }
   http_close_socket(sockwww);
  }
 }
 else exit(0);
}
else
{
 port = is_cgi_installed("/robots.txt");
 if(port)
 {
  sockwww = http_open_socket(port);
  if (sockwww)
  {
   sendata = http_get(item:"/robots.txt", port:port);
   send(socket:sockwww, data:sendata);
   headers = http_recv_headers(sockwww);
   body = http_recv_body(socket:sockwww, headers:headers, length:0);
  if("llow" >!< body && "agent:" >!< body)exit(0);
   
   if (body)
   {
    body = string("The file 'robots.txt' contains the following:\n", body);
    security_warning(port:port, data:head + body + tail);
   }
   http_close_socket(sockwww);
  }
 }
}
