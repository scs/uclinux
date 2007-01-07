#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10762);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "RTSP Server type and version";
 script_name(english:name["english"]);
 
 desc["english"] = "This detects the RTSP Server's type and version.

This information gives potential attackers additional information about the
system they are attacking. Server and Version should be omitted
where possible.

Solution: Change the server name

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "RTSP Server detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

#
# The script code starts here
#

 port = get_kb_item("Services/rtsp");
 if(!port)port = 554;
 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   data = string("OPTIONS * RTSP/1.0\r\n\r\n");
   send(socket:soc, data:data);
   header = recv(socket:soc, length:1024);
   if(("RTSP/1" >< header) && ("Server:" >< header)) {
     server = egrep(pattern:"Server:",string:header);
     if (server) {
      report = string("The remote RTSP server is :\n",server,"\nWe recommend that you configure your server to return\nbogus versions in order to not leak information\n");
      security_note(port:port, data:report);
     }
     security_note(port:port, data:string("All RTSP Header for 'OPTIONS *' method:\n",header));
   }
  }
  close(soc);
 }
