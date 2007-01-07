# This script was written by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10742); 
 script_version ("$Revision: 1.9 $");

 name["english"] = "Amanda Index Server version";
 script_name(english:name["english"]);

 desc["english"] = "This test detects the Amanda Index Server's 
version by connecting to the server and processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Version numbers should be omitted where possible.

Solution : Change the version number to something generic (like: 0.0.0.0)

Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Amanda Index Server version";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/amandaidx", 10082);
 script_dependencies("find_service.nes");
 exit(0);
}


#
# The script code starts here
#
include("misc_func.inc");
register = 0;

port = get_kb_item("Services/amandaidx");
if (!port) {
  	register = 1;
  	port = 10082;
	}

if(!get_port_state(port))exit(0);

soctcp10082 = open_sock_tcp(port);
if (soctcp10082)
{
 result = recv_line(socket:soctcp10082, length:1000);
 
 Amanda_version = "";

 if ("AMANDA index server" >< result)
 {
  if (ereg(pattern:"^220 .* AMANDA index server \(.*\).*", string:result)) {
   Amanda_version = ereg_replace(pattern:"^220 .* AMANDA index server \((.*)\).*", string:result, replace:"\1");
   report = string("The remote Amanda Server version is : ",
  		Amanda_version, 
		"\n");
   set_kb_item(name:"Amanda/version", value:Amanda_version);
   if(register)register_service(port:port, proto:"amandaidx");
  } else {
   report = string("Amanda Server is running with banner:\n",result);
  }
  security_note(port:port, data:report);
 }
 close(soctcp10082);
}
