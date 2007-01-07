#
#  (C) Tenable Network Security
#
#

if(description)
{
 script_id(11689);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Cisco IDS Device Manager Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "This host is running the Cisco IDS device manager.";

 script_description(english:desc["english"]);
 
 summary["english"] = "Cisco IDS Management Web Server Detect";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 family["english"] = "General";
 script_family(english:family["english"]);

 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_kb_item("Services/www");
 if (!port) port = 443;

 if (get_port_state(port))
 {
   res = http_keepalive_send_recv(data:http_get(item:"/", port:port), port:port);
   if( res == NULL ) exit(0);
   if("<title>Cisco Systems IDS Device Manager</title>" >< res)
   	security_note(port);
 }
