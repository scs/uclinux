if(description)
{
 script_id(10878);
 script_version("$Revision: 1.7 $");
 name["english"] = "Sun Cobalt Adaptive Firewall Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
Sun Cobalt machines contain a firewall mechanism, this mechanism can be
configured remotely by accessing Cobalt's built-in HTTP server. Upon access to
the HTTP server, a java based administration program would start, where a user
is required to enter a pass phrase in order to authenticate himself. Since no
username is required, just a passphrase bruteforcing of this interface is
easier.

Solution : 
Access to this port (by default set to port 8181) should not be permitted from
the outside. Further access to the firewall interface itself should not be
allowed (by default set to port 2005).

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sun Cobalt Adaptive Firewall Detection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SecurITeam");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 8181);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# Check starts here

function check(port, req)
{
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  
  if (("Sun Cobalt Adaptive Firewall" >< buf) && ("One moment please" >< buf))
  {
   	security_warning(port:port);
	exit(0);
  }
 return(0);
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8181);

foreach port (ports)
{
 check(port:port, req:"/");
 foreach dir (cgi_dirs())
 {
 check(port:port, req:string(dir, "/"));
 }
}
