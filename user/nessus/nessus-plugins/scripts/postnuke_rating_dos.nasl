#
# (C) Tenable Network Security
#
# Note: Based on the proof of concept example,  NOT fully tested
#
# Reference: http://www.example.com/modules.php?op=modload&name=Downloads&file=index&req=addrating&ratinglid=[DOWNLOAD ID]&ratinguser=[REMOTE USER]&ratinghost_name=[REMOTE HOST ;-)]&rating=[YOUR RANDOM CONTENT] 
#
if (description)
{
 script_id(11676);
 script_bugtraq_id(7702);
 script_name(english:"Post-Nuke Rating System Denial Of Service");
 desc["english"] = "
The remote host is running post-nuke. PostNuke Phoenix 0.721,
0.722 and 0.723 allows a remote attacker causes a denial of service 
to legitmate users, by submitting a string to its rating system.
Solution : Add vendor supplied patch.
Risk factor : High";
 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to the postnuke rating dos vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}
include("http_func.inc");
include("http_keepalive.inc");
port = get_kb_item("Services/www");
if(!port)port = 80;
if(!get_port_state(port))exit(0);

foreach dir (make_list("", "/post-nuke", "/pn", cgi_dirs()))
{
 req = http_get(item:string(dir, "/index.php"), port:port);
 #display(req);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL ) exit(0);
 if('Post-Nuke' >< res)
 {
  vers = egrep(pattern:".*GENERATOR.*Post-Nuke", string:res);
  if(ereg(pattern:".*Post-Nuke 0\.([0-6]\.|7\.([0-1]\.|2\.[0-3]))", string:vers)) { security_warning(port); exit(0); }
 }
 exit(0);
}
