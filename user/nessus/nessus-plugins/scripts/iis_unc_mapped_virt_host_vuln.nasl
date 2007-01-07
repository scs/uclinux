# 
# tony@libpcap.net
# http://libpcap.net
#
# See the Nessus Scripts License for details

if(description) {
  script_id(11443);
  script_version("$Revision: 1.3 $");
  script_cve_id("CVE-2000-0246");
  script_bugtraq_id(1081);

  name["english"] = "Microsoft IIS UNC Mapped Virtual Host Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Your IIS webserver allows the retrieval of ASP/HTR source code.

An attacker can use this vulnerability to see how your
pages interact and find holes in them to exploit.

Risk factor : Serious";

  script_description(english:desc["english"]);

  summary["english"] = "Checks IIS for .ASP/.HTR backslash vulnerability.";
  script_summary(english:summary["english"]);
  script_copyright(english:"(C) tony@libpcap.net");
  script_category(ACT_GATHER_INFO);

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port) port = 80;

if(get_port_state(port)) {
  # common ASP files
  f[0] = "/index.asp%5C";
  f[1] = "/default.asp%5C";
  f[2] = "/login.asp%5C";
  
  files = get_kb_list(string("www/", port, "/content/extensions/asp"));
  if(!isnull(files)){
  	files = make_list(files);
	f[3] = files[0] + "%5C";
	}

  for(i = 0; f[i]; i = i + 1) {
    req = http_get(item:f[i], port:port);
    h = http_keepalive_send_recv(port:port, data:req);
    if( h == NULL ) exit(0);
    
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:h) &&
       "Content-Type: application/octet-stream" >< r) {
      security_hole(port);
      exit(0);
    }
  }
}
