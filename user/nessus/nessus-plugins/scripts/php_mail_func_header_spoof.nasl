# tony@libpcap.net
# http://libpcap.net
#
# See the Nessus Scripts License for details

if(description)
{
  script_id(11444);
  script_version ("$Revision: 1.3 $");
  script_cve_id("CAN-2002-0985");
  script_bugtraq_id(5562);

  name["english"] = "PHP Mail Function Header Spoofing Vulnerability";
  script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of PHP earlier than 4.2.2.

The mail() function does not properly sanitize user input.
This allows users to forge email to make it look like it is
coming from a different source other than the server.

Users can exploit this even if SAFE_MODE is enabled.

Solution : Contact your vendor for the latest PHP release.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for version of PHP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_copyright(english:"(C) tony@libpcap.net");
  script_dependencie("find_service.nes", "no404.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;

if(get_port_state(port)) {
  banner = get_http_banner(port:port);
  if(!banner)exit(0);

  if(egrep(pattern:".*PHP/([0-3]\..*|4\.[0-1]\..*|4\.2\.[0-2][^0-9])", string:banner)) {
    security_warning(port);
  }
}
 
