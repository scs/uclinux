#
# This script was written by Sverre H. Huseby <shh@thathost.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(11617);
  script_version ("$Revision: 1.2 $");

  name["english"] = "Horde and IMP test disclosure";
  script_name(english:name["english"]);

  desc["english"] = "
The remote server is running Horde and/or IMP with test scripts
available from the outside.  The scripts may leak server-side
information that is valuable to an attacker.

Solution: test.php and imp/test.php should be deleted,
or they should be made unreadable by the web server.
Risk factor : Medium";

  script_description(english:desc["english"]);

  summary["english"] = "Checks if test.php is available in Horde or IMP";

  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"Sverre H. Huseby");
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if (!port)port = 80;

if (!get_port_state(port))
  exit(0);

dirs = make_list(cgi_dirs(), "");
files = make_list("/test.php", "/test.php3");

foreach d (dirs) {
  foreach f (files) {
    req = http_get(item:string(d, f), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if (res == NULL)
      exit(0);

    if ('PHP Version' >< res
        && ('Horde Version' >< res || 'IMP Version' >< res)) {
      security_warning(port);
      exit(0);
    }
  }
}
