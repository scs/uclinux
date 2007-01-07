#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if(description)
{
 script_id(11815);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "IMP_MIME_Viewer_html class XSS vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running IMP version 3.0, 3.1, 3.2, or 3.2.1.  These
versions are vulnerable to several cross-scripting attacks whereby an
attacker can cause a victim to unknowingly run arbitrary Javascript code
simply by reading an HTML message from the attacker.

Announcements of the vulnerabilities can be found at:

   - http://marc.theaimsgroup.com/?l=imp&m=105940167329471&w=2
   - http://marc.theaimsgroup.com/?l=imp&m=105981180431599&w=2
   - http://marc.theaimsgroup.com/?l=imp&m=105990362513789&w=2

Note: Nessus has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there.  If the
installation has already been patched, consider this a false positive. 

Solution: Apply patches found in the announcements to
imp/lib/MIME/Viewer/html.php. 

Risk factor : Serious";
 script_description(english:desc["english"]);
 
 summary["english"] = "IMP_MIME_Viewer_html class is vulnerable to XSS attacks";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 George A. Theall");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "webmirror.nasl", "no404.nasl", "cross_site_scripting.nasl");

 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_kb_item("Services/www");
if (!port) port = 80;
if (!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# Search for page in a couple of different locations in addition to cgi_dirs().
# nb: "webmail" is not a standard but is commonly used.
dirs = make_list("", "/imp", "/horde/imp", "/webmail", cgi_dirs());
foreach d (dirs) {
    if (debug) display("debug: testing ", string(d, "/test.php...\n"));
    req = http_get(item:string(d, "/test.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);    # no web server.
    if (debug) display("debug: res =>>", res, "<<\n");

    # nb: version number is preceded by "<li>IMP: ".
    start = strstr(res, "<li>IMP: ");
    if (start != NULL) {
        # nb: ignore "<li>IMP: " to get to start of version number.
        start = substr(start, 9);
        end = strstr(res, "</li>");
        vers = start - end;
        if (debug) display("debug: vers =>>", vers, "<<\n");
        if (ereg(pattern:"^3\.(0|1|2|2\.1)$", string:vers)) {
            security_hole(port);
            # nb: no sense testing any further.
            exit(0);
        }
    }
}
