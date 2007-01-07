#
# This NASL script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence
#
# Research on web server fingerprinting was done by Jeremiah Grossman from
# Whitehat Security
# For more information, read 
# http://www.blackhat.com/presentations/bh-asia-02/bh-asia-02-grossman.pdf
#

if (description)
{
  script_version("$Revision: 1.10 $");
  script_id(11525);
  name["english"] = "WWW fingerprinting";
  script_name(english:name["english"]);

  desc["english"] = "
This script tries to identify the HTTP Server type and version by
sending an OPTION request.

An attacker may use this to identify the kind of the remote web server
and gain further knowledge about this host.


See also : http://www.blackhat.com/presentations/bh-asia-02/bh-asia-02-grossman.pdf
Risk factor : Low";

  script_description(english:desc["english"]);
 
  summary["english"] = "Identifies the web server with OPTION";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "General";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "http_login.nasl", "httpver.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  exit(0);

}

exit(0); # Currently broken

#

function extract(headers, method)
{
  local_var	RE, line, v, m;

  RE = string("^", method, ":");
  line = egrep(pattern: RE, string: headers, icase: TRUE);
  if (! line) return;
  line = ereg_replace(string: line, pattern: RE, icase: TRUE, replace: "");
  # Remove blanks
  line = ereg_replace(string: line, pattern: '[ \r\n]', replace: '');
  while (line)
  {
    m = ereg_replace(pattern: ",.*", replace: "", string: line);
    v[m] = TRUE;
    line = ereg_replace(pattern: "^[^,]+,?", string: line, replace: "");
  } 
  return v;
}

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

req = http_get(port: port, item: "*");
req = ereg_replace(string: req, pattern:"^GET", replace: "OPTIONS");

send(socket: soc, data: req);
buf = http_recv_headers(soc);
http_close_socket(soc);

if (buf =~ "^HTTP/1\.[01] +404 ")
{
  soc = http_open_socket(port);
  if (! soc) exit(0);
  req = http_get(port: port, item: "/");
  req = ereg_replace(string: req, pattern:"^GET", replace: "OPTIONS");

  send(socket: soc, data: req);
  buf = http_recv_headers(soc);
  http_close_socket(soc);
}


if (! buf) exit(0);
all = extract(headers: buf, method: "Allow");
pub = extract(headers: buf, method: "Public");

srv = NULL;
if (isnull(all) && isnull(srv)) exit(0);

sigall = ""; sigpub = "";
if (!isnull(all))
  foreach v (sort(keys(all))) sigall = strcat(sigall, v, " ");
if (!isnull(pub))
  foreach v (sort(keys(pub))) sigpub = strcat(sigpub, v, " ");

if (     sigall == "GET HEAD OPTIONS TRACE ")
  srv = "Apache/1.2.x, Apache/1.3.x, Oracle 9iAS, FirstClass/x.x, WebLogic/7.x or Zope/2.6.1";
else if (sigall == "GET HEAD OPTIONS POST TRACE ")
  srv = "Apache/2.0.x, Domino/6.0.x, IIS-5.0 w/ DisableWebDAV";
else if (sigall == "GET HEAD OPTIONS POST ")
  srv = "WebLogic/x.x";
else if (sigall == "GET HEAD OPTIONS POST PUT ")
  srv = "Yaws/x.x";
else if (sigpub == "DELETE GET HEAD OPTIONS POST PUT TRACE ")
  srv = "IIS-4.0";
else if (sigpub == "COPY DELETE GET HEAD LOCK MOVE OPTIONS POST PROPFIND PROPPATCH PUT SEARCH TRACE UNLOCK ")
  srv = "IIS-5.0";
else if (sigpub == "GET HEAD POST PUT ")
  srv = "Netscape-Enterprise/3.6";
else if (sigall == "GET HEAD POST PUT ")
  srv = "Netscape-Enterprise/4.0";
else if (sigall == "DELETE GET HEAD INDEX MKDIR MOVE OPTIONS POST PUT RMDIR TRACE ")
  srv = "Netscape-Enterprise/4.1 or 6.0";
else if (sigall == "COPY DELETE GET HEAD MKCOL MOVE OPTIONS POST PROPFIND PROPPATCH ")
  srv = "SAMBAR/x.x";
else if (sigall == "DELETE GET HEAD MKCOL OPTIONS POST PROPFIND PROPPATCH PUT ")  srv = "4D_WebSTAR_S/5.2.x";
else if( sigpub == sigall && sigall == "DELETE GET HEAD MOVE OPTIONS POST PUT ")
  srv = "CommuniGatePro/4.0.x";
else if( sigall == " LOCK MKCOL OPTIONS PUT ") 
  srv = "CommuniGatePro/4.1.x";
else if( sigpub == sigall && sigall == "COPY DELETE GET HEAD LOCK MKCOL MOVE OPTIONS POST PROPFIND PROPPATCH PUT SEARCH TRACE UNLOCK ")
  srv = "Cougar 4.1.0.x";
else if(sigall == "GET HEAD POST ")
  srv = "Lotus-Domino/5.0.x";
else if(sigall == "DELETE GET HEAD OPTIONS POST PUT TRACE ")
  srv = "Apache Tomcat/4.x";
else if(sigall == "COPY DELETE GET HEAD LOCK MKCOL MOVE OPTIONS POST PROPFIND PROPPATCH PUT TRACE UNLOCK ")
  srv = "Zope/2.4.x, Zope/2.5.x";
else if(sigall == "COPY DELETE GET HEAD MKCOL MOVE OPTIONS POST PROPFIND PROPPATCH PUT TRACE ")
  srv = "Zope/2.2.x, Zope/2.3.x";

if (isnull(srv))
{
  rep = "Nessus was unable to reliably fingerprint this server
If you know what it is, please send this signature to the Nessus team:";
  if (sigall) rep = string(rep, "\nAllow: ", sigall);
  if (sigpub) rep = string(rep, "\nPublic: ", sigpub);
  security_note(port: port, data: rep);
}
else
  security_note(port: port, 
                data: string("This web server was fingerprinted as ", srv));
