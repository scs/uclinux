if(description)
{
 script_id(11385);
 script_version ("$Revision: 1.3 $");
 
 script_cve_id("CAN-2003-0015");
 script_bugtraq_id(6650);
 
 name["english"] = "CVS pserver double free() bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote CVS server, according to its version number,
is vulnerable to a double free() bug which may allow an
attacker to gain a shell on this host.

Solution : Upgrade to CVS 1.11.5
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", port);
 script_dependencies("find_service.nes", "cvs_public_pserver.nasl");
 exit(0);
}

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

login = get_kb_item(string("cvs/", port, "/login"));
pass  = get_kb_item(string("cvs/", port, "/pass"));
dir   = get_kb_item(string("cvs/", port, "/dir"));

if(!login || !dir) {
	soc = open_sock_tcp(port);
	if(!soc)exit(0);

	req = string("BEGIN AUTH REQUEST\n",
	"/\n",
	"\n",
	"A\n",
	"END AUTH REQUEST\n");
	send(socket:soc, data:req);
	r = recv_line(socket:soc, length:4096);
	if("repository" >< r || "I HATE" >< r)
		{
		str = 
string("The remote host is running a CVS server on this port, but
Nessus could not determine which version is running.

There is a flaw in CVS up to version 1.11.5 which makes it
vulnerable to a double free() bug which may allow an
attacker to gain a shell on this host.

*** This may be a false positive, check the version
*** of CVS locally

Solution : Upgrade to CVS 1.11.5
Risk Factor : High");
		security_hole(port:port, data:str);
		}
	}

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("BEGIN AUTH REQUEST\n",
dir, "\n",
login,"\n",
"A", pass,"\n",
"END AUTH REQUEST\n");

  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  if("I LOVE YOU" >< r)
  {
    send(socket:soc, data:string("version\n"));
    r = recv_line(socket:soc, length:4096);
    if("Concurrent" >< r)
    {
     set_kb_item(name:string("cvs/", port, "/version"), value:r);
     if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.[0-4][^0-9]).*", string:r))
     	security_hole(port);
    }
  }
  close(soc);
 
