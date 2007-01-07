#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if(description)
{
 script_id(20001);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Nikto";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs nikto(1) to find CGI.
See the section 'plugins options' to configure it

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find CGI with Nikto";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("find_service.nes", "httpver.nasl", "logins.nasl", 
	"no404.nasl", "libwhisker_settings.nasl");
 script_require_ports("Services/www", 80);

 script_add_preference(name:"Force scan all possible CGI directories",
                       type:"checkbox", value:"no");
 script_add_preference(name:"Force full (generic) scan", 
                      type:"checkbox", value:"no");
 exit(0);
}

#

if (! defined_func("pread"))
{
  set_kb_item(name: "/tmp/UnableToRun/11873", value: TRUE);
  display("Script #11873 (nikto_wrapper) cannot run\n");
  exit(0);
}

user = get_kb_item("http/login");
pass = get_kb_item("http/login");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

# Nikto will generate many false positives if the web server is broken
no404 = get_kb_item("www/no404/" + port);
if (no404 || no404 !~ '^[ \t\n\r]*$') exit(0);

i = 0;
argv[i++] = "nikto.pl";

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

argv[i++] = "-h"; argv[i++] = get_host_ip();
argv[i++] = "-p"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

p = script_get_preference("Force scan all possible CGI directories");
if ("yes" >< p) argv[i++] = "-allcgi";
p = script_get_preference("Force full (generic) scan");
if ("yes" >< p) argv[i++] = "-gener";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: "nikto.pl", argv: argv, cd: 1);
if (! r) exit(0);	# error

report = 'Here is the Nikto report:\n';
foreach l (split(r))
{
  display(j ++, "\n");
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, data: report);
