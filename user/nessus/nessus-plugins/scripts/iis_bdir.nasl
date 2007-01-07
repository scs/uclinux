#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
#
# See the Nessus Scripts License for details
#
if(description)
{
  script_id(10577);
 script_version ("$Revision: 1.13 $");

  script_name(english:"Check for bdir.htr files");
  desc["english"] = "
The file bdir.htr is a default IIS files which can give
a malicious user a lot of unnecessary information about 
your file system.  Specifically, the bdir.htr script allows
the user to browse and create files on hard drive.  As this
includes critical system files, it is highly possible that
the attacker will be able to use this script to escalate
privileges and gain 'Administrator' access.

Example,
http://target/scripts/iisadmin/bdir.htr??c:\

Solution: If you do not need these files, then delete them, 
otherwise use suitable access control lists to ensure that
the files are not world-readable.

Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Check for existence of bdir.htr");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses", francais:"Abus de CGI");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nes", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);   
  script_require_keys("www/iis");
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
    
port=get_kb_item("Services/www");
if(!port)port=80;
if(get_port_state(port)) 
{
    if(is_cgi_installed_ka(item:"/scripts/iisadmin/bdir.htr", port:port))
    {
        security_warning(port);
        exit(0);
    }
}

