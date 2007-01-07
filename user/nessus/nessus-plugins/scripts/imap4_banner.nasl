#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# License : GPLv2
#

if(description)
{
 script_id(11414);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "IMAP Banner";
 name["francais"] = "Banniere IMAP";
 
 script_name(english:name["english"],francais:name["francais"]);
 
 desc["english"] = "
Displays the imap4 service banner.

Risk factor: None";

 script_copyright(english:"This script is Copyright (C) 2003 StrongHoldNet",
 		  francais:"Ce script est Copyright (C) 2003 StrongHoldNet");

 script_description(english:desc["english"]);
 summary["english"] = "displays the imap4 banner";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 family["english"] = "General";
 script_family(english:family["english"]); 

 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}


port = get_kb_item("Services/imap");

if(!port) port = 143;

banner = get_kb_item(string("imap/banner/", port));

if(banner)
{
 if (!ereg(pattern:"\* OK", string:banner)) exit(0);
 report = string("The remote imap server banner is :\n",banner,
 "\nVersions and types should be omitted where possible.\nChange the imap banner to something generic.");
 security_note(port:port, data:report);
}

