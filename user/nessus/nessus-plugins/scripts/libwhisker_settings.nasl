#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL, blah blah blah
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11122);
 script_version ("$Revision: 1.5 $");

 name["english"] = "Libwhisker options";
 name["francais"] = "Options de libwhisker";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This plugin configures the libwhisker options (used by Nikto and Whisker)
It does not do any security check.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Configure libwhisker options";
 summary["francais"] = "Configure les options de libwhisker";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_SETTINGS);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Settings";
 family["francais"] = "Configuration";
 script_family(english:family["english"], francais:family["francais"]);
 
 script_add_preference(name:"IDS evasion technique: ", type:"radio",
	value:"X (none);1 Random URI encoding (non-UTF8);2 Directory self-reference (/./);3 Premature URL ending;4 Prepend long random string;5 Fake parameter;6 TAB as request spacer;7 Random case sensitivity;8 Use Windows directory separator (\);9 Session splicing (slow)");

 exit(0);
}

opt = script_get_preference("IDS evasion technique: ");
if(!opt)exit(0);
if("none" >< opt)exit(0);

set_kb_item(name:"/Settings/Whisker/NIDS", value:opt);

