#
# This script was written by Paul Ewing <ewing@ima.umn.edu>
#
# See the Nessus Scripts License for details
#

if(description) {
    script_id(10462);
 script_version ("$Revision: 1.9 $");
 
    name["english"] = "Amanda client version";
    script_name(english:name["english"]);
 
    desc["english"] = "This detects the Amanda backup system client
version. The client version gives potential attackers additional
information about the system they are attacking.

Risk factor : Low";

    script_description(english:desc["english"]);
 
    summary["english"] = "Detect Amanda client version";
    script_summary(english:summary["english"]);
 
    script_category(ACT_GATHER_INFO);
 
    script_copyright(english:"This script is Copyright (C) 2000 Paul J. Ewing Jr.");
    family["english"] = "General";
    script_family(english:family["english"]);
    exit(0);
}

#
# The script code starts here
#

function get_version(soc, port)
{
    req = string("Amanda 2.3 REQ HANDLE 000-65637373 SEQ 954568800\n")
	+ string("SERVICE nessus_scan\n");

    send(socket:soc, data:req);
    result = recv(socket:soc, length:2048);
    if (result) {
        if (egrep(pattern:"^[^ ]+ [0-9]+\.[0-9]+", string:result)) {
	    temp = strstr(result, " ");
            temp = temp - " ";
            temp = strstr(temp, " ");
            version = result - temp;
            data = string("Amanda version: ", version);
            security_note(port:port, data:data, protocol:"udp");
            set_kb_item(name:"Amanda/running", value:TRUE);
	}
    }
}

if(get_udp_port_state(10080))
{
 socudp10080 = open_sock_udp(10080);
 if (socudp10080) {
    get_version(soc:socudp10080, port:10080);
    close(socudp10080);
 }
}

if(get_udp_port_state(10081))
{
 socudp10081 = open_sock_udp(10081);
 if (socudp10081) {
    get_version(soc:socudp10081, port:10081);
    close(socudp10081);
 }
}
