#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# References:
# From: "kai takashi" <rst@coders.com>
# Organization: takashi industries
# To: bugtraq@securityfocus.com
# Subject: Remote Shell Trojan: Threat, Origin and the Solution
# Date: Sun, 9 Sep 2001 14:40:27 +0300
# CC: incidents@securityfocus.com, focus-virus@securityfocus.com, vulnwatch@vulnwatch.org, contribute@linuxsecurity.org
# 
# Date: Mon, 10 Mar 2003 01:54:12 -0500
# From: "Russ" <Russ.Cooper@RC.ON.CA>
# Subject: Alert: New Worm - W32/Deloder on TCP445
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#
# http://vil.nai.com/vil/content/v_100128.htm
#


if(description)
{
 script_id(11157);
 script_version ("$Revision: 1.22 $");
 
 name["english"] = "Trojan horses";
 name["francais"] = "Chevaux de Troie";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "An unknown service runs on this port. 
It is sometimes opened by Trojan horses. 
Unless you know for sure what is behind it, you'd better
check your system.

Solution: if a trojan horse is running, run a good antivirus scanner

Risk factor : Low";


 desc["francais"] = "Un service inconnu tourne sur ce port.
Il est parfois utilisé par des chevaux de Troie.
À moins que vous ne soyez sûr de ce qui est derrière, vous
devriez vérifier votre système.

Solution: si un cheval de Troie est présent, lancez un bon antivirus

Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Look for potential trojan horses";
 summary["francais"] = "Cherche des chevaux de Troie potentiels";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie(
  "PC_anywhere_tcp.nasl",
   "SHN_discard.nasl",
   "X.nasl",
   "apcnisd_detect.nasl",
   "alcatel_backdoor_switch.nasl",
   "asip-status.nasl",
   "auth_enabled.nasl",
   "bugbear.nasl",
   "cifs445.nasl",
   "dcetest.nasl",
   "dns_server.nasl",
   "echo.nasl",
   "find_service.nes",
   "find_service2.nasl",
   "mldonkey_telnet.nasl",
   "mssqlserver_detect.nasl",
   "mysql_version.nasl",
   "nessus_detect.nasl",
   "qmtp_detect.nasl",
   "radmin_detect.nasl",
   "rpc_portmap.nasl",
   "rpcinfo.nasl",
   "rsh.nasl",
   "socks.nasl",
   "telnet.nasl",
   "xtel_detect.nasl",
   "xtelw_detect.nasl");
 script_require_ports("Services/unknown");
 exit(0);
}

#
# This list comes from:
# http://www.sans.org/newlook/resources/IDFAQ/oddports.htm
# http://www.simovits.com/trojans/trojans.html
# 
trojanlist = "
UDP 1 Socket de Troie
TCP 2 Death
TCP 15 B2
TCP 20 Senna Spy FTP server
TCP 21 Back Construction, Blade Runner, Cattivik FTP Server, CC Invader, Dark FTP, Doly Trojan, Fore, FreddyK, Invisible FTP, Juggernaut 42 , Larva, MotIv FTP, Net Administrator, Ramen, RTB 666, Senna Spy FTP server, The Flu, Traitor 21, WebEx, WinCrash
TCP 22 Adore sshd, Shaft
# TCP 23 ADM worm, Fire HacKer, My Very Own trojan, RTB 666, Telnet Pro, Tiny Telnet Server - TTS, Truva Atl
TCP 25 Ajan, Antigen, Barok, BSE, Email Password Sender - EPS, EPS II, Gip, Gris, Happy99, Hpteam mail, I love you, Kuang2, Magic Horse, MBT (Mail Bombing Trojan),Moscow Email trojan, Naebi, NewApt worm, ProMail trojan, Shtirlitz, Stealth, Stukach, Tapiras, Terminator, WinPC, WinSpy
TCP 30 Agent 40421
TCP 31 Agent 31, Hackers Paradise, Masters Paradise
TCP 39 SubSARI
TCP 41 Deep Throat, Foreplay, Reduced Foreplay
TCP 44 Arctic
TCP 48 DRAT
TCP 50 DRAT
TCP 53 ADM worm, Lion
TCP 58 DMSetup
TCP 59 DMSetup
TCP 69 BackGate
TCP 79 CDK, Firehotcker
TCP 80 711 trojan (Seven Eleven), AckCmd, Back End, Back Orifice 2000 Plug-Ins, Cafeini, CGI Backdoor, Executor, God Message, God Message 4 Creator, Hooker, IISworm, MTX, NCX, Noob, Ramen, Reverse WWW Tunnel Backdoor, RingZero, RTB 666, Seeker, WAN Remote, Web Server CT, WebDownloader
TCP 81 RemoConChubo
TCP 99 Hidden Port, Mandragore, NCX
TCP 110 ProMail trojan
TCP 113 Invisible Identd Deamon, Kazimas
TCP 119 Happy99
TCP 121 Attack Bot, God Message, JammerKillah
TCP 123 Net Controller
TCP 133 Farnaz
TCP 137 Chode
UDP 137 Msinit, Qaz
TCP 138 Chode
#TCP 139 Chode, God Message worm, Msinit, Netlog, Network, Qaz, Sadmind, SMB Relay
TCP 142 NetTaxi
TCP 146 Infector
UDP 146 Infector
TCP 166 NokNok
TCP 170 A-trojan
TCP 334 Backage
TCP 411 Backage
TCP 420 Breach, Incognito
TCP 421 TCP Wrappers trojan
TCP 449 ierk8243
TCP 455 Fatal Connections
TCP 456 Hackers Paradise
TCP 511 T0rn Rootkit
#TCP 513 Grlogin
TCP 514 RPC Backdoor
#TCP 515 lpdw0rm, Ramen
TCP 531 Net666, Rasmin
TCP 555 711 trojan (Seven Eleven), Ini-Killer , Net Administrator, Phase Zero, Phase-0, Stealth Spy
TCP 600 Sadmind
TCP 605 Secret Service
TCP 661 NokNok
TCP 666 Attack FTP, Back Construction, Cain & Abel, lpdw0rm, NokNok, Satans Back Door - SBD, ServU, Shadow Phyre, th3r1pp3rz (= Therippers)
TCP 667 SniperNet
TCP 669 DP trojan
TCP 692 GayOL
TCP 707 Welchia
TCP 777 AimSpy, Undetected
TCP 808 WinHole
TCP 911 Dark Shadow
TCP 961 ierk8243
TCP 999 Chat power, Deep Throat, Foreplay, Reduced Foreplay, WinSatan
TCP 1000 Connecter, Der Späher / Der Spaeher, Direct Connection
TCP 1001 Der Späher / Der Spaeher, Le Guardien, Silencer, WTheef, ebEx
TCP 1005 Theef
TCP 1008 Lion
TCP 1010 Doly Trojan
TCP 1011 Doly Trojan
TCP 1012 Doly Trojan
TCP 1015 Doly Trojan
TCP 1016 Doly Trojan
TCP 1020 Vampire
TCP 1024 Jade, Latinus, NetSpy, Remote Administration Tool - RAT [no 2]
TCP 1025 Fraggle Rock, md5 Backdoor, NetSpy, Remote Storm
UDP 1025 Remote Storm
TCP 1031 Xanadu
TCP 1035 Multidropper
TCP 1042 BLA trojan
UDP 1042 BLA trojan
TCP 1045 Rasmin
TCP 1049 /sbin/initd
TCP 1050 MiniCommand
TCP 1054 AckCmd
TCP 1080 SubSeven 2.2, WinHole
TCP 1081 WinHole
TCP 1082 WinHole
TCP 1083 WinHole
TCP 1090 Xtreme
TCP 1095 Remote Administration Tool - RAT
TCP 1097 Remote Administration Tool - RAT
TCP 1098 Remote Administration Tool - RAT
TCP 1099 Blood Fest Evolution, Remote Administration Tool - RAT
UDP 1104 RexxRave
TCP 1150 Orion
TCP 1151 Orion
TCP 1170 Psyber Stream Server - PSS, Streaming Audio Server, Voice
TCP 1174 DaCryptic
TCP 1180 Unin68
TCP 1192 Lovgate.A, Lovgate.B, Lovgate.C
UDP 1200 NoBackO
UDP 1201 NoBackO
TCP 1207 SoftWAR
TCP 1208 Infector
TCP 1212 Kaos
TCP 1234 SubSeven Java client, Ultors Trojan
TCP 1243 BackDoor-G, SubSeven, SubSeven Apocalypse, Tiles
TCP 1245 VooDoo Doll
TCP 1255 Scarab
TCP 1256 Project nEXT, RexxRave
TCP 1269 Matrix
TCP 1272 The Matrix
TCP 1313 NETrojan
TCP 1337 Shadyshell
TCP 1338 Millenium Worm
TCP 1349 Bo dll
TCP 1386 Dagger
TCP 1394 GoFriller
TCP 1441 Remote Storm
TCP 1492 FTP99CMP
TCP 1524 Trinoo
TCP 1568 Remote Hack
TCP 1600 Direct Connection, Shivka-Burka
TCP 1703 Exploiter
TCP 1777 Scarab
TCP 1807 SpySender
TCP 1826 Glacier
TCP 1966 Fake FTP
TCP 1969 OpC BO
TCP 1981 Bowl, Shockrave
TCP 1991 PitFall
TCP 1999 Back Door, SubSeven, TransScout
TCP 2000 Der Späher / Der Spaeher, Insane Network, Last 2000, Remote Explorer 2000, Senna Spy Trojan Generator
TCP 2001 Der Späher / Der Spaeher, Trojan Cow
TCP 2023 Ripper Pro
TCP 2080 WinHole
TCP 2115 Bugs
UDP 2130 Mini Backlash
TCP 2140 The Invasor
UDP 2140 Deep Throat, Foreplay, Reduced Foreplay
TCP 2155 Illusion Mailer
TCP 2255 Nirvana
TCP 2283 Hvl RAT
TCP 2300 Xplorer
TCP 2311 Studio 54
TCP 2330 IRC Contact
TCP 2331 IRC Contact
TCP 2332 IRC Contact
TCP 2333 IRC Contact
TCP 2334 IRC Contact
TCP 2335 IRC Contact
TCP 2336 IRC Contact
TCP 2337 IRC Contact
TCP 2338 IRC Contact
TCP 2339 IRC Contact, Voice Spy
UDP 2339 Voice Spy
TCP 2400 Portd
TCP 2345 Doly Trojan
TCP 2555 Lion, T0rn Rootkit
TCP 2565 Striker trojan
TCP 2583 WinCrash
TCP 2589 Dagger
TCP 2600 Digital RootBeer
TCP 2702 Black Diver
TCP 2716 The Prayer
TCP 2773 SubSeven, SubSeven 2.1 Gold
TCP 2774 SubSeven, SubSeven 2.1 Gold
TCP 2801 Phineas Phucker
TCP 2929 Konik
UDP 2989 Remote Administration Tool - RAT
TCP 3000 InetSpy, Remote Shut
TCP 3024 WinCrash
TCP 3031 Microspy
TCP 3128 Reverse WWW Tunnel Backdoor, RingZero
TCP 3129 Masters Paradise
TCP 3131 SubSARI
TCP 3150 The Invasor
UDP 3150 Deep Throat, Foreplay, Reduced Foreplay, Mini Backlash
TCP 3456 Terror trojan
TCP 3459 Eclipse 2000, Sanctuary
TCP 3700 Portal of Doom - POD
TCP 3777 PsychWard
TCP 3791 Total Solar Eclypse
TCP 3801 Total Solar Eclypse
TCP 4000 Connect-Back Backdoor, Skydance
TCP 4092 WinCrash
TCP 4242 Virtual Hacking Machine - VHM
TCP 4321 BoBo
TCP 4444 CrackDown, Prosiak, Swift Remote, MS Blast
TCP 4488 Event Horizon
TCP 4523 Celine
TCP 4545 Internal Revise
TCP 4567 File Nail
TCP 4590 ICQ Trojan
TCP 4653 Cero
TCP 4666 Mneah
TCP 4950 ICQ Trogen (Lm)
TCP 5000 Back Door Setup, BioNet Lite, Blazer5, Bubbel, ICKiller, Ra1d, Socket de Troie
TCP 5001 Back Door Setup, Socket de Troie
TCP 5002 cd00r, Linux Rootkit IV (4), Shaft
TCP 5005 Aladino
TCP 5010 Solo
TCP 5011 One of the Last Trojans - OOTLT, One of the Last Trojans - OOTLT  modified
TCP 5025 WM Remote KeyLogger
TCP 5031 Net Metropolitan
TCP 5032 Net Metropolitan
TCP 5321 Firehotcker
TCP 5333 Backage, NetDemon
TCP 5343 wCrat - WC Remote Administration Tool
TCP 5400 Back Construction, Blade Runner
TCP 5401 Back Construction, Blade Runner, Mneah
TCP 5402 Back Construction, Blade Runner, Mneah
UDP 5503 RST (Remote Shell Trojan)
TCP 5512 Illusion Mailer
TCP 5534 The Flu
TCP 5550 Xtcp
TCP 5555 ServeMe
TCP 5556 BO Facil
TCP 5557 BO Facil
TCP 5569 Robo-Hack
TCP 5637 PC Crasher
TCP 5638 PC Crasher
TCP 5742 WinCrash
TCP 5760 Portmap Remote Root Linux Exploit
TCP 5800 BackDoor-ARG
TCP 5802 Y3K RAT
TCP 5873 SubSeven 2.2
TCP 5880 Y3K RAT
TCP 5882 Y3K RAT
UDP 5882 Y3K RAT
TCP 5888 Y3K RAT
UDP 5888 Y3K RAT
TCP 5889 Y3K RAT
TCP 6000 The Thing
TCP 6006 Bad Blood
TCP 6272 Secret Service
TCP 6400 The Thing
TCP 6661 TEMan, Weia-Meia
TCP 6666 Dark Connection Inside, NetBus worm
TCP 6667 Dark FTP, EGO, Maniac rootkit, Moses, ScheduleAgent, SubSeven, Subseven 2.1.4 DefCon 8, The Thing (modified), Trinity, WinSatan
TCP 6669 Host Control, Vampire
TCP 6670 BackWeb Server, Deep Throat, Foreplay or Reduced Foreplay, WinNuke eXtreame
TCP 6711 BackDoor-G, SubSARI, SubSeven , VP Killer
TCP 6712 Funny trojan, SubSeven
TCP 6713 SubSeven
TCP 6723 Mstream
TCP 6767 UandMe
TCP 6771 Deep Throat, Foreplay, Reduced Foreplay
TCP 6776 2000 Cracks, BackDoor-G, SubSeven , VP Killer
UDP 6838 Mstream
TCP 6883 Delta Source DarkStar (??)
TCP 6912 Shit Heep
TCP 6939 Indoctrination
TCP 6969 2000 Cracks, Danton, GateCrasher, IRC 3, Net Controller, Priority
TCP 6970 GateCrasher
TCP 7000 Exploit Translation Server, Kazimas, Remote Grab, SubSeven, SubSeven 2.1 Gold
TCP 7001 Freak88, Freak2k, NetSnooper Gold
TCP 7158 Lohoboyshik
TCP 7215 SubSeven, SubSeven 2.1 Gold
TCP 7300 NetMonitor
TCP 7301 NetMonitor
TCP 7306 NetMonitor
TCP 7307 NetMonitor, Remote Process Monitor
TCP 7308 NetMonitor, X Spy
TCP 7424 Host Control
UDP 7424 Host Control
TCP 7597 Qaz
TCP 7626 Binghe, Glacier, Hyne
TCP 7718 Glacier
TCP 7777 God Message, The Thing (modified), Tini
TCP 7789 Back Door Setup, ICKiller, Mozilla
TCP 7826 Oblivion
TCP 7891 The ReVeNgEr
TCP 7983 Mstream
TCP 8080 Brown Orifice, Generic backdoor, RemoConChubo, Reverse WWW Tunnel Backdoor, RingZero
TCP 8685 Unin68
TCP 8787 Back Orifice 2000
TCP 8812 FraggleRock Lite
TCP 8988 BacHack
TCP 8989 Rcon, Recon, Xcon
TCP 9000 Netministrator
UDP 9325 Mstream
TCP 9400 InCommand
TCP 9870 Remote Computer Control Center
TCP 9872 Portal of Doom - POD
TCP 9873 Portal of Doom - POD
TCP 9874 Portal of Doom - POD
TCP 9875 Portal of Doom - POD
TCP 9876 Cyber Attacker, Rux
TCP 9878 TransScout
TCP 9989 Ini-Killer
TCP 9999 The Prayer
TCP 10000 OpwinTRojan
TCP 10005 OpwinTRojan
TCP 10008 Cheese worm, Lion
UDP 10067 Portal of Doom - POD
TCP 10085 Syphillis
TCP 10086 Syphillis
TCP 10100 Control Total, GiFt trojan
TCP 10101 BrainSpy, Silencer
UDP 10167 Portal of Doom - POD
TCP 10168 Lovgate.B
TCP 10520 Acid Shivers
TCP 10528 Host Control
TCP 10607 Coma
UDP 10666 Ambush
TCP 11000 Senna Spy Trojan Generator
TCP 11050 Host Control
TCP 11051 Host Control
TCP 11223 Progenic trojan, Secret Agent
TCP 11831 Latinus
TCP 12076 Gjamer
TCP 12223 Hack´99 KeyLogger
TCP 12310 PreCursor
TCP 12345 Adore sshd, Ashley, cron / crontab, Fat Bitch trojan, GabanBus, icmp_client.c, icmp_pipe.c, Mypic , NetBus , NetBus Toy, NetBus worm, Pie Bill Gates, ValvNet, Whack Job, X-bill
TCP 12346 Fat Bitch trojan, GabanBus, NetBus, X-bill
TCP 12348 BioNet
TCP 12349 BioNet, Webhead
TCP 12361 Whack-a-mole
TCP 12362 Whack-a-mole
TCP 12363 Whack-a-mole
UDP 12623 DUN Control
TCP 12624 ButtMan
TCP 12631 Whack Job
TCP 12754 Mstream
TCP 13000 Senna Spy Trojan Generator
TCP 13010 BitchController, Hacker Brasil - HBR
TCP 13013 PsychWard
TCP 13014 PsychWard
TCP 13223 Hack´99 KeyLogger
TCP 13473 Chupacabra
TCP 14500 PC Invader
TCP 14501 PC Invader
TCP 14502 PC Invader
TCP 14503 PC Invader
TCP 15000 NetDemon
TCP 15092 Host Control
TCP 15104 Mstream
TCP 15382 SubZero
TCP 15858 CDK
TCP 16484 Mosucker
TCP 16660 Stacheldraht
TCP 16772 ICQ Revenge
TCP 16959 SubSeven, Subseven 2.1.4 DefCon 8
TCP 16969 Priority
TCP 17166 Mosaic
TCP 17300 Kuang2 the virus
TCP 17449 Kid Terror
TCP 17499 CrazzyNet
TCP 17500 CrazzyNet
TCP 17569 Infector
TCP 17593 AudioDoor
TCP 17777 Nephron
TCP 18667 Knark
UDP 18753 Shaft
TCP 19864 ICQ Revenge
TCP 20000 Millenium
TCP 20001 Insect, Millenium, Millenium (Lm)
TCP 20002 AcidkoR
TCP 20005 Mosucker
TCP 20023 VP Killer
TCP 20034 NetBus 2.0 Pro, NetBus 2.0 Pro Hidden, NetRex, Whack Job
TCP 20168 Lovgate.C
TCP 20203 Chupacabra
TCP 20331 BLA trojan
TCP 20432 Shaft
UDP 20433 Shaft
TCP 21544 GirlFriend, Kid Terror, Matrix
TCP 21554 Exploiter, FreddyK, Kid Terror, Schwindler, Winsp00fer
TCP 21579 Breach
TCP 21957 Latinus
TCP 22222 Donald Dick, Prosiak, Ruler, RUX The TIc.K
TCP 23005 NetTrash, Olive, Oxon
TCP 23006 NetTrash
TCP 23023 Logged
TCP 23032 Amanda
TCP 23321 Konik
TCP 23432 Asylum
TCP 23456 Evil FTP, Ugly FTP, Whack Job
TCP 23476 Donald Dick
UDP 23476 Donald Dick
TCP 23477 Donald Dick
TCP 23777 InetSpy
TCP 24000 Infector
TCP 24289 Latinus
TCP 25123 Goy'Z TroJan
TCP 25555 FreddyK
TCP 25685 MoonPie
TCP 25686 MoonPie
TCP 25982 MoonPie
UDP 26274 Delta Source
TCP 26681 Voice Spy
TCP 27160 MoonPie
TCP 27374 Bad Blood, EGO, Fake SubSeven, Lion, Ramen, Seeker, SubSeven , SubSeven 2.1 Gold, Subseven 2.1.4 DefCon 8, SubSeven 2.2, SubSeven Muie, The Saint, Ttfloader, Webhead
UDP 27444 Trinoo
TCP 27573 SubSeven
TCP 27665 Trinoo
TCP 28431 Hack´a´Tack
TCP 28678 Exploiter
TCP 29104 NetTrojan
TCP 29292 BackGate
TCP 29369 ovasOn
TCP 29559 Latinus
TCP 29891 The Unexplained
TCP 30000 Infector
TCP 30001 ErrOr32
TCP 30003 Lamers Death
TCP 30005 Backdoor JZ
TCP 30029 AOL trojan
TCP 30100 NetSphere
TCP 30101 NetSphere
TCP 30102 NetSphere
TCP 30103 NetSphere
UDP 30103 NetSphere
TCP 30133 NetSphere
TCP 30303 Socket de Troie
TCP 30700 Mantis
TCP 30947 Intruse
TCP 30999 Kuang2
TCP 31221 Knark
TCP 31335 Trinoo
TCP 31336 Bo Whack , Butt Funnel
TCP 31337 ADM worm, Back Fire, Back Orifice 1.20 patches, Back Orifice (Lm), Back Orifice russian, Baron Night, Beeone, bindshell, BO client, BO Facil, BO spy, BO2, cron / crontab, Freak88, Freak2k, Gummo, icmp_pipe.c,Linux Rootkit IV (4), Sm4ck, Sockdmini
UDP 31337 Back Orifice, Deep BO
TCP 31338 Back Orifice, Butt Funnel, NetSpy (DK)
UDP 31338 Deep BO, NetSpy (DK)
TCP 31339 NetSpy (DK)
TCP 31557 Xanadu
TCP 31666 BOWhack
TCP 31745 BuschTrommel
TCP 31785 Hack´a´Tack
TCP 31787 Hack´a´Tack
TCP 31788 Hack´a´Tack
UDP 31789 Hack´a´Tack
TCP 31790 Hack´a´Tack
UDP 31791 Hack´a´Tack
TCP 31792 Hack´a´Tack
TCP 32001 Donald Dick
TCP 32100 Peanut Brittle, Project nEXT
TCP 32418 Acid Battery
TCP 32791 Acropolis
TCP 33270 Trinity
TCP 33333 Blakharaz, Prosiak
TCP 33567 Lion, T0rn Rootkit
TCP 33568 Lion, T0rn Rootkit
TCP 33577 PsychWard
TCP 33777 PsychWard
TCP 33911 Spirit 2000, Spirit 2001
TCP 34324 Big Gluck, TN
TCP 34444 Donald Dick
UDP 34555 Trinoo (for Windows)
UDP 35555 Trinoo (for Windows)
TCP 36794 BugBear
TCP 37237 Mantis
TCP 37266 The Killer Trojan
TCP 37651 Yet Another Trojan - YAT
TCP 38741 CyberSpy
TCP 39507 Busters
TCP 40412 The Spy
TCP 40421 Agent 40421, Masters Paradise
TCP 40422 Masters Paradise
TCP 40423 Masters Paradise
TCP 40425 Masters Paradise
TCP 40426 Masters Paradise
TCP 41337 Storm
TCP 41666 Remote Boot Tool - RBT, Remote Boot Tool - RBT
TCP 44444 Prosiak
TCP 44575 Exploiter
UDP 44767 School Bus
TCP 45559 Maniac rootkit
TCP 45673 Acropolis
TCP 47017 T0rn Rootkit
UDP 47262 Delta Source
TCP 48004 Fraggle Rock
TCP 48006 Fraggle Rock
TCP 49000 Fraggle Rock
TCP 49301 OnLine KeyLogger
TCP 50000 SubSARI
TCP 50130 Enterprise
TCP 50505 Socket de Troie
TCP 50766 Fore, Schwindler
TCP 51966 Cafeini
TCP 52317 Acid Battery 2000
TCP 53001 Remote Windows Shutdown - RWS
TCP 54283 SubSeven , SubSeven 2.1 Gold
TCP 54320 Back Orifice 2000
TCP 54321 Back Orifice 2000, School Bus
TCP 55165 File Manager trojan, File Manager trojan, WM Trojan Generator
TCP 55166 WM Trojan GeneratorTCP 57341 NetRaider
TCP 58339 Butt Funnel
TCP 60000 Deep Throat, Foreplay, Reduced Foreplay, Socket de Troie
TCP 60001 Trinity
TCP 60008 Lion, T0rn Rootkit
TCP 60068 Xzip 6000068
TCP 60411 Connection
TCP 61348 Bunker-Hill
TCP 61466 TeleCommando
TCP 61603 Bunker-Hill
TCP 63485 Bunker-Hill
TCP 64101 Taskman / Task Manager
TCP 65000 Devil, Socket de Troie, Stacheldraht
TCP 65390 Eclypse
TCP 65421 Jade
TCP 65432 The Traitor (= th3tr41t0r)
UDP 65432 The Traitor (= th3tr41t0r)
TCP 65530 Windows Mite
TCP 65534 /sbin/initd
TCP 65535 Adore worm, RC1 trojan, Sins
";

include("misc_func.inc");

# Currently, we only check TCP trojan horses

port = get_kb_item("Services/unknown");
if (! port) exit(0); 

if (known_service(port: port)) exit(0);
if (! get_port_state(port)) exit(0);
# I don't know any trojan horse that runs on top of SSL/TLS
t = get_port_transport(port);
if (t == ENCAPS_SSLv23 || t == ENCAPS_SSLv2 || t == ENCAPS_SSLv3 || ENCAPS_TLSv1) exit(0);

req = string("^TCP ", port, " ");
str = egrep(string:trojanlist, pattern: req);
if (! str) exit(0);

key=string("unknown/banner/", port);
banner = get_kb_item(key);

# if banner is void, no use to open the port: find_service already
# did the job
name = ereg_replace(string: str, pattern: req, replace: "");
name = ereg_replace(string: name, pattern: " *, *", replace: string("\n\t"));
m = string("An unknown service runs on this port.\n", 
	"It is sometimes opened by this/these Trojan horse(s):\n\t",
	name,"\n");
if (banner) m = string(m, "Here is the service banner:\n", banner, "\n\n");
m = string(m, "Unless you know for sure what is behind it, you'd better\n",
	"check your system\n\n",
	"*** Anyway, don't panic, Nessus only found an open port. It may\n",
	"*** have been dynamically allocated to some service (RPC...)\n\n",
	"Solution: if a trojan horse is running, run a good antivirus scanner\n",
	"Risk factor : Low");
security_note(port: port, data: m);
