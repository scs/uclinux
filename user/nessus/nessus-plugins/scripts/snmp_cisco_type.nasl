#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(10969);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Obtain Cisco type via SNMP";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script uses SNMP to obtain the type of the remote
CISCO router

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Enumerates Cisco model via SNMP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "SNMP";
 script_family(english:family["english"]);
 
 script_dependencie("snmp_default_communities.nasl",
 		     "snmp_sysDesc.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

os = get_kb_item("SNMP/sysDesc");
if(!os)exit(0);
if(!ereg(pattern:".*IOS.*Version.*", string:os))exit(0);

#
# Solaris comes with a badly configured snmpd which
# always reply with the same value. We make sure the answers
# we receive are not in the list of default values usually
# answered...
#
function valid_snmp_value(value)
{
 if("/var/snmp/snmpdx.st" >< value)return(0);
 if("/etc/snmp/conf" >< value)return(0);
 if( (strlen(value) == 1) && (ord(value[0]) < 32) )return(0);
 return(1);
}

#--------------------------------------------------------------------#
# Forges an SNMP GET packet                                          #
#--------------------------------------------------------------------#


function get(community)
{
 len = strlen(community);
 len = len % 256;
 _r = raw_string(0x02, 0x01, 0x00, 0x04, len) +
 	community + 
      raw_string(0xA0, 0x1C, 0x02, 0x04, 0x74, 0xD9, 0x0C, 0x2C, 0x02,
      		0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x30,
		0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x02, 0x00, 0x05, 0x00);
 tot_len = strlen(_r);
 tot_len = tot_len % 256;
 res = raw_string(0x30, tot_len) + _r;
 return(res);
}


function decode(community, pkt)
{
 skip = strlen(community);
 skip = skip + 44;
 if(strlen(pkt) < skip)
  return(0);
 else
 {
 tot_len = strlen(pkt);
 tot_len = tot_len - skip;
 val = 0;

 
 for(i=0;i<tot_len;i=i+1)
 {
  val = val * 128;
  v   = ord(pkt[skip+i]);
  if(v > 0x80)
  {
   v = v - 0x80;
  }
  val = val + v;
 }
 return(val);
 }
}

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port) port = 161;


res = "";

soc = open_sock_udp(port);

req = get(community:community);

send(socket:soc, data:req);
r = recv(socket:soc, length:1025);
if(strlen(r) < 48)exit(0);

type = decode(pkt:r, community:community);


cisco[1] = "ciscoGatewayServer";
cisco[2] = "ciscoTerminalServer";
cisco[3] = "ciscoTrouter";
cisco[4] = "ciscoProtocolTranslator";
cisco[5] = "ciscoIGS";
cisco[6] = "cisco3000";
cisco[7] = "cisco4000";
cisco[8] = "cisco7000";
cisco[9] = "ciscoCS500";
cisco[10] = "cisco2000";
cisco[11] = "ciscoAGSplus";
cisco[12] = "cisco7010";
cisco[13] = "cisco2500";
cisco[14] = "cisco4500";
cisco[15] = "cisco2102";
cisco[16] = "cisco2202";
cisco[17] = "cisco2501";
cisco[18] = "cisco2502";
cisco[19] = "cisco2503";
cisco[20] = "cisco2504";
cisco[21] = "cisco2505";
cisco[22] = "cisco2506";
cisco[23] = "cisco2507";
cisco[24] = "cisco2508";
cisco[25] = "cisco2509";
cisco[26] = "cisco2510";
cisco[27] = "cisco2511";
cisco[28] = "cisco2512";
cisco[29] = "cisco2513";
cisco[30] = "cisco2514";
cisco[31] = "cisco2515";
cisco[32] = "cisco3101";
cisco[33] = "cisco3102";
cisco[34] = "cisco3103";
cisco[35] = "cisco3104";
cisco[36] = "cisco3202";
cisco[37] = "cisco3204";
cisco[38] = "ciscoAccessProRC";
cisco[39] = "ciscoAccessProEC";
cisco[40] = "cisco1000";
cisco[41] = "cisco1003";
cisco[42] = "cisco2516";
cisco[43] = "cisco1020";
cisco[44] = "cisco1004";
cisco[45] = "cisco7507";
cisco[46] = "cisco7513";
cisco[48] = "cisco7505";
cisco[49] = "cisco1005";
cisco[50] = "cisco4700";
cisco[51] = "ciscoPro1003";
cisco[52] = "ciscoPro1004";
cisco[53] = "ciscoPro1005";
cisco[55] = "ciscoPro2500PCE";
cisco[56] = "ciscoPro2501";
cisco[57] = "ciscoPro2503";
cisco[58] = "ciscoPro2505";
cisco[59] = "ciscoPro2507";
cisco[60] = "ciscoPro2509";
cisco[61] = "ciscoPro2511";
cisco[62] = "ciscoPro2514";
cisco[63] = "ciscoPro2516";
cisco[64] = "ciscoPro2519";
cisco[66] = "ciscoPro4500";
cisco[67] = "cisco2517";
cisco[68] = "cisco2518";
cisco[69] = "cisco2519";
cisco[70] = "cisco2520";
cisco[71] = "cisco2521";
cisco[72] = "cisco2522";
cisco[73] = "cisco2523";
cisco[74] = "cisco2524";
cisco[75] = "cisco2525";
cisco[76] = "ciscoPro751";
cisco[77] = "ciscoPro752";
cisco[78] = "ciscoPro753";
cisco[81] = "cisco751";
cisco[82] = "cisco752";
cisco[83] = "cisco753";
cisco[92] = "ciscoPro765";
cisco[93] = "ciscoPro766";
cisco[98] = "cisco761";
cisco[99] = "cisco762";
cisco[102] = "cisco765";
cisco[103] = "cisco766";
cisco[104] = "ciscoPro2520";
cisco[105] = "ciscoPro2522";
cisco[106] = "ciscoPro2524";
cisco[107] = "ciscoLS1010";
cisco[108] = "cisco7206";
cisco[109] = "ciscoAS5200";
cisco[110] = "cisco3640";
cisco[113] = "cisco1601";
cisco[114] = "cisco1602";
cisco[115] = "cisco1603";
cisco[116] = "cisco1604";
cisco[117] = "ciscoPro1601";
cisco[118] = "ciscoPro1602";
cisco[119] = "ciscoPro1603";
cisco[120] = "ciscoPro1604";
cisco[122] = "cisco3620";
cisco[125] = "cisco7204";
cisco[126] = "cisco771";
cisco[127] = "cisco772";
cisco[128] = "cisco775";
cisco[129] = "cisco776";
cisco[130] = "ciscoPro2502";
cisco[131] = "ciscoPro2504";
cisco[132] = "ciscoPro2506";
cisco[133] = "ciscoPro2508";
cisco[134] = "ciscoPro2510";
cisco[135] = "ciscoPro2512";
cisco[136] = "ciscoPro2513";
cisco[137] = "ciscoPro2515";
cisco[138] = "ciscoPro2517";
cisco[139] = "ciscoPro2518";
cisco[140] = "ciscoPro2523";
cisco[141] = "ciscoPro2525";
cisco[142] = "ciscoPro4700";
cisco[147] = "ciscoPro316T";
cisco[148] = "ciscoPro316C";
cisco[149] = "ciscoPro3116";
cisco[150] = "catalyst116T";
cisco[151] = "catalyst116C";
cisco[152] = "catalyst1116";
cisco[153] = "ciscoAS2509RJ";
cisco[154] = "ciscoAS2511RJ";
cisco[157] = "ciscoMC3810";
cisco[160] = "cisco1503";
cisco[161] = "cisco1502";
cisco[162] = "ciscoAS5300";
cisco[164] = "ciscoLS1015";
cisco[165] = "cisco2501FRADFX";
cisco[166] = "cisco2501LANFRADFX";
cisco[167] = "cisco2502LANFRADFX";
cisco[168] = "ciscoWSX5302";
cisco[169] = "ciscoFastHub216T";
cisco[170] = "catalyst2908xl";
cisco[171] = "catalyst2916m-xl";
cisco[172] = "cisco1605";
cisco[173] = "cisco12012";
cisco[175] = "catalyst1912C";
cisco[176] = "ciscoMicroWebServer2";
cisco[177] = "ciscoFastHubBMMTX";
cisco[178] = "ciscoFastHubBMMFX";
cisco[179] = "ciscoUBR7246";
cisco[180] = "cisco6400";
cisco[181] = "cisco12004";
cisco[182] = "cisco12008";
cisco[183] = "catalyst2924XL";
cisco[184] = "catalyst2924CXL";
cisco[185] = "cisco2610";
cisco[186] = "cisco2611";
cisco[187] = "cisco2612";
cisco[188] = "ciscoAS5800";
cisco[189] = "ciscoSC3640";
cisco[190] = "cisco8510";
cisco[191] = "ciscoUBR904";
cisco[192] = "cisco6200";
cisco[194] = "cisco7202";
cisco[195] = "cisco2613";
cisco[196] = "cisco8515";
cisco[197] = "catalyst9006";
cisco[198] = "catalyst9009";
cisco[199] = "ciscoRPM";
cisco[200] = "cisco1710";
cisco[201] = "cisco1720";
cisco[202] = "catalyst8540msr";
cisco[203] = "catalyst8540csr";
cisco[204] = "cisco7576";
cisco[205] = "cisco3660";
cisco[206] = "cisco1401";
cisco[208] = "cisco2620";
cisco[209] = "cisco2621";
cisco[210] = "ciscoUBR7223";
cisco[211] = "cisco6400Nrp";
cisco[212] = "cisco801";
cisco[213] = "cisco802";
cisco[214] = "cisco803";
cisco[215] = "cisco804";
cisco[216] = "cisco1750";
cisco[217] = "catalyst2924XLv";
cisco[218] = "catalyst2924CXLv";
cisco[219] = "catalyst2912XL";
cisco[220] = "catalyst2924MXL";
cisco[221] = "catalyst2912MfXL";
cisco[222] = "cisco7206VXR";
cisco[223] = "cisco7204VXR";
cisco[224] = "cisco1538M";
cisco[225] = "cisco1548M";
cisco[226] = "ciscoFasthub100";
cisco[227] = "ciscoPIXFirewall";
cisco[228] = "ciscoMGX8850";
cisco[229] = "ciscoMGX8830";
cisco[230] = "catalyst8510msr";
cisco[231] = "catalyst8515msr";
cisco[232] = "ciscoIGX8410";
cisco[233] = "ciscoIGX8420";
cisco[234] = "ciscoIGX8430";
cisco[235] = "ciscoIGX8450";
cisco[237] = "ciscoBPX8620";
cisco[238] = "ciscoBPX8650";
cisco[239] = "ciscoBPX8680";
cisco[240] = "ciscoCacheEngine";
cisco[241] = "ciscoCat6000";
cisco[242] = "ciscoBPXSes";
cisco[243] = "ciscoIGXSes";
cisco[244] = "ciscoLocalDirector";
cisco[245] = "cisco805";
cisco[246] = "catalyst3508GXL";
cisco[247] = "catalyst3512XL";
cisco[248] = "catalyst3524XL";
cisco[249] = "cisco1407";
cisco[250] = "cisco1417";
cisco[251] = "cisco6100";
cisco[252] = "cisco6130";
cisco[253] = "cisco6260";
cisco[254] = "ciscoOpticalRegenerator";
cisco[255] = "ciscoUBR924";
cisco[256] = "ciscoWSX6302Msm";
cisco[257] = "catalyst5kRsfc";
cisco[258] = "catalyst6kMsfc";
cisco[259] = "cisco7120Quadt1";
cisco[260] = "cisco7120T3";
cisco[261] = "cisco7120E3";
cisco[262] = "cisco7120At3";
cisco[263] = "cisco7120Ae3";
cisco[264] = "cisco7120Smi3";
cisco[265] = "cisco7140Dualt3";
cisco[266] = "cisco7140Duale3";
cisco[267] = "cisco7140Dualat3";
cisco[268] = "cisco7140Dualae3";
cisco[269] = "cisco7140Dualmm3";
cisco[270] = "cisco827QuadV";
cisco[271] = "ciscoUBR7246VXR";
cisco[272] = "cisco10400";
cisco[273] = "cisco12016";
cisco[274] = "ciscoAs5400";
cisco[275] = "cat2948gL3";
cisco[276] = "cisco7140Octt1";
cisco[277] = "cisco7140Dualfe";
cisco[278] = "cat3548XL";
cisco[279] = "ciscoVG200";
cisco[280] = "cat6006";
cisco[281] = "cat6009";
cisco[282] = "cat6506";
cisco[283] = "cat6509";
cisco[284] = "cisco827";
cisco[285] = "ciscoManagementEngine1100";
cisco[286] = "ciscoMc3810V3";
cisco[287] = "cat3524tXLEn";
cisco[288] = "cisco7507z";
cisco[289] = "cisco7513z";
cisco[290] = "cisco7507mx";
cisco[291] = "cisco7513mx";
cisco[292] = "ciscoUBR912C";
cisco[293] = "ciscoUBR912S";
cisco[294] = "ciscoUBR914";
cisco[295] = "cisco802J";
cisco[296] = "cisco804J";
cisco[297] = "cisco6160";
cisco[298] = "cat4908gL3";
cisco[299] = "cisco6015";
cisco[300] = "cat4232L3";
cisco[301] = "catalyst6kMsfc2";
cisco[302] = "cisco7750Mrp200";
cisco[303] = "cisco7750Ssp80";
cisco[306] = "ciscoCVA122";
cisco[307] = "ciscoCVA124";
cisco[308] = "ciscoAS5850";
cisco[310] = "cat6509Sp";
cisco[311] = "ciscoMGX8240";
cisco[312] = "cat4840gL3";
cisco[313] = "ciscoAS5350";
cisco[314] = "cisco7750";
cisco[316] = "ciscoUBR925";
cisco[317] = "ciscoUBR10012";
cisco[318] = "catalyst4kGateway";
cisco[319] = "cisco2650";
cisco[320] = "cisco2651";
cisco[321] = "cisco826QuadV";
cisco[323] = "catalyst295012";
cisco[324] = "catalyst295024";
cisco[325] = "catalyst295024C";
cisco[329] = "cisco626";
cisco[330] = "cisco627";
cisco[331] = "cisco633";
cisco[332] = "cisco673";
cisco[333] = "cisco675";
cisco[334] = "cisco675e";
cisco[335] = "cisco676";
cisco[336] = "cisco677";
cisco[337] = "cisco678";
cisco[338] = "cisco3661Ac";
cisco[339] = "cisco3661Dc";
cisco[340] = "cisco3662Ac";
cisco[341] = "cisco3662Dc";
cisco[342] = "cisco3662AcCo";
cisco[343] = "cisco3662DcCo";
cisco[344] = "ciscoUBR7111";
cisco[346] = "ciscoUBR7114";
cisco[348] = "cisco12010";
cisco[349] = "cisco8110";
cisco[351] = "ciscoUBR905";
cisco[353] = "ciscoSOHO77";
cisco[354] = "ciscoSOHO76";
cisco[355] = "cisco7150Dualfe";
cisco[356] = "cisco7150Octt1";
cisco[357] = "cisco7150Dualt3";
cisco[359] = "catalyst2950t24";
cisco[360] = "ciscoVPS1110";
cisco[361] = "ciscoContentEngine";
cisco[362] = "ciscoIAD2420";
cisco[363] = "cisco677i";
cisco[364] = "cisco674";
cisco[365] = "ciscoDPA7630";
cisco[366] = "catalyst355024";
cisco[367] = "catalyst355048";
cisco[368] = "catalyst355012T";
cisco[371] = "ciscoCVA122E";
cisco[372] = "ciscoCVA124E";
cisco[373] = "ciscoURM";
cisco[374] = "ciscoURM2FE";
cisco[375] = "ciscoURM2FE2V";
cisco[379] = "ciscoCAP340";
cisco[381] = "ciscoDPA7610";
cisco[385] = "cisco12416";
cisco[386] = "cat2948gL3Dc";
cisco[387] = "cat4908gL3Dc";
cisco[388] = "cisco12406";
cisco[389] = "ciscoPIXFirewall506";
cisco[390] = "ciscoPIXFirewall515";
cisco[391] = "ciscoPIXFirewall520";
cisco[392] = "ciscoPIXFirewall525";
cisco[393] = "ciscoPIXFirewall535";
cisco[394] = "cisco12410";
cisco[395] = "cisco811";
cisco[396] = "cisco813";
cisco[397] = "cisco10720";
cisco[399] = "cisco4224";
cisco[403] = "cisco7401ASR";
cisco[405] = "ciscoHSE1105";
cisco[406] = "ciscoONS15540ESP";
cisco[409] = "ciscoCe507";
cisco[410] = "ciscoCe560";
cisco[411] = "ciscoCe590";
cisco[412] = "ciscoCe7320";
cisco[417] = "ciscoPIXFirewall501";
cisco[418] = "cisco2610M";
cisco[419] = "cisco2611M";
cisco[423] = "cisco12404";
cisco[424] = "cisco9004";
cisco[427] = "catalyst295012G";
cisco[428] = "catalyst295024G";
cisco[429] = "catalyst295048G";
cisco[430] = "catalyst295024S";
cisco[431] = "catalyst355012G";
cisco[432] = "ciscoCE507AV";
cisco[433] = "ciscoCE560AV";
cisco[434] = "ciscoIE2105";
cisco[439] = "cisco7304";
cisco[450] = "ciscoPIXFirewall506E";
cisco[451] = "ciscoPIXFirewall515E";
cisco[452] = "cat355024Dc";
cisco[454] = "ciscoCE2636";
cisco[455] = "ciscoDwCE";
cisco[457] = "ciscoRPMPR";
cisco[464] = "cisco6400UAC";
cisco[466] = "cisco2610XM";
cisco[467] = "cisco2611XM";
cisco[468] = "cisco2620XM";
cisco[469] = "cisco2621XM";
cisco[470] = "cisco2650XM";
cisco[471] = "cisco2651XM";
cisco[472] = "catalyst295024GDC";
cisco[481] = "ciscoONS15540ESPx";
cisco[486] = "ciscoCDM4630";
cisco[487] = "ciscoCDM4650";
cisco[490] = "ciscoCE508";
cisco[491] = "ciscoCE565";
cisco[492] = "ciscoCE7325";
cisco[504] = "ciscoCE7305";
cisco[505] = "ciscoCE510";
cisco[507] = "ciscoAIRAP1100";
cisco[517] = "ciscoGSS";
cisco[518] = "ciscoPrimaryGSSM";
cisco[519] = "ciscoStandbyGSSM";
cisco[521] = "ciscoDSC9216K9";
cisco[522] = "cat6500FirewallSm";
cisco[524] = "ciscoCSM";
cisco[525] = "ciscoAIRAP1210";
cisco[531] = "ciscoCR4430";
cisco[532] = "ciscoCR4450";
cisco[533] = "ciscoAIRBR1410";





if(!cisco[type])
{
 item = "unknown";
}
else
{ 
 item = cisco[type];
}

set_kb_item(name:"CISCO/model", value:item);

if(!(item == "unknown"))
{
rep = 
string("Using SNMP, we could determine the model of the remote Cisco device:\n",
	item);

security_note(port:port,
		protocol:"udp",
		data:rep);
}
