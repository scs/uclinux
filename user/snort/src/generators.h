/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __GENERATORS_H__
#define __GENERATORS_H__

#define GENERATOR_SNORT_ENGINE        1

#define GENERATOR_TAG                 2
#define    TAG_LOG_PKT                1

#define GENERATOR_SPP_PORTSCAN      100
#define     PORTSCAN_SCAN_DETECT        1
#define     PORTSCAN_INTER_INFO         2
#define     PORTSCAN_SCAN_END           3

#define GENERATOR_SPP_MINFRAG       101
#define     MINFRAG_ALERT_ID            1

#define GENERATOR_SPP_HTTP_DECODE   102
#define     HTTP_DECODE_UNICODE_ATTACK  1
#define     HTTP_DECODE_CGINULL_ATTACK  2
#define     HTTP_DECODE_LARGE_METHOD    3
#define     HTTP_DECODE_MISSING_URI     4
#define     HTTP_DECODE_DOUBLE_ENC      5
#define     HTTP_DECODE_ILLEGAL_HEX     6
#define     HTTP_DECODE_OVERLONG_CHAR   7


#define GENERATOR_SPP_DEFRAG        103
#define     DEFRAG_FRAG_OVERFLOW        1
#define     DEFRAG_FRAGS_DISCARDED      2

#define GENERATOR_SPP_SPADE         104
#define     SPADE_ANOM_THRESHOLD_EXCEEDED   1
#define     SPADE_ANOM_THRESHOLD_ADJUSTED   2

#define GENERATOR_SPP_BO            105
#define     BO_TRAFFIC_DETECT           1

#define GENERATOR_SPP_RPC_DECODE    106
#define     RPC_FRAG_TRAFFIC                1
#define     RPC_MULTIPLE_RECORD             2
#define     RPC_LARGE_FRAGSIZE              3
#define     RPC_INCOMPLETE_SEGMENT          4

#define GENERATOR_SPP_STREAM2       107
#define GENERATOR_SPP_STREAM3       108
#define GENERATOR_SPP_TELNET_NEG    109

#define GENERATOR_SPP_UNIDECODE     110
#define     UNIDECODE_CGINULL_ATTACK        1
#define     UNIDECODE_DIRECTORY_TRAVERSAL   2
#define     UNIDECODE_UNKNOWN_MAPPING       3
#define     UNIDECODE_INVALID_MAPPING       4

#define GENERATOR_SPP_STREAM4       111
#define     STREAM4_STEALTH_ACTIVITY            1
#define     STREAM4_EVASIVE_RST                 2
#define     STREAM4_EVASIVE_RETRANS             3
#define     STREAM4_WINDOW_VIOLATION            4
#define     STREAM4_DATA_ON_SYN                 5
#define     STREAM4_STEALTH_FULL_XMAS           6
#define     STREAM4_STEALTH_SAPU                7
#define     STREAM4_STEALTH_FIN_SCAN            8
#define     STREAM4_STEALTH_NULL_SCAN           9
#define     STREAM4_STEALTH_NMAP_XMAS_SCAN      10
#define     STREAM4_STEALTH_VECNA_SCAN          11
#define     STREAM4_STEALTH_NMAP_FINGERPRINT    12
#define     STREAM4_STEALTH_SYN_FIN_SCAN        13
#define     STREAM4_FORWARD_OVERLAP             14
#define     STREAM4_TTL_EVASION                 15
#define     STREAM4_EVASIVE_RETRANS_DATA        16
#define     STREAM4_EVASIVE_RETRANS_DATASPLIT   17
#define     STREAM4_MULTIPLE_ACKED              18
#define     STREAM4_EMERGENCY                   19
#define     STREAM4_SUSPEND                     20

#define GENERATOR_SPP_ARPSPOOF      112
#define     ARPSPOOF_UNICAST_ARP_REQUEST         1
#define     ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC  2
#define     ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST  3
#define     ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK   4

#define GENERATOR_SPP_FRAG2         113
#define     FRAG2_OVERSIZE_FRAG                   1
#define     FRAG2_TEARDROP                        2
#define     FRAG2_TTL_EVASION                     3
#define     FRAG2_OVERLAP                         4
#define     FRAG2_DUPFIRST                        5
#define     FRAG2_MEM_EXCEED                      6
#define     FRAG2_OUTOFORDER                      7
#define     FRAG2_IPOPTIONS                       8
#define     FRAG2_EMERGENCY                       9
#define     FRAG2_SUSPEND                         10

#define GENERATOR_SPP_FNORD         114
#define     FNORD_NOPSLED                         1

#define GENERATOR_SPP_ASN1          115
#define     ASN1_INDEFINITE_LENGTH                1
#define     ASN1_INVALID_LENGTH                   2
#define     ASN1_OVERSIZED_ITEM                   3
#define     ASN1_SPEC_VIOLATION                   4
#define     ASN1_DATUM_BAD_LENGTH                 5


#define GENERATOR_SNORT_DECODE      116
#define     DECODE_NOT_IPV4_DGRAM                 1
#define     DECODE_IPV4_INVALID_HEADER_LEN        2
#define     DECODE_IPV4_DGRAM_LT_IPHDR            3
#define     DECODE_IPV4OPT_BADLEN                 4
#define     DECODE_IPV4OPT_TRUNCATED              5

#define     DECODE_TCP_DGRAM_LT_TCPHDR            45
#define     DECODE_TCP_INVALID_OFFSET             46
#define     DECODE_TCP_LARGE_OFFSET               47

#define     DECODE_TCPOPT_BADLEN                  54
#define     DECODE_TCPOPT_TRUNCATED               55
#define     DECODE_TCPOPT_TTCP                    56
#define     DECODE_TCPOPT_OBSOLETE                57
#define     DECODE_TCPOPT_EXPERIMENT              58

#define     DECODE_UDP_DGRAM_LT_UDPHDR            95
#define     DECODE_UDP_DGRAM_INVALID_LENGTH       96
#define     DECODE_UDP_DGRAM_SHORT_PACKET         97

#define     DECODE_ICMP_DGRAM_LT_ICMPHDR          105
#define     DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR     106
#define     DECODE_ICMP_DGRAM_LT_ADDRHDR          107
#define     DECODE_IPV4_DGRAM_UNKNOWN             108

#define     DECODE_ARP_TRUNCATED                  109
#define     DECODE_EAPOL_TRUNCATED                110
#define     DECODE_EAPKEY_TRUNCATED               111
#define     DECODE_EAP_TRUNCATED                  112

#define     DECODE_BAD_PPPOE                      120
#define     DECODE_BAD_VLAN                       130
#define     DECODE_BAD_VLAN_ETHLLC                131
#define     DECODE_BAD_VLAN_OTHER                 132
#define     DECODE_BAD_80211_ETHLLC               133 
#define     DECODE_BAD_80211_OTHER                134

#define     DECODE_BAD_TRH                        140
#define     DECODE_BAD_TR_ETHLLC                  141
#define     DECODE_BAD_TR_MR_LEN                  142
#define     DECODE_BAD_TRHMR                      143

#define GENERATOR_SPP_SCAN2         117
#define     SCAN_TYPE                             1

#define GENERATOR_SPP_CONV         118
#define     CONV_BAD_IP_PROTOCOL                            1

/*
**  HttpInspect Generator IDs
**
**  IMPORTANT::
**    Whenever events are added to the internal HttpInspect
**    event queue, you must also add the event here.  The
**    trick is that whatever the number is in HttpInspect,
**    it must be +1 when you define it here.
*/
#define GENERATOR_SPP_HTTP_INSPECT_CLIENT           119
#define     HI_CLIENT_ASCII                         1   /* done */
#define     HI_CLIENT_DOUBLE_DECODE                 2   /* done */
#define     HI_CLIENT_U_ENCODE                      3   /* done */
#define     HI_CLIENT_BARE_BYTE                     4   /* done */
#define     HI_CLIENT_BASE36                        5   /* done */
#define     HI_CLIENT_UTF_8                         6   /* done */
#define     HI_CLIENT_IIS_UNICODE                   7   /* done */
#define     HI_CLIENT_MULTI_SLASH                   8   /* done */
#define     HI_CLIENT_IIS_BACKSLASH                 9   /* done */
#define     HI_CLIENT_SELF_DIR_TRAV                 10  /* done */
#define     HI_CLIENT_DIR_TRAV                      11  /* done */
#define     HI_CLIENT_APACHE_WS                     12  /* done */
#define     HI_CLIENT_IIS_DELIMITER                 13  /* done */
#define     HI_CLIENT_NON_RFC_CHAR                  14  /* done */
#define     HI_CLIENT_OVERSIZE_DIR                  15  /* done */
#define     HI_CLIENT_LARGE_CHUNK                   16  /* done */
#define     HI_CLIENT_PROXY_USE                     17  /* done */
#define     HI_CLIENT_WEBROOT_DIR                   18  /* done */

#define GENERATOR_SPP_HTTP_INSPECT_ANOM_SERVER      120
#define     HI_ANOM_SERVER_ALERT                    1   /* done */

#define GENERATOR_FLOW_PORTSCAN                     121
#define     FLOW_SCANNER_FIXED_ALERT                 1
#define     FLOW_SCANNER_SLIDING_ALERT               2
#define     FLOW_TALKER_FIXED_ALERT                  3
#define     FLOW_TALKER_SLIDING_ALERT                4

#define GENERATOR_PSNG                             122
#define     PSNG_TCP_PORTSCAN                      1
#define     PSNG_TCP_DECOY_PORTSCAN                2
#define     PSNG_TCP_PORTSWEEP                     3
#define     PSNG_TCP_DISTRIBUTED_PORTSCAN          4
#define     PSNG_TCP_FILTERED_PORTSCAN             5
#define     PSNG_TCP_FILTERED_DECOY_PORTSCAN       6
#define     PSNG_TCP_PORTSWEEP_FILTERED            7
#define     PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN 8

#define     PSNG_IP_PORTSCAN                       9
#define     PSNG_IP_DECOY_PORTSCAN                 10
#define     PSNG_IP_PORTSWEEP                      11
#define     PSNG_IP_DISTRIBUTED_PORTSCAN           12
#define     PSNG_IP_FILTERED_PORTSCAN              13
#define     PSNG_IP_FILTERED_DECOY_PORTSCAN        14
#define     PSNG_IP_PORTSWEEP_FILTERED             15
#define     PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN  16

#define     PSNG_UDP_PORTSCAN                      17
#define     PSNG_UDP_DECOY_PORTSCAN                18
#define     PSNG_UDP_PORTSWEEP                     19
#define     PSNG_UDP_DISTRIBUTED_PORTSCAN          20
#define     PSNG_UDP_FILTERED_PORTSCAN             21
#define     PSNG_UDP_FILTERED_DECOY_PORTSCAN       22
#define     PSNG_UDP_PORTSWEEP_FILTERED            23
#define     PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN 24

#define     PSNG_ICMP_PORTSWEEP                    25
#define     PSNG_ICMP_PORTSWEEP_FILTERED           26

#define     PSNG_OPEN_PORT                         27

#define GENERATOR_SMTP                             124

/*  This is where all the alert messages will be archived for each
    internal alerts */

#define ARPSPOOF_UNICAST_ARP_REQUEST_STR "(spp_arpspoof) Unicast ARP request"
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR \
"(spp_arpspoof) Ethernet/ARP Mismatch request for Source"
#define ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST_STR \
"(spp_arpspoof) Ethernet/ARP Mismatch request for Destination"
#define ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK_STR \
"(spp_arpspoof) Attempted ARP cache overwrite attack"

#define ASN1_INDEFINITE_LENGTH_STR "(spp_asn1) Indefinite ASN.1 length encoding"
#define ASN1_INVALID_LENGTH_STR "(spp_asn1) Invalid ASN.1 length encoding"
#define ASN1_OVERSIZED_ITEM_STR "(spp_asn1) ASN.1 oversized item, possible overflow"
#define ASN1_SPEC_VIOLATION_STR  "(spp_asn1) ASN.1 spec violation, possible overflow"
#define ASN1_DATUM_BAD_LENGTH_STR "(spp_asn1) ASN.1 Attack: Datum length > packet length"

#define BO_TRAFFIC_DETECT_STR "(spo_bo) Back Orifice Traffic detected"

#define FNORD_NOPSLED_IA32_STR "(spp_fnord) Possible Mutated IA32 NOP Sled detected"
#define FNORD_NOPSLED_HPPA_STR "(spp_fnord) Possible Mutated HPPA NOP Sled detected"
#define FNORD_NOPSLED_SPARC_STR "(spp_fnord) Possible Mutated SPARC NOP Sled detected"

#define FRAG2_DUPFIRST_STR "(spp_frag2) Duplicate first fragments"
#define FRAG2_IPOPTIONS_STR "(spp_frag2) IP Options on Fragmented Packet"
#define FRAG2_OUTOFORDER_STR "(spp_frag2) Out of order fragments" 
#define FRAG2_OVERLAP_STR "(spp_frag2) Overlapping new fragment (probable fragroute)"
#define FRAG2_OVERSIZE_FRAG_STR "(spp_frag2) Oversized fragment, probable DoS"
#define FRAG2_TEARDROP_STR "(spp_frag2) Teardrop attack"
#define FRAG2_TTL_EVASION_STR "(spp_frag2) TTL Limit Exceeded (reassemble) detection"
#define FRAG2_EMERGENCY_STR "(spp_frag2) Shifting to Emergency Session Mode"
#define FRAG2_SUSPEND_STR "(spp_frag2) Shifting to Suspend Mode"



#define HTTP_DECODE_LARGE_METHOD_STR "(spp_http_decode) A large HTTP method was received"
#define HTTP_DECODE_MISSING_URI_STR "(spp_http_decode) HTTP request without URI"
#define HTTP_DECODE_DOUBLE_ENC_STR  "(spp_http_decode) Double Hex Encoding Received"
#define HTTP_DECODE_ILLEGAL_HEX_STR "(spp_http_decode) Illegal URL hex encoding"
#define HTTP_DECODE_OVERLONG_CHAR_STR "(spp_http_decode) Overlong Unicode character received"

#define STREAM4_MULTIPLE_ACKED_STR "(spp_stream4) Multiple Acked Packets (possible fragroute)"
#define STREAM4_DATA_ON_SYN_STR  "(spp_stream4) DATA ON SYN detection"
#define STREAM4_STEALTH_NMAP_FINGERPRINT_STR "(spp_stream4) NMAP FINGERPRINT (stateful) detection"
#define STREAM4_STEALTH_FULL_XMAS_STR "(spp_stream4) STEALTH ACTIVITY (Full XMAS scan) detection"
#define STREAM4_STEALTH_SAPU_STR "(spp_stream4) STEALTH ACTIVITY (SAPU scan) detection"
#define STREAM4_STEALTH_FIN_SCAN_STR "(spp_stream4) STEALTH ACTIVITY (FIN scan) detection"
#define STREAM4_STEALTH_SYN_FIN_SCAN_STR "(spp_stream4) STEALTH ACTIVITY (SYN FIN scan) detection"
#define STREAM4_STEALTH_NULL_SCAN_STR "(spp_stream4) STEALTH ACTIVITY (NULL scan) detection"
#define STREAM4_STEALTH_NMAP_XMAS_SCAN_STR "(spp_stream4) STEALTH ACTIVITY (XMAS scan) detection"
#define STREAM4_STEALTH_VECNA_SCAN_STR "(spp_stream4) STEALTH ACTIVITY (Vecna scan) detection"
#define STREAM4_STEALTH_ACTIVITY_STR "(spp_stream4) STEALTH ACTIVITY (unknown) detection"
#define STREAM4_EVASIVE_RST_STR "(spp_stream4) possible EVASIVE RST detection"
#define STREAM4_TTL_EVASION_STR "(spp_stream4) TTL LIMIT Exceeded"
#define STREAM4_EVASIVE_RETRANS_STR "(spp_stream4) Possible RETRANSMISSION detection"
#define STREAM4_WINDOW_VIOLATION_STR "(spp_stream4) WINDOW VIOLATION detection"
#define STREAM4_EVASIVE_RETRANS_DATA_STR \
 "(spp_stream4) TCP CHECKSUM CHANGED ON RETRANSMISSION (possible fragroute) detection"
#define STREAM4_FORWARD_OVERLAP_STR "(spp_stream4) FORWARD OVERLAP detection"
#define STREAM4_EVASIVE_RETRANS_DATASPLIT_STR \
"(spp_stream4) TCP TOO FAST RETRANSMISSION WITH DIFFERENT DATA SIZE (possible fragroute) detection"
#define STREAM4_EMERGENCY_STR "(spp_stream4) Shifting to Emergency Session Mode"
#define STREAM4_SUSPEND_STR "(spp_stream4) Shifting to Suspend Mode"


#define DECODE_NOT_IPV4_DGRAM_STR "(snort_decoder) WARNING: Not IPv4 datagram!"
#define DECODE_IPV4_INVALID_HEADER_LEN_STR "(snort_decoder) WARNING: hlen < IP_HEADER_LEN!"
#define DECODE_IPV4_DGRAM_LT_IPHDR_STR "(snort_decoder) WARNING: IP dgm len < IP Hdr len!"
#define DECODE_IPV4OPT_BADLEN_STR      "(snort_decoder): Ipv4 Options found with bad lengths"
#define DECODE_IPV4OPT_TRUNCATED_STR   "(snort_decoder): Truncated Ipv4 Options"

#define DECODE_TCP_DGRAM_LT_TCPHDR_STR "(snort_decoder) TCP packet len is smaller than 20 bytes!"
#define DECODE_TCP_INVALID_OFFSET_STR "(snort_decoder) WARNING: TCP Data Offset is less than 5!"
#define DECODE_TCP_LARGE_OFFSET_STR "(snort_decoder) WARNING: TCP Header length exceeds packet length!"

#define DECODE_TCPOPT_BADLEN_STR      "(snort_decoder): Tcp Options found with bad lengths"
#define DECODE_TCPOPT_TRUNCATED_STR   "(snort_decoder): Truncated Tcp Options"
#define DECODE_TCPOPT_TTCP_STR        "(snort_decoder): T/TCP Detected"
#define DECODE_TCPOPT_OBSOLETE_STR    "(snort_decoder): Obsolete TCP Options found"
#define DECODE_TCPOPT_EXPERIMENT_STR  "(snort_decoder): Experimental Tcp Options found"



#define DECODE_UDP_DGRAM_LT_UDPHDR_STR "(snort_decoder) WARNING: Truncated UDP Header!"
#define DECODE_UDP_DGRAM_INVALID_LENGTH_STR "(snort_decoder): Invalid UDP header, length field < 8"
#define DECODE_UDP_DGRAM_SHORT_PACKET_STR "(snort_decoder): Short UDP packet, length field > payload length"

#define DECODE_ICMP_DGRAM_LT_ICMPHDR_STR "(snort_decoder) WARNING: ICMP Header Truncated!"
#define DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR_STR "(snort_decoder) WARNING: ICMP Timestamp Header Truncated!"
#define DECODE_ICMP_DGRAM_LT_ADDRHDR_STR "(snort_decoder) WARNING: ICMP Address Header Truncated!"
#define DECODE_IPV4_DGRAM_UNKNOWN_STR "(snort_decoder) Unknown Datagram decoding problem!"
#define DECODE_ARP_TRUNCATED_STR "(snort_decoder) WARNING: Truncated ARP!"
#define DECODE_EAPOL_TRUNCATED_STR "(snort_decoder) WARNING: Truncated EAP Header!"
#define DECODE_EAPKEY_TRUNCATED_STR "(snort_decoder) WARNING: EAP Key Truncated!"
#define DECODE_EAP_TRUNCATED_STR "(snort_decoder) WARNING: EAP Header Truncated!"
#define DECODE_BAD_PPPOE_STR "(snort_decoder) WARNING: Bad PPPOE frame detected!"
#define DECODE_BAD_VLAN_STR "(snort_decoder) WARNING: Bad VLAN Frame!"
#define DECODE_BAD_VLAN_ETHLLC_STR "(snort_decoder) WARNING: Bad LLC header!"
#define DECODE_BAD_VLAN_OTHER_STR "(snort_decoder) WARNING: Bad Extra LLC Info!"
#define DECODE_BAD_80211_ETHLLC_STR "(snort_decoder) WARNING: Bad 802.11 LLC header!"
#define DECODE_BAD_80211_OTHER_STR "(snort_decoder) WARNING: Bad 802.11 Extra LLC Info!"

#define DECODE_BAD_TRH_STR "(snort_decoder) WARNING: Bad Token Ring Header!"
#define DECODE_BAD_TR_ETHLLC_STR "(snort_decoder) WARNING: Bad Token Ring ETHLLC Header!"
#define DECODE_BAD_TR_MR_LEN_STR "(snort_decoder) WARNING: Bad Token Ring MRLENHeader!"
#define DECODE_BAD_TRHMR_STR "(snort_decoder) WARNING: Bad Token Ring MR Header!"


#define SCAN2_PREFIX_STR "(spp_portscan2) Portscan detected from "

#define CONV_BAD_IP_PROTOCOL_STR "(spp_conversation) Bad IP protocol!"

#define RPC_FRAG_TRAFFIC_STR "(spp_rpc_decode) Fragmented RPC Records"
#define RPC_MULTIPLE_RECORD_STR "(spp_rpc_decode) Multiple RPC Records"
#define RPC_LARGE_FRAGSIZE_STR  "(spp_rpc_decode) Large RPC Record Fragment"
#define RPC_INCOMPLETE_SEGMENT_STR "(spp_rpc_decode) Incomplete RPC segment"

#define PSNG_TCP_PORTSCAN_STR "(portscan) TCP Portscan"
#define PSNG_TCP_DECOY_PORTSCAN_STR "(portscan) TCP Decoy Portscan"
#define PSNG_TCP_PORTSWEEP_STR "(portscan) TCP Portsweep"
#define PSNG_TCP_DISTRIBUTED_PORTSCAN_STR "(portscan) TCP Distributed Portscan"
#define PSNG_TCP_FILTERED_PORTSCAN_STR "(portscan) TCP Filtered Portscan"
#define PSNG_TCP_FILTERED_DECOY_PORTSCAN_STR "(portscan) TCP Filtered Decoy Portscan"
#define PSNG_TCP_FILTERED_DISTRIBUTED_PORTSCAN_STR "(portscan) TCP Filtered Distributed Portscan"
#define PSNG_TCP_PORTSWEEP_FILTERED_STR "(portscan) TCP Filtered Portsweep"

#define PSNG_IP_PORTSCAN_STR "(portscan) IP Protocol Scan"
#define PSNG_IP_DECOY_PORTSCAN_STR "(portscan) IP Decoy Protocol Scan"
#define PSNG_IP_PORTSWEEP_STR "(portscan) IP Protocol Sweep"
#define PSNG_IP_DISTRIBUTED_PORTSCAN_STR "(portscan) IP Distributed Protocol Scan"
#define PSNG_IP_FILTERED_PORTSCAN_STR "(portscan) IP Filtered Protocol Scan"
#define PSNG_IP_FILTERED_DECOY_PORTSCAN_STR "(portscan) IP Filtered Decoy Protocol Scan"
#define PSNG_IP_FILTERED_DISTRIBUTED_PORTSCAN_STR "(portscan) IP Filtered Distributed Protocol Scan"
#define PSNG_IP_PORTSWEEP_FILTERED_STR "(portscan) IP Filtered Protocol Sweep"

#define PSNG_UDP_PORTSCAN_STR "(portscan) UDP Portscan"
#define PSNG_UDP_DECOY_PORTSCAN_STR "(portscan) UDP Decoy Portscan"
#define PSNG_UDP_PORTSWEEP_STR "(portscan) UDP Portsweep"
#define PSNG_UDP_DISTRIBUTED_PORTSCAN_STR "(portscan) UDP Distributed Portscan"
#define PSNG_UDP_FILTERED_PORTSCAN_STR "(portscan) UDP Filtered Portscan"
#define PSNG_UDP_FILTERED_DECOY_PORTSCAN_STR "(portscan) UDP Filtered Decoy Portscan"
#define PSNG_UDP_FILTERED_DISTRIBUTED_PORTSCAN_STR "(portscan) UDP Filtered Distributed Portscan"
#define PSNG_UDP_PORTSWEEP_FILTERED_STR "(portscan) UDP Filtered Portsweep"

#define PSNG_ICMP_PORTSWEEP_STR "(portscan) ICMP Sweep"
#define PSNG_ICMP_PORTSWEEP_FILTERED_STR "(portscan) ICMP Filtered Sweep"

#define PSNG_OPEN_PORT_STR "(portscan) Open Port"

#endif /* __GENERATORS_H__ */
