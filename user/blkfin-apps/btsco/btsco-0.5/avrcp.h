
 /*
stream received on pressing 'play'
 00 tlabel, ptype, cr, ipid
 11 pid1
 0e pid0
 00 ctype control
 48 panel subunit/unit 0
 7c passthrough opcode
 44 play
 00 data length is 0

reply should be:
 02 tlabel, ptype, cr reply, ipid
 11 pid1
 0e pid0
 09 control accepted
 48 panel subunit/unit 0
 7c passthrough opcode
 44 play
 00 data length is 0

play-> 44, c4
next-> 4b, cb
prev-> 4c, cc

*/

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction_label:4;
	uint16_t pid;
} __attribute__ ((packed));

struct avc_frame {
	struct avctp_header header;
	uint8_t ctype:4;
	uint8_t zeroes:4;
	uint8_t subunit_id:3;
	uint8_t subunit_type:5;
	uint8_t opcode;
	uint8_t operand0;
	uint8_t operand1;
} __attribute__ ((packed));

// avrcp p. 49 for operand examples unit/subunit/passthrough

// Message types
#define AVCTP_COMMAND_FRAME 0
#define AVCTP_RESPONSE_FRAME 1

// Packet types
#define PACKET_TYPE_SINGLE 0
#define PACKET_TYPE_START 1
#define PACKET_TYPE_CONTINUE 2
#define PACKET_TYPE_END 3

// AVRCP profile pid
#define AVRCP_PID 0x0e11

// we define the psm
#define L2CAP_PSM_AVCTP            0x0017

// ctype entries
#define CMD_PASSTHROUGH 0
#define CMD_ACCEPTED 9

// opcodes
#define OP_PASS 0x7c

// subunits of interest
#define SUBUNIT_PANEL 9

// operands in passthrough commands
#define VOLUP_OP 0x41
#define VOLDOWN_OP 0x42
#define MUTE_OP 0x43

#define PLAY_OP 0x44
#define STOP_OP 0x45
#define PAUSE_OP 0x46
#define NEXT_OP 0x4b
#define PREV_OP 0x4c
