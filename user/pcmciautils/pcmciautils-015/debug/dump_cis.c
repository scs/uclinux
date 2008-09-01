/*
 * cistpl.c -- 16-bit PCMCIA Card Information Structure parser
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * (C) 1999		David A. Hinds
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../src/cistpl.h"

#define MAX_SOCKETS 8

static int verbose = 1;

static void print_tuple(tuple_t *tup)
{
	int i;
	printf("offset 0x%2.2x, tuple 0x%2.2x, link 0x%2.2x\n",
	       tup->CISOffset, tup->TupleCode,
	       tup->TupleLink);
	for (i = 0; i < tup->TupleDataLen; i++) {
		if (!(i % 16))
			printf("  ");
		printf("%2.2x ", (unsigned char) tup->TupleData[i]);
		if ((i % 16) == 15)
			printf("\n");
	}
	if ((i % 16) != 0)
		putchar('\n');
}

#define IRQ_INFO2_VALID       0x10
#define IRQ_MASK              0x0f
#define IRQ_LEVEL_ID          0x20
#define IRQ_PULSE_ID          0x40
#define IRQ_SHARE_ID          0x80

static void print_funcid(cistpl_funcid_t *fn)
{
	printf("funcid ");
	switch (fn->func) {
	case CISTPL_FUNCID_MULTI:
		printf("multi_function");
		break;
	case CISTPL_FUNCID_MEMORY:
		printf("memory_card");
		break;
	case CISTPL_FUNCID_SERIAL:
		printf("serial_port");
		break;
	case CISTPL_FUNCID_PARALLEL:
		printf("parallel_port");
		break;
	case CISTPL_FUNCID_FIXED:
		printf("fixed_disk");
		break;
	case CISTPL_FUNCID_VIDEO:
		printf("video_adapter");
		break;
	case CISTPL_FUNCID_NETWORK:
		printf("network_adapter");
		break;
	case CISTPL_FUNCID_AIMS:
		printf("aims_card");
		break;
	case CISTPL_FUNCID_SCSI:
		printf("scsi_adapter");
		break;
	default:
		printf("unknown");
		break;
	}
	if (fn->sysinit & CISTPL_SYSINIT_POST)
		printf(" [post]");
	if (fn->sysinit & CISTPL_SYSINIT_ROM)
		printf(" [rom]");
	putchar('\n');
}

/*====================================================================*/

static void print_size(u_int size)
{
	if (size < 1024)
		printf("%ub", size);
	else if (size < 1024*1024)
		printf("%ukb", size/1024);
	else
		printf("%umb", size/(1024*1024));
}

static void print_unit(u_int v, char *unit, char tag)
{
	unsigned int n;
	for (n = 0; (v % 1000) == 0; n++)
		v /= 1000;
	printf("%u", v);
	if (n < strlen(unit))
		putchar(unit[n]);
	putchar(tag);
}

static void print_time(u_int tm, u_long scale)
{
	print_unit(tm * scale, "num", 's');
}

static void print_volt(u_int vi)
{
	print_unit(vi * 10, "um", 'V');
}

static void print_current(u_int ii)
{
	print_unit(ii / 10, "um", 'A');
}

static void print_speed(u_int b)
{
	if (b < 1000)
		printf("%u bits/sec", b);
	else if (b < 1000000)
		printf("%u kb/sec", b/1000);
	else
		printf("%u mb/sec", b/1000000);
}

/*====================================================================*/

static const char *dtype[] = {
	"NULL", "ROM", "OTPROM", "EPROM", "EEPROM", "FLASH", "SRAM",
	"DRAM", "rsvd", "rsvd", "rsvd", "rsvd", "rsvd", "fn_specific",
	"extended", "rsvd"
};

static void print_device(cistpl_device_t *dev)
{
	int i;
	for (i = 0; i < dev->ndev; i++) {
		printf("  %s ", dtype[dev->dev[i].type]);
		printf("%uns, ", dev->dev[i].speed);
		print_size(dev->dev[i].size);
		putchar('\n');
	}
	if (dev->ndev == 0)
		printf("  no_info\n");
}


static void print_power(char *tag, cistpl_power_t *power)
{
	int i, n;
	for (i = n = 0; i < 8; i++)
		if (power->present & (1<<i))
			n++;
	i = 0;
	printf("  %s", tag);
	if (power->present & (1<<CISTPL_POWER_VNOM)) {
		printf(" Vnom "); i++;
		print_volt(power->param[CISTPL_POWER_VNOM]);
	}
	if (power->present & (1<<CISTPL_POWER_VMIN)) {
		printf(" Vmin "); i++;
		print_volt(power->param[CISTPL_POWER_VMIN]);
	}
	if (power->present & (1<<CISTPL_POWER_VMAX)) {
		printf(" Vmax "); i++;
		print_volt(power->param[CISTPL_POWER_VMAX]);
	}
	if (power->present & (1<<CISTPL_POWER_ISTATIC)) {
		printf(" Istatic "); i++;
		print_current(power->param[CISTPL_POWER_ISTATIC]);
	}
	if (power->present & (1<<CISTPL_POWER_IAVG)) {
		if (++i == 5)
			printf("\n");
		printf(" Iavg ");
		print_current(power->param[CISTPL_POWER_IAVG]);
	}
	if (power->present & (1<<CISTPL_POWER_IPEAK)) {
		if (++i == 5)
			printf("\n");
		printf(" Ipeak ");
		print_current(power->param[CISTPL_POWER_IPEAK]);
	}
	if (power->present & (1<<CISTPL_POWER_IDOWN)) {
		if (++i == 5)
			printf("\n");
		printf(" Idown ");
		print_current(power->param[CISTPL_POWER_IDOWN]);
	}
	if (power->flags & CISTPL_POWER_HIGHZ_OK) {
		if (++i == 5)
			printf("\n");
		printf(" [highz OK]");
	}
	if (power->flags & CISTPL_POWER_HIGHZ_REQ) {
		printf(" [highz]");
	}
	putchar('\n');
}

/*====================================================================*/

static void print_cftable_entry(cistpl_cftable_entry_t *entry)
{
	int i;

	printf("cftable_entry 0x%2.2x%s\n", entry->index,
	       (entry->flags & CISTPL_CFTABLE_DEFAULT) ? " [default]" : "");

	if (entry->flags & ~CISTPL_CFTABLE_DEFAULT) {
		if (entry->flags & CISTPL_CFTABLE_BVDS)
			printf(" [bvd]");
		if (entry->flags & CISTPL_CFTABLE_WP)
			printf(" [wp]");
		if (entry->flags & CISTPL_CFTABLE_RDYBSY)
			printf(" [rdybsy]");
		if (entry->flags & CISTPL_CFTABLE_MWAIT)
			printf(" [mwait]");
		if (entry->flags & CISTPL_CFTABLE_AUDIO)
			printf(" [audio]");
		if (entry->flags & CISTPL_CFTABLE_READONLY)
			printf(" [readonly]");
		if (entry->flags & CISTPL_CFTABLE_PWRDOWN)
			printf(" [pwrdown]");
		putchar('\n');
	}

	if (entry->vcc.present)
		print_power("Vcc", &entry->vcc);
	if (entry->vpp1.present)
		print_power("Vpp1", &entry->vpp1);
	if (entry->vpp2.present)
		print_power("Vpp2", &entry->vpp2);

	if ((entry->timing.wait != 0) || (entry->timing.ready != 0) ||
	    (entry->timing.reserved != 0)) {
		printf("  timing");
		if (entry->timing.wait != 0) {
			printf(" wait ");
			print_time(entry->timing.wait, entry->timing.waitscale);
		}
		if (entry->timing.ready != 0) {
			printf(" ready ");
			print_time(entry->timing.ready, entry->timing.rdyscale);
		}
		if (entry->timing.reserved != 0) {
			printf(" reserved ");
			print_time(entry->timing.reserved, entry->timing.rsvscale);
		}
		putchar('\n');
	}

	if (entry->io.nwin) {
		cistpl_io_t *io = &entry->io;
		printf("  io");
		for (i = 0; i < io->nwin; i++) {
			if (i)
				putchar(',');
			printf(" 0x%4.4x-0x%4.4x", io->win[i].base,
			       io->win[i].base+io->win[i].len-1);
		}
		printf(" [lines=%d]", io->flags & CISTPL_IO_LINES_MASK);
		if (io->flags & CISTPL_IO_8BIT)
			printf(" [8bit]");
		if (io->flags & CISTPL_IO_16BIT)
			printf(" [16bit]");
		if (io->flags & CISTPL_IO_RANGE)
			printf(" [range]");
		putchar('\n');
	}

	if (entry->irq.IRQInfo1) {
		printf("  irq ");
		if (entry->irq.IRQInfo1 & IRQ_INFO2_VALID)
			printf("mask 0x%04x", entry->irq.IRQInfo2);
		else
			printf("%u", entry->irq.IRQInfo1 & IRQ_MASK);
		if (entry->irq.IRQInfo1 & IRQ_LEVEL_ID)
			printf(" [level]");
		if (entry->irq.IRQInfo1 & IRQ_PULSE_ID)
			printf(" [pulse]");
		if (entry->irq.IRQInfo1 & IRQ_SHARE_ID)
			printf(" [shared]");
		putchar('\n');
	}

	if (entry->mem.nwin) {
		cistpl_mem_t *mem = &entry->mem;
		printf("  memory");
		for (i = 0; i < mem->nwin; i++) {
			if (i)
				putchar(',');
			printf(" 0x%4.4x-0x%4.4x @ 0x%4.4x",
			       mem->win[i].card_addr,
			       mem->win[i].card_addr + mem->win[i].len-1,
			       mem->win[i].host_addr);
		}
		putchar('\n');
	}

	if (verbose && entry->subtuples)
		printf("  %d bytes in subtuples\n", entry->subtuples);
}

/*====================================================================*/

static void print_cftable_entry_cb(cistpl_cftable_entry_cb_t *entry)
{
	int i;

	printf("cftable_entry_cb 0x%2.2x%s\n", entry->index,
	       (entry->flags & CISTPL_CFTABLE_DEFAULT) ? " [default]" : "");

	if (entry->flags & ~CISTPL_CFTABLE_DEFAULT) {
		printf(" ");
		if (entry->flags & CISTPL_CFTABLE_MASTER)
			printf(" [master]");
		if (entry->flags & CISTPL_CFTABLE_INVALIDATE)
			printf(" [invalidate]");
		if (entry->flags & CISTPL_CFTABLE_VGA_PALETTE)
			printf(" [vga palette]");
		if (entry->flags & CISTPL_CFTABLE_PARITY)
			printf(" [parity]");
		if (entry->flags & CISTPL_CFTABLE_WAIT)
			printf(" [wait]");
		if (entry->flags & CISTPL_CFTABLE_SERR)
			printf(" [serr]");
		if (entry->flags & CISTPL_CFTABLE_FAST_BACK)
			printf(" [fast back]");
		if (entry->flags & CISTPL_CFTABLE_BINARY_AUDIO)
			printf(" [binary audio]");
		if (entry->flags & CISTPL_CFTABLE_PWM_AUDIO)
			printf(" [pwm audio]");
		putchar('\n');
	}

	if (entry->vcc.present)
		print_power("Vcc", &entry->vcc);
	if (entry->vpp1.present)
		print_power("Vpp1", &entry->vpp1);
	if (entry->vpp2.present)
		print_power("Vpp2", &entry->vpp2);

	if (entry->io) {
		printf("  io_base");
		for (i = 0; i < 8; i++)
			if (entry->io & (1<<i)) printf(" %d", i);
		putchar('\n');
	}

	if (entry->irq.IRQInfo1) {
		printf("  irq ");
		if (entry->irq.IRQInfo1 & IRQ_INFO2_VALID)
			printf("mask 0x%4.4x", entry->irq.IRQInfo2);
		else
			printf("%u", entry->irq.IRQInfo1 & IRQ_MASK);
		if (entry->irq.IRQInfo1 & IRQ_LEVEL_ID)
			printf(" [level]");
		if (entry->irq.IRQInfo1 & IRQ_PULSE_ID)
			printf(" [pulse]");
		if (entry->irq.IRQInfo1 & IRQ_SHARE_ID)
			printf(" [shared]");
		putchar('\n');
	}

	if (entry->mem) {
		printf("  mem_base");
		for (i = 0; i < 8; i++)
			if (entry->mem & (1<<i))
				printf(" %d", i);
		putchar('\n');
	}

	if (verbose && entry->subtuples)
		printf("  %d bytes in subtuples\n", entry->subtuples);
}

/*====================================================================*/

static void print_jedec(cistpl_jedec_t *j)
{
	int i;
	for (i = 0; i < j->nid; i++) {
		if (i != 0)
			putchar(',');
		printf(" 0x%02x 0x%02x", j->id[i].mfr, j->id[i].info);
	}
	putchar('\n');
}

/*====================================================================*/

static void print_device_geo(cistpl_device_geo_t *geo)
{
	int i;
	for (i = 0; i < geo->ngeo; i++) {
		printf("  width %d erase 0x%x read 0x%x write 0x%x "
		       "partition 0x%x interleave 0x%x\n",
		       geo->geo[i].buswidth, geo->geo[i].erase_block,
		       geo->geo[i].read_block, geo->geo[i].write_block,
		       geo->geo[i].partition, geo->geo[i].interleave);
	}
}

/*====================================================================*/

static void print_org(cistpl_org_t *org)
{
	printf("data_org ");
	switch (org->data_org) {
	case CISTPL_ORG_FS:
		printf("[filesystem]");
		break;
	case CISTPL_ORG_APPSPEC:
		printf("[app_specific]");
		break;
	case CISTPL_ORG_XIP:
		printf("[code]"); break;
	default:
		if (org->data_org < 0x80)
			printf("[reserved]");
		else
			printf("[vendor_specific]");
	}
	printf(", \"%s\"\n", org->desc);
}


static char *data_mod[] = {
	"Bell103", "V.21", "V.23", "V.22", "Bell212A", "V.22bis",
	"V.26", "V.26bis", "V.27bis", "V.29", "V.32", "V.32bis",
	"V.34", "rfu", "rfu", "rfu"
};
static char *fax_mod[] = {
	"V.21-C2", "V.27ter", "V.29", "V.17", "V.33", "rfu", "rfu", "rfu"
};
static char *fax_features[] = {
	"T.3", "T.4", "T.6", "error", "voice", "poll", "file", "passwd"
};
static char *cmd_protocol[] = {
	"AT1", "AT2", "AT3", "MNP_AT", "V.25bis", "V.25A", "DMCL"
};
static char *uart[] = {
	"8250", "16450", "16550", "8251", "8530", "85230"
};
static char *parity[] = { "space", "mark", "odd", "even" };
static char *stop[] = { "1", "1.5", "2" };
static char *flow[] = {
	"XON/XOFF xmit", "XON/XOFF rcv", "hw xmit", "hw rcv", "transparent"
};
static void print_serial(cistpl_funce_t *funce)
{
	cistpl_serial_t *s;
	cistpl_data_serv_t *ds;
	cistpl_fax_serv_t *fs;
	cistpl_modem_cap_t *cp;
	int i, j;

	switch (funce->type & 0x0f) {
	case CISTPL_FUNCE_SERIAL_IF:
	case CISTPL_FUNCE_SERIAL_IF_DATA:
	case CISTPL_FUNCE_SERIAL_IF_FAX:
	case CISTPL_FUNCE_SERIAL_IF_VOICE:
		s = (cistpl_serial_t *)(funce->data);
		printf("serial_interface");
		if ((funce->type & 0x0f) == CISTPL_FUNCE_SERIAL_IF_DATA)
			printf("_data");
		else if ((funce->type & 0x0f) == CISTPL_FUNCE_SERIAL_IF_FAX)
			printf("_fax");
		else if ((funce->type & 0x0f) == CISTPL_FUNCE_SERIAL_IF_VOICE)
			printf("_voice");
		printf("\n  uart %s",
		       (s->uart_type < 6) ? uart[s->uart_type] : "reserved");
		if (s->uart_cap_0) {
			printf(" [");
			for (i = 0; i < 4; i++)
				if (s->uart_cap_0 & (1<<i))
					printf("%s%s", parity[i],
					       (s->uart_cap_0 >= (2<<i)) ? "/" : "]");
		}
		if (s->uart_cap_1) {
			int m = s->uart_cap_1 & 0x0f;
			int n = s->uart_cap_1 >> 4;
			printf(" [");
			for (i = 0; i < 4; i++)
				if (m & (1<<i))
					printf("%d%s", i+5, (m >= (2<<i)) ? "/" : "");
			printf("] [");
			for (i = 0; i < 3; i++)
				if (n & (1<<i))
					printf("%s%s", stop[i], (n >= (2<<i)) ? "/" : "]");
		}
		printf("\n");
		break;
	case CISTPL_FUNCE_SERIAL_CAP:
	case CISTPL_FUNCE_SERIAL_CAP_DATA:
	case CISTPL_FUNCE_SERIAL_CAP_FAX:
	case CISTPL_FUNCE_SERIAL_CAP_VOICE:
		cp = (cistpl_modem_cap_t *)(funce->data);
		printf("serial_modem_cap");
		if ((funce->type & 0x0f) == CISTPL_FUNCE_SERIAL_CAP_DATA)
			printf("_data");
		else if ((funce->type & 0x0f) == CISTPL_FUNCE_SERIAL_CAP_FAX)
			printf("_fax");
		else if ((funce->type & 0x0f) == CISTPL_FUNCE_SERIAL_CAP_VOICE)
			printf("_voice");
		if (cp->flow) {
			printf("\n  flow");
			for (i = 0; i < 5; i++)
				if (cp->flow & (1<<i))
					printf(" [%s]", flow[i]);
		}
		printf("\n  cmd_buf %d rcv_buf %d xmit_buf %d\n",
		       4*(cp->cmd_buf+1),
		       cp->rcv_buf_0+(cp->rcv_buf_1<<8)+(cp->rcv_buf_2<<16),
		       cp->xmit_buf_0+(cp->xmit_buf_1<<8)+(cp->xmit_buf_2<<16));
		break;
	case CISTPL_FUNCE_SERIAL_SERV_DATA:
		ds = (cistpl_data_serv_t *)(funce->data);
		printf("serial_data_services\n");
		printf("  data_rate %d\n",
		       75*((ds->max_data_0<<8) + ds->max_data_1));
		printf("  modulation");
		for (i = j = 0; i < 16; i++)
			if (((ds->modulation_1<<8) + ds->modulation_0) & (1<<i)) {
				if (++j % 6 == 0)
					printf("\n   ");
				printf(" [%s]", data_mod[i]);
			}
		printf("\n");
		if (ds->error_control) {
			printf("  error_control");
			if (ds->error_control & CISTPL_SERIAL_ERR_MNP2_4)
				printf(" [MNP2-4]");
			if (ds->error_control & CISTPL_SERIAL_ERR_V42_LAPM)
				printf(" [V.42/LAPM]");
			printf("\n");
	}
		if (ds->compression) {
			printf("  compression");
			if (ds->compression & CISTPL_SERIAL_CMPR_V42BIS)
				printf(" [V.42bis]");
			if (ds->compression & CISTPL_SERIAL_CMPR_MNP5)
				printf(" [MNP5]");
			printf("\n");
		}
		if (ds->cmd_protocol) {
			printf("  cmd_protocol");
			for (i = 0; i < 7; i++)
				if (ds->cmd_protocol & (1<<i))
					printf(" [%s]", cmd_protocol[i]);
			printf("\n");
		}
		break;

	case CISTPL_FUNCE_SERIAL_SERV_FAX:
		fs = (cistpl_fax_serv_t *)(funce->data);
		printf("serial_fax_services [class=%d]\n",
		       funce->type>>4);
		printf("  data_rate %d\n",
		       75*((fs->max_data_0<<8) + fs->max_data_1));
		printf("  modulation");
		for (i = 0; i < 8; i++)
			if (fs->modulation & (1<<i))
				printf(" [%s]", fax_mod[i]);
		printf("\n");
		if (fs->features_0) {
			printf("  features");
			for (i = 0; i < 8; i++)
				if (fs->features_0 & (1<<i))
					printf(" [%s]", fax_features[i]);
			printf("\n");
		}
		break;
	}
}

/*====================================================================*/

static void print_fixed(cistpl_funce_t *funce)
{
	cistpl_ide_interface_t *i;
	cistpl_ide_feature_t *f;

	switch (funce->type) {
	case CISTPL_FUNCE_IDE_IFACE:
		i = (cistpl_ide_interface_t *)(funce->data);
		printf("disk_interface ");
		if (i->interface == CISTPL_IDE_INTERFACE)
			printf("[ide]\n");
		else
			printf("[undefined]\n");
		break;
	case CISTPL_FUNCE_IDE_MASTER:
	case CISTPL_FUNCE_IDE_SLAVE:
		f = (cistpl_ide_feature_t *)(funce->data);
		printf("disk_features");
		if (f->feature1 & CISTPL_IDE_SILICON)
			printf(" [silicon]");
		else
			printf(" [rotating]");
		if (f->feature1 & CISTPL_IDE_UNIQUE)
			printf(" [unique]");
		if (f->feature1 & CISTPL_IDE_DUAL)
			printf(" [dual]");
		else
			printf(" [single]");
		if (f->feature1 && f->feature2)
			printf("\n ");
		if (f->feature2 & CISTPL_IDE_HAS_SLEEP)
			printf(" [sleep]");
		if (f->feature2 & CISTPL_IDE_HAS_STANDBY)
			printf(" [standby]");
		if (f->feature2 & CISTPL_IDE_HAS_IDLE)
			printf(" [idle]");
		if (f->feature2 & CISTPL_IDE_LOW_POWER)
			printf(" [low power]");
		if (f->feature2 & CISTPL_IDE_REG_INHIBIT)
			printf(" [reg inhibit]");
		if (f->feature2 & CISTPL_IDE_HAS_INDEX)
			printf(" [index]");
		if (f->feature2 & CISTPL_IDE_IOIS16)
			printf(" [iois16]");
		putchar('\n');
		break;
	}
}

static const char *tech[] = {
	"undefined", "ARCnet", "ethernet", "token_ring", "localtalk",
	"FDDI/CDDI", "ATM", "wireless"
};

static const char *media[] = {
	"undefined", "unshielded_twisted_pair", "shielded_twisted_pair",
	"thin_coax", "thick_coax", "fiber", "900_MHz", "2.4_GHz",
	"5.4_GHz", "diffuse_infrared", "point_to_point_infrared"
};

static void print_network(cistpl_funce_t *funce)
{
	cistpl_lan_tech_t *t;
	cistpl_lan_speed_t *s;
	cistpl_lan_media_t *m;
	cistpl_lan_node_id_t *n;
	cistpl_lan_connector_t *c;
	int i;

	switch (funce->type) {
	case CISTPL_FUNCE_LAN_TECH:
		t = (cistpl_lan_tech_t *)(funce->data);
		printf("lan_technology %s\n", tech[t->tech]);
		break;
	case CISTPL_FUNCE_LAN_SPEED:
		s = (cistpl_lan_speed_t *)(funce->data);
		printf("lan_speed ");
		print_speed(s->speed);
		putchar('\n');
		break;
	case CISTPL_FUNCE_LAN_MEDIA:
		m = (cistpl_lan_media_t *)(funce->data);
		printf("lan_media %s\n", media[m->media]);
		break;
	case CISTPL_FUNCE_LAN_NODE_ID:
		n = (cistpl_lan_node_id_t *)(funce->data);
		printf("lan_node_id");
		for (i = 0; i < n->nb; i++)
			printf(" %02x", n->id[i]);
		putchar('\n');
		break;
	case CISTPL_FUNCE_LAN_CONNECTOR:
		c = (cistpl_lan_connector_t *)(funce->data);
		printf("lan_connector ");
		if (c->code == 0)
			printf("Open connector standard\n");
		else
			printf("Closed connector standard\n");
		break;
	}
}


static void print_vers_1(cistpl_vers_1_t *v1)
{
	int i, n;
	char s[32];
	sprintf(s, "vers_1 %d.%d", v1->major, v1->minor);
	printf("%s", s);
	n = strlen(s);
	for (i = 0; i < v1->ns; i++) {
		if (n + strlen(v1->str + v1->ofs[i]) + 4 > 72) {
			n += 2;
			printf(",\n  ");
		} else {
			printf(", ");
			n += 2;
		}
		printf("\"%s\"", v1->str + v1->ofs[i]);
		n += strlen(v1->str + v1->ofs[i]) + 2;
	}
	putchar('\n');
}


static void print_vers_2(cistpl_vers_2_t *v2)
{
	printf("version 0x%2.2x, compliance 0x%2.2x, dindex 0x%4.4x\n",
	       v2->vers, v2->comply, v2->dindex);
	printf("  vspec8 0x%2.2x, vspec9 0x%2.2x, nhdr %d\n",
	       v2->vspec8, v2->vspec9, v2->nhdr);
	printf("  vendor \"%s\"\n", v2->str+v2->vendor);
	printf("  info \"%s\"\n", v2->str+v2->info);
}


static void print_format(cistpl_format_t *fmt)
{
	if (fmt->type == CISTPL_FORMAT_DISK)
		printf("  [disk]");
	else if (fmt->type == CISTPL_FORMAT_MEM)
		printf("  [memory]");
	else
		printf("  [type 0x%02x]\n", fmt->type);
	if (fmt->edc == CISTPL_EDC_NONE)
		printf(" [no edc]");
	else if (fmt->edc == CISTPL_EDC_CKSUM)
		printf(" [cksum]");
	else if (fmt->edc == CISTPL_EDC_CRC)
		printf(" [crc]");
	else if (fmt->edc == CISTPL_EDC_PCC)
		printf(" [pcc]");
	else
		printf(" [edc 0x%02x]", fmt->edc);
	printf(" offset 0x%04x length ", fmt->offset);
	print_size(fmt->length);
	putchar('\n');
}


static void print_config(int code, cistpl_config_t *cfg)
{
    printf("config%s base 0x%4.4x",
	   (code == CISTPL_CONFIG_CB) ? "_cb" : "",
	   cfg->base);
    if (code == CISTPL_CONFIG)
	    printf(" mask 0x%4.4x", cfg->rmask[0]);
    printf(" last_index 0x%2.2x\n", cfg->last_idx);
    if (verbose && cfg->subtuples)
	    printf("  %d bytes in subtuples\n", cfg->subtuples);
}


static int nfn = 0, cur = 0;

static void print_parse(tuple_t *tuple, cisparse_t *parse)
{
	static int func = 0;
	int i;

	switch (tuple->TupleCode) {
	case CISTPL_DEVICE:
	case CISTPL_DEVICE_A:
		if (tuple->TupleCode == CISTPL_DEVICE)
			printf("dev_info\n");
		else
			printf("attr_dev_info\n");
		print_device(&parse->device);
		break;
	case CISTPL_CHECKSUM:
		printf("checksum 0x%04x-0x%04x = 0x%02x\n",
		       parse->checksum.addr,
		       parse->checksum.addr+parse->checksum.len-1,
		       parse->checksum.sum);
		break;
	case CISTPL_LONGLINK_A:
		if (verbose)
			printf("long_link_attr 0x%04x\n",
			       parse->longlink.addr);
		break;
	case CISTPL_LONGLINK_C:
		if (verbose)
			printf("long_link 0x%04x\n",
			       parse->longlink.addr);
		break;
	case CISTPL_LONGLINK_MFC:
		if (verbose) {
			printf("mfc_long_link\n");
			for (i = 0; i < parse->longlink_mfc.nfn; i++)
				printf(" function %d: %s 0x%04x\n", i,
				       parse->longlink_mfc.fn[i].space ? "common" : "attr",
				       parse->longlink_mfc.fn[i].addr);
		} else {
			printf("mfc {\n");
			nfn = parse->longlink_mfc.nfn;
			cur = 0;
		}
		break;
	case CISTPL_NO_LINK:
		if (verbose)
			printf("no_long_link\n");
		break;
	case CISTPL_INDIRECT:
		if (verbose)
			printf("indirect_access\n");
		break;
	case CISTPL_LINKTARGET:
		if (verbose)
			printf("link_target\n");
		else {
			if (cur++)
				printf("}, {\n");
		}
		break;
	case CISTPL_VERS_1:
		print_vers_1(&parse->version_1);
		break;
	case CISTPL_ALTSTR:
		break;
	case CISTPL_JEDEC_A:
	case CISTPL_JEDEC_C:
		if (tuple->TupleCode == CISTPL_JEDEC_C)
			printf("common_jedec");
		else
			printf("attr_jedec");
		print_jedec(&parse->jedec);
		break;
	case CISTPL_DEVICE_GEO:
	case CISTPL_DEVICE_GEO_A:
		if (tuple->TupleCode == CISTPL_DEVICE_GEO)
			printf("common_geometry\n");
		else
			printf("attr_geometry\n");
		print_device_geo(&parse->device_geo);
		break;
	case CISTPL_MANFID:
		printf("manfid 0x%4.4x, 0x%4.4x\n",
		       parse->manfid.manf, parse->manfid.card);
		break;
	case CISTPL_FUNCID:
		print_funcid(&parse->funcid);
		func = parse->funcid.func;
		break;
	case CISTPL_FUNCE:
		switch (func) {
		case CISTPL_FUNCID_SERIAL:
			print_serial(&parse->funce);
			break;
		case CISTPL_FUNCID_FIXED:
			print_fixed(&parse->funce);
			break;
		case CISTPL_FUNCID_NETWORK:
			print_network(&parse->funce);
			break;
		}
		break;
	case CISTPL_BAR:
		printf("BAR %d size ",
		       parse->bar.attr & CISTPL_BAR_SPACE);
		print_size(parse->bar.size);
		if (parse->bar.attr & CISTPL_BAR_SPACE_IO)
			printf(" [io]");
		else
			printf(" [mem]");
		if (parse->bar.attr & CISTPL_BAR_PREFETCH)
			printf(" [prefetch]");
		if (parse->bar.attr & CISTPL_BAR_CACHEABLE)
			printf(" [cacheable]");
		if (parse->bar.attr & CISTPL_BAR_1MEG_MAP)
			printf(" [<1mb]");
		putchar('\n');
		break;
	case CISTPL_CONFIG:
	case CISTPL_CONFIG_CB:
		print_config(tuple->TupleCode, &parse->config);
		break;
	case CISTPL_CFTABLE_ENTRY:
		print_cftable_entry(&parse->cftable_entry);
		break;
	case CISTPL_CFTABLE_ENTRY_CB:
		print_cftable_entry_cb(&parse->cftable_entry_cb);
		break;
	case CISTPL_VERS_2:
		print_vers_2(&parse->vers_2);
		break;
	case CISTPL_ORG:
		print_org(&parse->org);
		break;
	case CISTPL_FORMAT:
	case CISTPL_FORMAT_A:
		if (tuple->TupleCode == CISTPL_FORMAT)
			printf("common_format\n");
		else
			printf("attr_format\n");
		print_format(&parse->format);
	}
}


static int parse_cis_one_socket(unsigned int socket_no, FILE *fd)
{
	int ret = 0;
	tuple_t tuple;
	unsigned char buf[256];
	cisparse_t parse;

	memset(&tuple, 0, sizeof(tuple_t));

        ret = read_out_cis(socket_no, fd);
        if (ret)
                return (ret);

	printf("Socket %u\n", socket_no);

	tuple.Attributes = TUPLE_RETURN_LINK | TUPLE_RETURN_COMMON;
        tuple.DesiredTuple = RETURN_FIRST_TUPLE;

	ret = pcmcia_get_first_tuple(BIND_FN_ALL, &tuple);
	if (ret)
		return (ret);

	while(tuple.TupleCode != CISTPL_END) {
		tuple.TupleData = buf;
		tuple.TupleOffset = 0;
		tuple.TupleDataMax = 255;

		pcmcia_get_tuple_data(&tuple);

		if (verbose)
			print_tuple(&tuple);

		ret = pccard_parse_tuple(&tuple, &parse);
		if (ret)
			printf("invalid tuple\n");
		else {
			print_parse(&tuple, &parse);
			printf("\n");
		}

		ret = pcmcia_get_next_tuple(BIND_FN_ALL, &tuple);
		if (ret)
			break;
	}

	return (ret);
}

int main(int argc, char** argv)
{
	unsigned int socket_no = MAX_SOCKETS;
	int ret = -ENODEV, i;
	FILE *fd = NULL;

	if (argc == 2) {
		ret = sscanf(argv[1], "%u", &socket_no);
		if (ret != 1)
			socket_no = MAX_SOCKETS;
	} else if (argc == 3) {
		if (!strncmp("-f", argv[1], 2)) {
			if (!strncmp("-", argv[2], 1))
				fd = stdin;
			else
				fd = fopen(argv[2], "r");
			if (!fd)
				return -EINVAL;
			return parse_cis_one_socket(MAX_SOCKETS + 1, fd);
		}
	}

	if ((socket_no != MAX_SOCKETS) || fd) {
		return parse_cis_one_socket(socket_no, fd);
	} else {
		for (i=0; i<MAX_SOCKETS; i++)
			if (!parse_cis_one_socket(i, fd))
				ret = 0;
	}

	return (ret);;
}
