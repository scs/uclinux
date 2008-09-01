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

/*  Parsing routines for individual tuples  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <byteswap.h>

#include "../src/cistpl.h"

#define IRQ_INFO2_VALID               0x10

static const u_char mantissa[] = {
    10, 12, 13, 15, 20, 25, 30, 35,
    40, 45, 50, 55, 60, 70, 80, 90
};

static const u_int exponent[] = {
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000
};

/* Convert an extended speed byte to a time in nanoseconds */
#define SPEED_CVT(v) \
    (mantissa[(((v)>>3)&15)-1] * exponent[(v)&7] / 10)
/* Convert a power byte to a current in 0.1 microamps */
#define POWER_CVT(v) \
    (mantissa[((v)>>3)&15] * exponent[(v)&7] / 10)
#define POWER_SCALE(v)          (exponent[(v)&7])

#if __BYTE_ORDER == __BIG_ENDIAN
# define le32_to_cpu(value) bswap_32(value)
# define le16_to_cpu(value) bswap_16(value)
#else
# define le32_to_cpu(value) (value)
# define le16_to_cpu(value) (value)
#endif

static int parse_device(tuple_t *tuple, cistpl_device_t *device)
{
	int i;
	u_char scale;
	u_char *p, *q;

	p = (u_char *) tuple->TupleData;
	q = p + tuple->TupleDataLen;

	device->ndev = 0;
	for (i = 0; i < CISTPL_MAX_DEVICES; i++) {

		if (*p == 0xff)
			break;

		device->dev[i].type = (*p >> 4);
		device->dev[i].wp = (*p & 0x08) ? 1 : 0;
		switch (*p & 0x07) {
		case 0: device->dev[i].speed = 0;   break;
		case 1: device->dev[i].speed = 250; break;
		case 2: device->dev[i].speed = 200; break;
		case 3: device->dev[i].speed = 150; break;
		case 4: device->dev[i].speed = 100; break;
		case 7:
			if (++p == q) return -EINVAL;
			device->dev[i].speed = SPEED_CVT(*p);
			while (*p & 0x80)
				if (++p == q) return -EINVAL;
			break;
		default:
			return -EINVAL;
		}

		if (++p == q)
			return -EINVAL;
		if (*p == 0xff)
			break;
		scale = *p & 7;
		if (scale == 7)
			return -EINVAL;
		device->dev[i].size = ((*p >> 3) + 1) * (512 << (scale*2));
		device->ndev++;
		if (++p == q)
			break;
	}

	return 0;
}

/*====================================================================*/

static int parse_checksum(tuple_t *tuple, cistpl_checksum_t *csum)
{
	u_char *p;
	if (tuple->TupleDataLen < 5)
		return -EINVAL;
	p = (u_char *)tuple->TupleData;
	csum->addr = tuple->CISOffset+(short)le16_to_cpu(*(u_short *)p)-2;
	csum->len = le16_to_cpu(*(u_short *)(p + 2));
	csum->sum = *(p+4);
	return 0;
}

/*====================================================================*/

static int parse_longlink(tuple_t *tuple, cistpl_longlink_t *link)
{
	if (tuple->TupleDataLen < 4)
		return -EINVAL;
	link->addr = le32_to_cpu(*(u_int *)tuple->TupleData);
	return 0;
}

/*====================================================================*/

static int parse_longlink_mfc(tuple_t *tuple,
			      cistpl_longlink_mfc_t *link)
{
	u_char *p;
	int i;

	p = (u_char *)tuple->TupleData;

	link->nfn = *p; p++;
	if (tuple->TupleDataLen <= link->nfn*5)
		return -EINVAL;
	for (i = 0; i < link->nfn; i++) {
		link->fn[i].space = *p; p++;
		link->fn[i].addr = le32_to_cpu(*(u_int *)p); p += 4;
	}
	return 0;
}

/*====================================================================*/

static int parse_strings(u_char *p, u_char *q, int max,
			 char *s, u_char *ofs, u_char *found)
{
	int i, j, ns;

	if (p == q)
		return -EINVAL;
	ns = 0; j = 0;
	for (i = 0; i < max; i++) {
		if (*p == 0xff)
			break;
		ofs[i] = j;
		ns++;
		for (;;) {
			s[j++] = (*p == 0xff) ? '\0' : *p;
			if ((*p == '\0') || (*p == 0xff))
				break;
			if (++p == q)
				return -EINVAL;
		}
		if ((*p == 0xff) || (++p == q))
			break;
	}
	if (found) {
		*found = ns;
		return 0;
	} else {
		return (ns == max) ? 0 : -EINVAL;
	}
}

/*====================================================================*/

static int parse_vers_1(tuple_t *tuple, cistpl_vers_1_t *vers_1)
{
	u_char *p, *q;

	p = (u_char *) tuple->TupleData;
	q = p + tuple->TupleDataLen;

	vers_1->major = *p; p++;
	vers_1->minor = *p; p++;
	if (p >= q)
		return -EINVAL;

	return parse_strings(p, q, CISTPL_VERS_1_MAX_PROD_STRINGS,
			     vers_1->str, vers_1->ofs, &vers_1->ns);
}

/*====================================================================*/

static int parse_altstr(tuple_t *tuple, cistpl_altstr_t *altstr)
{
	u_char *p, *q;

	p = (u_char *) tuple->TupleData;
	q = p + tuple->TupleDataLen;

	return parse_strings(p, q, CISTPL_MAX_ALTSTR_STRINGS,
			     altstr->str, altstr->ofs, &altstr->ns);
}

/*====================================================================*/

static int parse_jedec(tuple_t *tuple, cistpl_jedec_t *jedec)
{
	u_char *p, *q;
	int nid;

	p = (u_char *)tuple->TupleData;
	q = p + tuple->TupleDataLen;

	for (nid = 0; nid < CISTPL_MAX_DEVICES; nid++) {
		if (p > q-2)
			break;
		jedec->id[nid].mfr = p[0];
		jedec->id[nid].info = p[1];
		p += 2;
	}
	jedec->nid = nid;
	return 0;
}

/*====================================================================*/

static int parse_manfid(tuple_t *tuple, cistpl_manfid_t *m)
{
	u_short *p;
	if (tuple->TupleDataLen < 4)
		return -EINVAL;
	p = (u_short *)tuple->TupleData;
	m->manf = le16_to_cpu(p[0]);
	m->card = le16_to_cpu(p[1]);
	return 0;
}

/*====================================================================*/

static int parse_funcid(tuple_t *tuple, cistpl_funcid_t *f)
{
	u_char *p;
	if (tuple->TupleDataLen < 2)
		return -EINVAL;
	p = (u_char *)tuple->TupleData;
	f->func = p[0];
	f->sysinit = p[1];
	return 0;
}

/*====================================================================*/

static int parse_funce(tuple_t *tuple, cistpl_funce_t *f)
{
	u_char *p;
	int i;
	if (tuple->TupleDataLen < 1)
		return -EINVAL;
	p = (u_char *)tuple->TupleData;
	f->type = p[0];
	for (i = 1; i < tuple->TupleDataLen; i++)
		f->data[i-1] = p[i];
	return 0;
}

/*====================================================================*/

static int parse_config(tuple_t *tuple, cistpl_config_t *config)
{
	int rasz, rmsz, i;
	u_char *p;

	p = (u_char *)tuple->TupleData;
	rasz = *p & 0x03;
	rmsz = (*p & 0x3c) >> 2;
	if (tuple->TupleDataLen < rasz+rmsz+4)
		return -EINVAL;
	config->last_idx = *(++p);
	p++;
	config->base = 0;
	for (i = 0; i <= rasz; i++)
		config->base += p[i] << (8*i);
	p += rasz+1;
	for (i = 0; i < 4; i++)
		config->rmask[i] = 0;
	for (i = 0; i <= rmsz; i++)
		config->rmask[i>>2] += p[i] << (8*(i%4));
	config->subtuples = tuple->TupleDataLen - (rasz+rmsz+4);
	return 0;
}

/*======================================================================

    The following routines are all used to parse the nightmarish
    config table entries.
    
======================================================================*/

static u_char *parse_power(u_char *p, u_char *q,
			   cistpl_power_t *pwr)
{
	int i;
	u_int scale;

	if (p == q) return NULL;
	pwr->present = *p;
	pwr->flags = 0;
	p++;
	for (i = 0; i < 7; i++)
		if (pwr->present & (1<<i)) {
			if (p == q)
				return NULL;
			pwr->param[i] = POWER_CVT(*p);
			scale = POWER_SCALE(*p);
			while (*p & 0x80) {
				if (++p == q)
					return NULL;
				if ((*p & 0x7f) < 100)
					pwr->param[i] += (*p & 0x7f) * scale / 100;
				else if (*p == 0x7d)
					pwr->flags |= CISTPL_POWER_HIGHZ_OK;
				else if (*p == 0x7e)
					pwr->param[i] = 0;
				else if (*p == 0x7f)
					pwr->flags |= CISTPL_POWER_HIGHZ_REQ;
				else
					return NULL;
			}
			p++;
		}
	return p;
}

/*====================================================================*/

static u_char *parse_timing(u_char *p, u_char *q,
			    cistpl_timing_t *timing)
{
	u_char scale;

	if (p == q)
		return NULL;
	scale = *p;
	if ((scale & 3) != 3) {
		if (++p == q)
			return NULL;
		timing->wait = SPEED_CVT(*p);
		timing->waitscale = exponent[scale & 3];
	} else
		timing->wait = 0;
	scale >>= 2;
	if ((scale & 7) != 7) {
		if (++p == q)
			return NULL;
		timing->ready = SPEED_CVT(*p);
		timing->rdyscale = exponent[scale & 7];
	} else
		timing->ready = 0;
	scale >>= 3;
	if (scale != 7) {
		if (++p == q)
			return NULL;
		timing->reserved = SPEED_CVT(*p);
		timing->rsvscale = exponent[scale];
	} else
		timing->reserved = 0;
	p++;
	return p;
}

/*====================================================================*/

static u_char *parse_io(u_char *p, u_char *q, cistpl_io_t *io)
{
	int i, j, bsz, lsz;

	if (p == q) return NULL;
	io->flags = *p;

	if (!(*p & 0x80)) {
		io->nwin = 1;
		io->win[0].base = 0;
		io->win[0].len = (1 << (io->flags & CISTPL_IO_LINES_MASK));
		return p+1;
	}

	if (++p == q)
		return NULL;
	io->nwin = (*p & 0x0f) + 1;
	bsz = (*p & 0x30) >> 4;
	if (bsz == 3)
		bsz++;
	lsz = (*p & 0xc0) >> 6;
	if (lsz == 3)
		lsz++;
	p++;

	for (i = 0; i < io->nwin; i++) {
		io->win[i].base = 0;
		io->win[i].len = 1;
		for (j = 0; j < bsz; j++, p++) {
			if (p == q)
				return NULL;
			io->win[i].base += *p << (j*8);
		}
		for (j = 0; j < lsz; j++, p++) {
			if (p == q)
				return NULL;
			io->win[i].len += *p << (j*8);
		}
	}
	return p;
}

/*====================================================================*/

static u_char *parse_mem(u_char *p, u_char *q, cistpl_mem_t *mem)
{
	int i, j, asz, lsz, has_ha;
	u_int len, ca, ha;

	if (p == q)
		return NULL;

	mem->nwin = (*p & 0x07) + 1;
	lsz = (*p & 0x18) >> 3;
	asz = (*p & 0x60) >> 5;
	has_ha = (*p & 0x80);
	if (++p == q)
		return NULL;

	for (i = 0; i < mem->nwin; i++) {
		len = ca = ha = 0;
		for (j = 0; j < lsz; j++, p++) {
			if (p == q)
				return NULL;
			len += *p << (j*8);
		}
		for (j = 0; j < asz; j++, p++) {
			if (p == q)
				return NULL;
			ca += *p << (j*8);
		}
		if (has_ha)
			for (j = 0; j < asz; j++, p++) {
				if (p == q)
					return NULL;
				ha += *p << (j*8);
			}
		mem->win[i].len = len << 8;
		mem->win[i].card_addr = ca << 8;
		mem->win[i].host_addr = ha << 8;
	}
	return p;
}

/*====================================================================*/

static u_char *parse_irq(u_char *p, u_char *q, cistpl_irq_t *irq)
{
	if (p == q)
		return NULL;
	irq->IRQInfo1 = *p; p++;
	if (irq->IRQInfo1 & IRQ_INFO2_VALID) {
		if (p+2 > q)
			return NULL;
		irq->IRQInfo2 = (p[1]<<8) + p[0];
		p += 2;
	}
	return p;
}

/*====================================================================*/

static int parse_cftable_entry(tuple_t *tuple,
			       cistpl_cftable_entry_t *entry)
{
	u_char *p, *q, features;

	p = tuple->TupleData;
	q = p + tuple->TupleDataLen;
	entry->index = *p & 0x3f;
	entry->flags = 0;
	if (*p & 0x40)
		entry->flags |= CISTPL_CFTABLE_DEFAULT;
	if (*p & 0x80) {
		if (++p == q)
			return -EINVAL;
		if (*p & 0x10)
			entry->flags |= CISTPL_CFTABLE_BVDS;
		if (*p & 0x20)
			entry->flags |= CISTPL_CFTABLE_WP;
		if (*p & 0x40)
			entry->flags |= CISTPL_CFTABLE_RDYBSY;
		if (*p & 0x80)
			entry->flags |= CISTPL_CFTABLE_MWAIT;
		entry->interface = *p & 0x0f;
	} else
		entry->interface = 0;

	/* Process optional features */
	if (++p == q)
		return -EINVAL;
	features = *p; p++;

	/* Power options */
	if ((features & 3) > 0) {
		p = parse_power(p, q, &entry->vcc);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->vcc.present = 0;
	if ((features & 3) > 1) {
		p = parse_power(p, q, &entry->vpp1);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->vpp1.present = 0;
	if ((features & 3) > 2) {
		p = parse_power(p, q, &entry->vpp2);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->vpp2.present = 0;

	/* Timing options */
	if (features & 0x04) {
		p = parse_timing(p, q, &entry->timing);
		if (p == NULL)
			return -EINVAL;
	} else {
		entry->timing.wait = 0;
		entry->timing.ready = 0;
		entry->timing.reserved = 0;
	}

	/* I/O window options */
	if (features & 0x08) {
		p = parse_io(p, q, &entry->io);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->io.nwin = 0;

	/* Interrupt options */
	if (features & 0x10) {
		p = parse_irq(p, q, &entry->irq);
		if (p == NULL) return -EINVAL;
	} else
		entry->irq.IRQInfo1 = 0;

	switch (features & 0x60) {
	case 0x00:
		entry->mem.nwin = 0;
		break;
	case 0x20:
		entry->mem.nwin = 1;
		entry->mem.win[0].len = le16_to_cpu(*(u_short *)p) << 8;
		entry->mem.win[0].card_addr = 0;
		entry->mem.win[0].host_addr = 0;
		p += 2;
		if (p > q)
			return -EINVAL;
		break;
	case 0x40:
		entry->mem.nwin = 1;
		entry->mem.win[0].len = le16_to_cpu(*(u_short *)p) << 8;
		entry->mem.win[0].card_addr =
			le16_to_cpu(*(u_short *)(p+2)) << 8;
		entry->mem.win[0].host_addr = 0;
		p += 4;
		if (p > q)
			return -EINVAL;
		break;
	case 0x60:
		p = parse_mem(p, q, &entry->mem);
		if (p == NULL)
			return -EINVAL;
		break;
	}

	/* Misc features */
	if (features & 0x80) {
		if (p == q)
			return -EINVAL;
		entry->flags |= (*p << 8);
		while (*p & 0x80)
			if (++p == q)
				return -EINVAL;
		p++;
	}

	entry->subtuples = q-p;

	return 0;
}

/*====================================================================*/

static int parse_bar(tuple_t *tuple, cistpl_bar_t *bar)
{
	u_char *p;
	if (tuple->TupleDataLen < 6)
		return -EINVAL;
	p = (u_char *)tuple->TupleData;
	bar->attr = *p;
	p += 2;
	bar->size = le32_to_cpu(*(u_int *)p);
	return 0;
}

static int parse_config_cb(tuple_t *tuple, cistpl_config_t *config)
{
	u_char *p;

	p = (u_char *)tuple->TupleData;
	if ((*p != 3) || (tuple->TupleDataLen < 6))
		return -EINVAL;
	config->last_idx = *(++p);
	p++;
	config->base = le32_to_cpu(*(u_int *)p);
	config->subtuples = tuple->TupleDataLen - 6;
	return 0;
}

static int parse_cftable_entry_cb(tuple_t *tuple,
				  cistpl_cftable_entry_cb_t *entry)
{
	u_char *p, *q, features;

	p = tuple->TupleData;
	q = p + tuple->TupleDataLen;
	entry->index = *p & 0x3f;
	entry->flags = 0;
	if (*p & 0x40)
		entry->flags |= CISTPL_CFTABLE_DEFAULT;

	/* Process optional features */
	if (++p == q)
		return -EINVAL;
	features = *p; p++;

	/* Power options */
	if ((features & 3) > 0) {
		p = parse_power(p, q, &entry->vcc);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->vcc.present = 0;
	if ((features & 3) > 1) {
		p = parse_power(p, q, &entry->vpp1);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->vpp1.present = 0;
	if ((features & 3) > 2) {
		p = parse_power(p, q, &entry->vpp2);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->vpp2.present = 0;

	/* I/O window options */
	if (features & 0x08) {
		if (p == q)
			return -EINVAL;
		entry->io = *p; p++;
	} else
		entry->io = 0;

	/* Interrupt options */
	if (features & 0x10) {
		p = parse_irq(p, q, &entry->irq);
		if (p == NULL)
			return -EINVAL;
	} else
		entry->irq.IRQInfo1 = 0;

	if (features & 0x20) {
		if (p == q)
			return -EINVAL;
		entry->mem = *p; p++;
	} else
		entry->mem = 0;

	/* Misc features */
	if (features & 0x80) {
		if (p == q)
			return -EINVAL;
		entry->flags |= (*p << 8);
		if (*p & 0x80) {
			if (++p == q)
				return -EINVAL;
			entry->flags |= (*p << 16);
		}
		while (*p & 0x80)
			if (++p == q)
				return -EINVAL;
		p++;
	}

	entry->subtuples = q-p;

	return 0;
}

/*====================================================================*/

static int parse_device_geo(tuple_t *tuple, cistpl_device_geo_t *geo)
{
	u_char *p, *q;
	int n;

	p = (u_char *)tuple->TupleData;
	q = p + tuple->TupleDataLen;

	for (n = 0; n < CISTPL_MAX_DEVICES; n++) {
		if (p > q-6)
			break;
		geo->geo[n].buswidth = p[0];
		geo->geo[n].erase_block = 1 << (p[1]-1);
		geo->geo[n].read_block  = 1 << (p[2]-1);
		geo->geo[n].write_block = 1 << (p[3]-1);
		geo->geo[n].partition   = 1 << (p[4]-1);
		geo->geo[n].interleave  = 1 << (p[5]-1);
		p += 6;
	}
	geo->ngeo = n;
	return 0;
}

/*====================================================================*/

static int parse_vers_2(tuple_t *tuple, cistpl_vers_2_t *v2)
{
	u_char *p, *q;

	if (tuple->TupleDataLen < 10)
		return -EINVAL;

	p = tuple->TupleData;
	q = p + tuple->TupleDataLen;

	v2->vers = p[0];
	v2->comply = p[1];
	v2->dindex = le16_to_cpu(*(u_short *)(p+2));
	v2->vspec8 = p[6];
	v2->vspec9 = p[7];
	v2->nhdr = p[8];
	p += 9;
	return parse_strings(p, q, 2, v2->str, &v2->vendor, NULL);
}

/*====================================================================*/

static int parse_org(tuple_t *tuple, cistpl_org_t *org)
{
	u_char *p, *q;
	int i;

	p = tuple->TupleData;
	q = p + tuple->TupleDataLen;
	if (p == q)
		return -EINVAL;
	org->data_org = *p;
	if (++p == q)
		return -EINVAL;
	for (i = 0; i < 30; i++) {
		org->desc[i] = *p;
		if (*p == '\0') break;
		if (++p == q)
			return -EINVAL;
	}
	return 0;
}

/*====================================================================*/

static int parse_format(tuple_t *tuple, cistpl_format_t *fmt)
{
	u_char *p;

	if (tuple->TupleDataLen < 10)
		return -EINVAL;

	p = tuple->TupleData;

	fmt->type = p[0];
	fmt->edc = p[1];
	fmt->offset = le32_to_cpu(*(u_int *)(p+2));
	fmt->length = le32_to_cpu(*(u_int *)(p+6));

	return 0;
}

/*====================================================================*/

int pccard_parse_tuple(tuple_t *tuple, cisparse_t *parse)
{
	int ret = 0;

	if (tuple->TupleDataLen > tuple->TupleDataMax)
		return -EINVAL;
	switch (tuple->TupleCode) {
	case CISTPL_DEVICE:
	case CISTPL_DEVICE_A:
		ret = parse_device(tuple, &parse->device);
		break;
	case CISTPL_BAR:
		ret = parse_bar(tuple, &parse->bar);
		break;
	case CISTPL_CONFIG_CB:
		ret = parse_config_cb(tuple, &parse->config);
		break;
	case CISTPL_CFTABLE_ENTRY_CB:
		ret = parse_cftable_entry_cb(tuple, &parse->cftable_entry_cb);
		break;
	case CISTPL_CHECKSUM:
		ret = parse_checksum(tuple, &parse->checksum);
		break;
	case CISTPL_LONGLINK_A:
	case CISTPL_LONGLINK_C:
		ret = parse_longlink(tuple, &parse->longlink);
		break;
	case CISTPL_LONGLINK_MFC:
		ret = parse_longlink_mfc(tuple, &parse->longlink_mfc);
		break;
	case CISTPL_VERS_1:
		ret = parse_vers_1(tuple, &parse->version_1);
		break;
	case CISTPL_ALTSTR:
		ret = parse_altstr(tuple, &parse->altstr);
		break;
	case CISTPL_JEDEC_A:
	case CISTPL_JEDEC_C:
		ret = parse_jedec(tuple, &parse->jedec);
		break;
	case CISTPL_MANFID:
		ret = parse_manfid(tuple, &parse->manfid);
		break;
	case CISTPL_FUNCID:
		ret = parse_funcid(tuple, &parse->funcid);
		break;
	case CISTPL_FUNCE:
		ret = parse_funce(tuple, &parse->funce);
		break;
	case CISTPL_CONFIG:
		ret = parse_config(tuple, &parse->config);
		break;
	case CISTPL_CFTABLE_ENTRY:
		ret = parse_cftable_entry(tuple, &parse->cftable_entry);
		break;
	case CISTPL_DEVICE_GEO:
	case CISTPL_DEVICE_GEO_A:
		ret = parse_device_geo(tuple, &parse->device_geo);
		break;
	case CISTPL_VERS_2:
		ret = parse_vers_2(tuple, &parse->vers_2);
		break;
	case CISTPL_ORG:
		ret = parse_org(tuple, &parse->org);
		break;
	case CISTPL_FORMAT:
	case CISTPL_FORMAT_A:
		ret = parse_format(tuple, &parse->format);
		break;
	case CISTPL_NO_LINK:
	case CISTPL_LINKTARGET:
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}
