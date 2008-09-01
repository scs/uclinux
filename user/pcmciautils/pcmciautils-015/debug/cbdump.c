/*
 * cbdump.c - dump cardbus bridge registers
 *
 * Copyright (C) 2003 Russell King.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Build instructions:
 *
 *  gcc -O2 -o cbdump cbdump.c -lpci
 */

#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <pci/pci.h>

struct dump_data {
	const char *name;
	unsigned char offset;
	unsigned char size;
};

static void
__dump_memory(void *mem, const struct dump_data *d, int num)
{
	int i;

	for (i = 0; i < num; i++, d++) {
		u32 val = 0xa5a5a5a5;
		void *p = (void *) ((unsigned long) mem + d->offset);

		switch (d->size) {
		case 1: val = *(u8 *)p;  break;
		case 2: val = *(u16 *)p; break;
		case 4: val = *(u32 *)p; break;
		}

		printf("  %-31s[%02x] : 0x%0*x\n", d->name,
			d->offset, d->size * 2, val);
	}
}

#define dump_memory(m,d) \
	__dump_memory(m,d,sizeof(d)/sizeof(struct dump_data))

static void
__dump_config(struct pci_dev *dev, const struct dump_data *d, int num)
{
	int i;

	for (i = 0; i < num; i++, d++) {
		u32 val = 0xa5a5a5a5;

		switch (d->size) {
		case 1:
			val = pci_read_byte(dev, d->offset);
			break;
		case 2:
			val = pci_read_word(dev, d->offset);
			break;
		case 4:
			val = pci_read_long(dev, d->offset);
			break;
		}

		printf("  %-31s[%02x] : 0x%0*x\n", d->name,
			d->offset, d->size * 2, val);
	}
}

#define dump_config(m,d) \
	__dump_config(m,d,sizeof(d)/sizeof(struct dump_data))

static const struct dump_data cb_data[] = {
	{ "CB_SOCKET_EVENT",   0x00, 4 },
	{ "CB_SOCKET_MASK",    0x04, 4 },
	{ "CB_SOCKET_STATE",   0x08, 4 },
	{ "CB_SOCKET_FORCE",   0x0c, 4 },
	{ "CB_SOCKET_CONTROL", 0x10, 4 },
	{ "CB_SOCKET_POWER",   0x20, 4 },
};

static void dump_cb(void *mem)
{
	printf("  -- cardbus registers\n");
	dump_memory(mem, cb_data);
}

static const struct dump_data exca_data[] = {
	{ "I365_IDENT",		0x00, 1 },
	{ "I365_STATUS",	0x01, 1 },
	{ "I365_POWER",		0x02, 1 },
	{ "I365_INTCTL",	0x03, 1 },
	{ "I365_CSC",		0x04, 1 },
	{ "I365_CSCINT",	0x05, 1 },
	{ "I365_ADDRWIN",	0x06, 1 },
	{ "I365_IOCTL",		0x07, 1 },
	{ "I365_GENCTL",	0x16, 2 },
	{ "I365_GBLCTL",	0x1e, 2 },

	{ "I365_IO0_START",	0x08, 2 },
	{ "I365_IO0_STOP",	0x0a, 2 },
	{ "I365_IO1_START",	0x0c, 2 },
	{ "I365_IO1_STOP",	0x0e, 2 },

	{ "I365_MEM0_START",	0x10, 2 },
	{ "I365_MEM0_STOP",	0x12, 2 },
	{ "I365_MEM0_OFF",	0x14, 2 },
	{ "I365_MEM0_PAGE",	0x40, 1 },
	{ "I365_MEM1_START",	0x18, 2 },
	{ "I365_MEM1_STOP",	0x1a, 2 },
	{ "I365_MEM1_OFF",	0x1c, 2 },
	{ "I365_MEM1_PAGE",	0x41, 1 },
	{ "I365_MEM2_START",	0x20, 2 },
	{ "I365_MEM2_STOP",	0x22, 2 },
	{ "I365_MEM2_OFF",	0x24, 2 },
	{ "I365_MEM2_PAGE",	0x42, 1 },
	{ "I365_MEM3_START",	0x28, 2 },
	{ "I365_MEM3_STOP",	0x2a, 2 },
	{ "I365_MEM3_OFF",	0x2c, 2 },
	{ "I365_MEM3_PAGE",	0x43, 1 },
	{ "I365_MEM4_START",	0x30, 2 },
	{ "I365_MEM4_STOP",	0x32, 2 },
	{ "I365_MEM4_OFF",	0x34, 2 },
	{ "I365_MEM4_PAGE",	0x44, 1 },
};

static void dump_exca(void *mem)
{
	printf("  -- exca registers\n");
	dump_memory((void *) ((unsigned long) mem + 0x800), exca_data);
}

static void dump_memspace(struct pci_dev *dev, u32 mem)
{
	void *base;
	int fd;

	fd = open("/dev/mem", O_RDONLY);
	if (fd == -1) {
		perror("open /dev/mem");
		return;
	}

	base = mmap(NULL, 4096, PROT_READ, MAP_SHARED|MAP_FILE, fd, mem);
	if (base == (void *)-1) {
		perror("mmap /dev/mem");
		close(fd);
		return;
	}

	close(fd);

	dump_cb(base);
	dump_exca(base);

	munmap(base, 4096);
}

static struct dump_data cb_general_data[] = {
	{ "Vendor ID",			PCI_VENDOR_ID, 2 },
	{ "Device ID",			PCI_DEVICE_ID, 2 },
	{ "PCI command",		PCI_COMMAND, 2 },
	{ "Base address",		PCI_BASE_ADDRESS_0, 4 },
	{ "Memory Base 0",		PCI_CB_MEMORY_BASE_0, 4 },
	{ "Memory Limit 0",		PCI_CB_MEMORY_LIMIT_0, 4 },
	{ "Memory Base 1",		PCI_CB_MEMORY_BASE_1, 4 },
	{ "Memory Limit 1",		PCI_CB_MEMORY_LIMIT_1, 4 },
	{ "IO Base 0",			PCI_CB_IO_BASE_0, 4 },
	{ "IO Limit 0",			PCI_CB_IO_LIMIT_0, 4 },
	{ "IO Base 1",			PCI_CB_IO_BASE_1, 4 },
	{ "IO Limit 1",			PCI_CB_IO_LIMIT_1, 4 },
	{ "Bridge control",		PCI_CB_BRIDGE_CONTROL, 2 },
	{ "Subsystem vendor ID",	PCI_CB_SUBSYSTEM_VENDOR_ID, 2 },
	{ "Subsystem device ID",	PCI_CB_SUBSYSTEM_ID, 2 },
	{ "Legacy mode base",		PCI_CB_LEGACY_MODE_BASE, 2 },
};

static const struct dump_data ti_data[] = {
	{ "System control",		0x80, 4 },
	{ "IRQ Mux",			0x8c, 4 },
	{ "Retry",			0x90, 1 },
	{ "Card control",		0x91, 1 },
	{ "Device control",		0x92, 1 },
	{ "Diagnostic",			0x93, 1 },
};

static const struct dump_data rl5c475_data[] = {
	{ "System configuration",	0x80, 2 },
	{ "Misc Control",		0x82, 2 },
	{ "16-bit Interface Control",	0x84, 2 },
	{ "16-bit I/O Timing 0",	0x88, 2 },
	{ "16-bit Memory Timing 0",	0x8a, 2 },
	{ "DMA Slave",			0x90, 2 },
};

static const struct dump_data rl5c476II_data[] = {
	{ "Misc Control 2",		0xa0, 2 },
	{ "Misc Control 3",		0xa2, 2 },
	{ "Misc Control 4",		0xa4, 2 },
	{ "GPIO 1",			0xaa, 1 },
};

static void dump_cardbus(struct pci_dev *dev)
{
	char class[256];
	char name[256];
	u32 base;

	printf("%02x:%02x.%x %s: %s\n",
		dev->bus, dev->dev, dev->func,
		pci_lookup_name(dev->access, class, sizeof(class),
			PCI_LOOKUP_CLASS,
			pci_read_word(dev, PCI_CLASS_DEVICE), 0, 0, 0),
		pci_lookup_name(dev->access, name, sizeof(name),
			PCI_LOOKUP_VENDOR | PCI_LOOKUP_DEVICE,
			dev->vendor_id, dev->device_id, 0, 0));

	base = pci_read_long(dev, PCI_BASE_ADDRESS_0);

	printf("  -- generic cardbus config registers\n");
	dump_config(dev, cb_general_data);

	if (dev->vendor_id == 0x104c) {	/* TI */
		printf("  -- TI specific config registers\n");
		dump_config(dev, ti_data);
	}

	if ((dev->vendor_id == 0x1180) &&
	    (dev->device_id == 0x0475)) {	/* Ricoh RL5c475 */
		printf("  -- Ricoh RL5c475 specific config registers\n");
		dump_config(dev, rl5c475_data);
	}

	if ((dev->vendor_id == 0x1180) &&
	    (dev->device_id == 0x0476)) {	/* Ricoh RL5c476II */
		printf("  -- Ricoh RL5c476II specific config registers\n");
		dump_config(dev, rl5c475_data);
		dump_config(dev, rl5c476II_data);
	}

	dump_memspace(dev, base);

	printf("\n");
}

int main(int argc, char *argv[])
{
	struct pci_access *pa;
	struct pci_dev *dev;

	pa = pci_alloc();
	if (!pa) {
		perror("pci_alloc");
		return 1;
	}

	pa->writeable = 0;
	pa->buscentric = 0;

	pci_init(pa);
	pci_scan_bus(pa);

	for (dev = pa->devices; dev; dev = dev->next) {
		unsigned int header;

		header = pci_read_word(dev, PCI_HEADER_TYPE);
		header &= ~0x80;
		if (header == PCI_HEADER_TYPE_CARDBUS)
			dump_cardbus(dev);
	}
	pci_cleanup(pa);

	return 0;
}
