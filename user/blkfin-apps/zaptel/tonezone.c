/*
 * BSD Telephony Of Mexico "Tormenta" Tone Zone Support 2/22/01
 * 
 * Working with the "Tormenta ISA" Card 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under thet erms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 * Primary Author: Mark Spencer <markster@linux-support.net>
 *
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "tonezone.h"

#define DEFAULT_ZT_DEV "/dev/zap/zapctl"

#define MAX_SIZE 16384
#define CLIP 32635
#define BIAS 0x84

struct tone_zone *tone_zone_find(char *country)
{
	struct tone_zone *z;
	z = builtin_zones;
	while(z->zone > -1) {
		if (!strcasecmp(country, z->country))
			return z;
		z++;
	}
	return NULL;
}

struct tone_zone *tone_zone_find_by_num(int id)
{
	struct tone_zone *z;
	z = builtin_zones;
	while(z->zone > -1) {
		if (z->zone == id)
			return z;
		z++;
	}
	return NULL;
}

#define LEVEL -10

static int build_tone(char *data, int size, struct tone_zone_sound *t, int *count)
{
	char *dup, *s;
	struct zt_tone_def *td=NULL;
	int firstnobang = -1;
	int freq1, freq2, time;
	int used = 0;
	int modulate = 0;
	float gain;
	dup = strdup(t->data);
	s = strtok(dup, ",");
	while(s && strlen(s)) {
		/* Handle optional ! which signifies don't start here*/
		if (s[0] == '!') 
			s++;
		else if (firstnobang < 0) {
#if 0
			printf("First no bang: %s\n", s);
#endif			
			firstnobang = *count;
		}
		if (sscanf(s, "%d+%d/%d", &freq1, &freq2, &time) == 3) {
			/* f1+f2/time format */
#if 0
			printf("f1+f2/time format: %d, %d, %d\n", freq1, freq2, time);
#endif			
		} else if (sscanf(s, "%d*%d/%d", &freq1, &freq2, &time) == 3) {
			/* f1*f2/time format */
			modulate = 1;
#if 0
			printf("f1+f2/time format: %d, %d, %d\n", freq1, freq2, time);
#endif			
		} else if (sscanf(s, "%d+%d", &freq1, &freq2) == 2) {
#if 0
			printf("f1+f2 format: %d, %d\n", freq1, freq2);
#endif			
			time = 0;
		} else if (sscanf(s, "%d*%d", &freq1, &freq2) == 2) {
			modulate = 1;
#if 0
			printf("f1+f2 format: %d, %d\n", freq1, freq2);
#endif			
			time = 0;
		} else if (sscanf(s, "%d/%d", &freq1, &time) == 2) {
#if 0
			printf("f1/time format: %d, %d\n", freq1, time);
#endif			
			freq2 = 0;
		} else if (sscanf(s, "%d", &freq1) == 1) {
#if 0		
			printf("f1 format: %d\n", freq1);
#endif			
			firstnobang = *count;
			freq2 = 0;
			time = 0;
		} else {
			fprintf(stderr, "tone component '%s' of '%s' is a syntax error\n", s,t->data);
			return -1;
		}
#if 0
		printf("Using %d samples for %d and %d\n", samples, freq1, freq2);
#endif
		if (size < sizeof(struct zt_tone_def)) {
			fprintf(stderr, "Not enough space for samples\n");
			return -1;
		}
		td = (struct zt_tone_def *)data;

		/* Bring it down -8 dbm */
		gain = pow(10.0, (LEVEL - 3.14) / 20.0) * 65536.0 / 2.0;

		td->fac1 = 2.0 * cos(2.0 * M_PI * (freq1 / 8000.0)) * 32768.0;
		td->init_v2_1 = sin(-4.0 * M_PI * (freq1 / 8000.0)) * gain;
		td->init_v3_1 = sin(-2.0 * M_PI * (freq1 / 8000.0)) * gain;
		
		td->fac2 = 2.0 * cos(2.0 * M_PI * (freq2 / 8000.0)) * 32768.0;
		td->init_v2_2 = sin(-4.0 * M_PI * (freq2 / 8000.0)) * gain;
		td->init_v3_2 = sin(-2.0 * M_PI * (freq2 / 8000.0)) * gain;

		td->modulate = modulate;

		data += (sizeof(struct zt_tone_def));
		used += (sizeof(struct zt_tone_def));
		size -= (sizeof(struct zt_tone_def));
		td->tone = t->toneid;
		if (time) {
			/* We should move to the next tone */
			td->next = *count + 1;
			td->samples = time * 8;
		} else {
			/* Stay with us */
			td->next = *count;
			td->samples = 8000;
		}
		(*count)++;
		s = strtok(NULL, ",");
	}
	if (td && time) {
		/* If we don't end on a solid tone, return */
		td->next = firstnobang;
	}
	return used;
}

char *tone_zone_tone_name(int id)
{
	static char tmp[80];
	switch(id) {
	case ZT_TONE_DIALTONE:
		return "Dialtone";
	case ZT_TONE_BUSY:
		return "Busy";
	case ZT_TONE_RINGTONE:
		return "Ringtone";
	case ZT_TONE_CONGESTION:
		return "Congestion";
	case ZT_TONE_CALLWAIT:
		return "Call Waiting";
	case ZT_TONE_DIALRECALL:
		return "Dial Recall";
	case ZT_TONE_RECORDTONE:
		return "Record Tone";
	case ZT_TONE_CUST1:
		return "Custom 1";
	case ZT_TONE_CUST2:
		return "Custom 2";
	case ZT_TONE_INFO:
		return "Special Information";
	case ZT_TONE_STUTTER:
		return "Stutter Dialtone";
	default:
		snprintf(tmp, sizeof(tmp), "Unknown tone %d", id);
		return tmp;
	}
}

#ifdef TONEZONE_DRIVER
static void dump_tone_zone(void *data)
{
	struct zt_tone_def_header *z;
	struct zt_tone_def *td;
	int x;
	int len=0;
	z = data;
	data += sizeof(*z);
	printf("Header: %d tones, %d bytes of data, zone %d (%s)\n", 
		z->count, z->size, z->zone, z->name);
	for (x=0;x < z->count; x++) {
		td = data;
		printf("Tone Fragment %d: %d bytes, %s tone, next is %d, %d samples total\n",
			x, td->size, tone_name(td->tone), td->next, td->samples);
		data += sizeof(*td);
		data += td->size;
		len += td->size;
	}
	printf("Total measured bytes of data: %d\n", len);
}
#endif

int tone_zone_register_zone(int fd, struct tone_zone *z)
{
	char buf[MAX_SIZE];
	int res;
	int count=0;
	int x;
	int used = 0;
	int iopenedit = 0;
	int space = MAX_SIZE;
	char *ptr = buf;
	struct zt_tone_def_header *h;
	if (fd < 0) {
		fd = open(DEFAULT_ZT_DEV, O_RDWR);
		iopenedit=1;
		if (fd < 0) {
			fprintf(stderr, "Unable to open %s and fd not provided\n", DEFAULT_ZT_DEV);
			return -1;
		}
	}
	h = (struct zt_tone_def_header *)ptr;
	ptr += sizeof(struct zt_tone_def_header);
	space -= sizeof(struct zt_tone_def_header);
	used += sizeof(struct zt_tone_def_header);
	/*
	 * Fill in ring cadence 
	 */
	for (x=0;x<ZT_MAX_CADENCE;x++) 
		h->ringcadence[x] = z->ringcadence[x];
	/* Put in an appropriate method for a kernel ioctl */
	for (x=0;x<ZT_TONE_MAX;x++) {
		if (strlen(z->tones[x].data)) {
			/* It's a real tone */
#if 0
			printf("Tone: %d, string: %s\n", z->tones[x].toneid, z->tones[x].data);
#endif			
			res = build_tone(ptr, space, &z->tones[x], &count);
			if (res < 0) {
				fprintf(stderr, "Tone not built.\n");
				if (iopenedit)
					close(fd);
				return -1;
			}
			ptr += res;
			used += res;
			space -= res;
		}
	}
	h->count = count;
	h->zone = z->zone;
	strncpy(h->name, z->description, sizeof(h->name));
	x = z->zone;
	ioctl(fd, ZT_FREEZONE, &x);
	res = ioctl(fd, ZT_LOADZONE, h);
	if (res) 
		fprintf(stderr, "ioctl(ZT_LOADZONE) failed: %s\n", strerror(errno));
	if (iopenedit)
		close(fd);
	return res;
}

int tone_zone_register(int fd, char *country)
{
	struct tone_zone *z;
	z = tone_zone_find(country);
	if (z) {
		return tone_zone_register_zone(-1, z);
	} else {
		return -1;
	}
}

int tone_zone_set_zone(int fd, char *country)
{
	int res=-1;
	struct tone_zone *z;
	if (fd > -1) {
		z = tone_zone_find(country);
		if (z)
			res = ioctl(fd, ZT_SETTONEZONE, &z->zone);
		if ((res < 0) && (errno == ENODATA)) {
			tone_zone_register_zone(fd, z);
			res = ioctl(fd, ZT_SETTONEZONE, &z->zone);
		}
	}
	return res;
}

int tone_zone_get_zone(int fd)
{
	int x=-1;
	if (fd > -1) {
		ioctl(fd, ZT_GETTONEZONE, &x);
		return x;
	}
	return -1;
}

int tone_zone_play_tone(int fd, int tone)
{
	struct tone_zone *z;
	int res = -1;
	int zone;

#if 1
	printf("Playing tone %d (%s) on %d\n", tone, tone_zone_tone_name(tone), fd);
#endif
	if (fd > -1) {
		res = ioctl(fd, ZT_SENDTONE, &tone);
		if ((res < 0) && (errno == ENODATA)) {
			ioctl(fd, ZT_GETTONEZONE, &zone);
			z = tone_zone_find_by_num(zone);
			if (z) {
				res = tone_zone_register_zone(fd, z);
				/* Recall the zone */
				ioctl(fd, ZT_SETTONEZONE, &zone);
				if (res < 0) {
					fprintf(stderr, "Failed to register zone '%s': %s\n", z->description, strerror(errno));
				} else {
					res = ioctl(fd, ZT_SENDTONE, &tone);
				}
			} else
				fprintf(stderr, "Don't know anything about zone %d\n", zone);
		}
	}
	return res;
}
