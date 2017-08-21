/*
 * Copyright (c) 2016-2017 Chuck Tuffli <chuck@tuffli.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <strings.h>
#include <sys/endian.h>

#include "libsmart.h"
#include "libsmart_priv.h"
#include "libsmart_dev.h"

static uint32_t __smart_attribute_max(smart_buf_t *sb);
static uint32_t __smart_buffer_size(smart_buf_t *sb);
static smart_map_t *__smart_map(smart_h h, smart_buf_t *sb);

smart_h
smart_open(smart_protocol_e protocol, char *devname)
{

	return device_open(protocol, devname);
}

void
smart_close(smart_h h)
{

	device_close(h);
}

bool
smart_supported(smart_h h)
{
	smart_t *s = h;
	bool supported = false;

	if (s) {
		supported = s->info.supported;
	}

	return supported;
}

smart_map_t *
smart_read(smart_h h)
{
	smart_t *s = h;
	smart_buf_t *sb = NULL;
	smart_map_t *sm = NULL;

	sb = malloc(sizeof(smart_buf_t));
	if (sb) {
		sb->protocol = s->protocol;
		sb->b = NULL;
		sb->bsize = __smart_buffer_size(sb);

		if (sb->bsize != 0) {
			sb->b = malloc(sb->bsize);
		}

		if (sb->b == NULL) {
			free(sb);
			sb = NULL;
		} else {
			uint32_t page = 0;

			switch (s->protocol) {
			case SMART_PROTO_ATA:
				page = 0xd0;
				break;
			case SMART_PROTO_NVME:
				page = 0x02;
				break;
			default:
				page = 0;
			}

			if (device_read_log(h, page, sb->b, sb->bsize)) {
				free(sb);
				sb = NULL;
			} else {
				sb->attr_count = __smart_attribute_max(sb);

				sm = __smart_map(h, sb);
				if (!sm) {
					free(sb->b);
					free(sb);
					sb = NULL;
				}
			}
		}
	}
	
	return sm;
}

void
smart_free(smart_map_t *sm)
{
	smart_buf_t *sb = NULL;
	uint32_t i;

	if (sm == NULL)
		return;

	sb = sm->sb;

	if (sb) {
		if (sb->b) {
			free(sb->b);
			sb->b = NULL;
		}

		free(sb);
	}

	for (i = 0; i < sm->count; i++) {
		smart_map_t *tm = sm->attr[i].thresh;

		if (tm) {
			free(tm);
		}
	}

	free(sm);
}

/*
 * XXX TODO some of this is ATA specific
 */
#define ID_HEX		"%#01.1x "
#define ID_DEC		"%d "

#define THRESH_HEX	"%#01.1x %#01.1x %#01.1x %#01.1x "
#define	THRESH_DEC	"%d %d %d %d "

#define RAW_HEX		"%#01.1x\n"
#define RAW_DEC		"%d\n"

/* Long integer version of the format macro */
#define RAW_LHEX	"%#01.1lx\n"
#define RAW_LDEC	"%ld\n"

static char *
__smart_u128_str(smart_attr_t *sa)
{
	/* log10(x) = log2(x) / log2(10) ~= log2(x) / 3.322 */
	const uint32_t max_len = 128 / 3 + 1 + 1;
	static char s[max_len];
	char *p = s + max_len - 1;
	uint32_t *a = (uint32_t *)sa->raw;
	uint64_t r, d;
	uint32_t last = 0;

	*p-- = '\0';

	do {
		r = a[3];

		d = r / 10;
		r = ((r - d * 10) << 32) + a[2];
		a[3] = d;

		d = r / 10;
		r = ((r - d * 10) << 32) + a[1];
		a[2] = d;

		d = r / 10;
		r = ((r - d * 10) << 32) + a[0];
		a[1] = d;

		d = r / 10;
		r = r - d * 10;
		a[0] = d;

		*p-- = '0' + r;
	} while (a[0] || a[1] || a[2] || a[3]);

	p++;

	while ((*p == '0') && (p < &s[sizeof(s) - 2]))
		p++;

	return p;
}

static void
__smart_print_thresh(smart_map_t *tm, uint32_t flags)
{
	bool do_hex = false;
	bool do_thresh = false;

	if (!tm) {
		return;
	}

	if (flags & 0x1)
		do_hex = true;

	if (flags & 0x2)
		do_thresh = true;

	if (do_thresh && tm) {
		printf(do_hex ? THRESH_HEX : THRESH_DEC,
				*((uint8_t *)tm->attr[0].raw),
				*((uint8_t *)tm->attr[1].raw),
				*((uint8_t *)tm->attr[2].raw),
				*((uint8_t *)tm->attr[3].raw));
	}
}

void
smart_print(smart_h h, smart_map_t *sm, int32_t which, uint32_t flags)
{
	uint32_t i;
	const char *fmt, *lfmt;
	bool do_hex = false;
	bool do_thresh = false;
	uint32_t bytes = 0;

	if (!sm) {
		return;
	}

	if (flags & 0x1)
		do_hex = true;

	if (flags & 0x2)
		do_thresh = true;

	for (i = 0; i < sm->count; i++) {
		if ((which != -1) && (which != sm->attr[i].id)) {
			continue;
		}

		bytes = sm->attr[i].bytes;

		if (bytes > 8) {
			if (which == -1)
				printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].id);

			__smart_print_thresh(sm->attr[i].thresh, flags);

			if (do_hex)
				;
			else
				printf("%s\n", __smart_u128_str(&sm->attr[i]));

		} else if (bytes > 4) {
			uint64_t v64 = 0;
			uint64_t mask = UINT64_MAX;

			bcopy(sm->attr[i].raw, &v64, bytes);

			if (sm->attr[i].flags & SMART_ATTR_F_BE) {
				v64 = be64toh(v64);
			} else {
				v64 = le64toh(v64);
			}

			mask >>= 8 * (sizeof(uint64_t) - bytes);

			v64 &= mask;

			if (which == -1)
				printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].id);

			__smart_print_thresh(sm->attr[i].thresh, flags);

			printf(do_hex ? RAW_LHEX : RAW_LDEC, v64);

		} else if (bytes > 2) {
			uint32_t v32 = 0;
			uint32_t mask = UINT32_MAX;

			bcopy(sm->attr[i].raw, &v32, bytes);

			if (sm->attr[i].flags & SMART_ATTR_F_BE) {
				v32 = be32toh(v32);
			} else {
				v32 = le32toh(v32);
			}

			mask >>= 8 * (sizeof(uint32_t) - bytes);

			v32 &= mask;

			if (which == -1)
				printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].id);

			__smart_print_thresh(sm->attr[i].thresh, flags);

			printf(do_hex ? RAW_HEX : RAW_DEC, v32);

		} else if (bytes > 1) {
			uint16_t v16 = 0;
			uint16_t mask = UINT16_MAX;

			bcopy(sm->attr[i].raw, &v16, bytes);

			if (sm->attr[i].flags & SMART_ATTR_F_BE) {
				v16 = be16toh(v16);
			} else {
				v16 = le16toh(v16);
			}

			mask >>= 8 * (sizeof(uint16_t) - bytes);

			v16 &= mask;

			if (which == -1)
				printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].id);

			__smart_print_thresh(sm->attr[i].thresh, flags);

			printf(do_hex ? RAW_HEX : RAW_DEC, v16);

		} else if (bytes > 0) {
			uint8_t v8 = *((uint8_t *)sm->attr[i].raw);

			if (which == -1)
				printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].id);

			__smart_print_thresh(sm->attr[i].thresh, flags);

			printf(do_hex ? RAW_HEX : RAW_DEC, v8);

		}

		if (which != -1)
			break;
	}
}

void
smart_print_device_info(smart_h h)
{
	smart_t *s = h;

	if (!s) {
		return;
	}

	if (*s->info.vendor != '\0')
		printf("Vendor %s\n", s->info.vendor);
	if (*s->info.device != '\0')
		printf("Device %s\n", s->info.device);
	if (*s->info.rev != '\0')
		printf("Revision %s\n", s->info.rev);
	if (*s->info.serial != '\0')
		printf("Serial %s\n", s->info.serial);
}

static uint32_t
__smart_attr_max_ata(smart_buf_t *sb)
{
	uint32_t max = 0;

	if (sb) {
		max = (sb->bsize - 2) / 12;
	}

	return max;
}

static uint32_t
__smart_attr_max_nvme(smart_buf_t *sb)
{

	return 0;
}

static uint32_t
__smart_attribute_max(smart_buf_t *sb)
{
	uint32_t count = 0;

	if (sb != NULL) {
		switch (sb->protocol) {
		case SMART_PROTO_ATA:
			count = __smart_attr_max_ata(sb);
			break;
		case SMART_PROTO_NVME:
			count = __smart_attr_max_nvme(sb);
			break;
		default:
			;
		}
	}

	return count;
}

/**
 * Return the buffer size needed by the underlying protocol
 */
static uint32_t
__smart_buffer_size(smart_buf_t *sb)
{
	uint32_t size = 0;

	if (sb != NULL) {
		switch (sb->protocol) {
		case SMART_PROTO_ATA:
			size = 512;
			break;
		case SMART_PROTO_NVME:
			size = 4096;
			break;
		default:
			size = 0;
		}
	}

	return size;
}

static smart_map_t *
__smart_map_ata_thresh(uint8_t *b)
{
	smart_map_t *sm = NULL;

	sm = malloc(sizeof(smart_map_t) + (4 * sizeof(smart_attr_t)));
	if (sm) {
		uint32_t i;

		sm->count = 4;

		for (i = 0; i < sm->count; i++) {
			sm->attr[i].id = i;
			sm->attr[i].bytes = 1;
			sm->attr[i].flags = 0;
			sm->attr[i].raw = b + i;
			sm->attr[i].thresh = NULL;
		}
	}

	return sm;
}

static void
__smart_map_ata(smart_buf_t *sb, smart_map_t *sm)
{
	uint8_t *b = NULL;
	uint8_t *b_end = NULL;
	uint32_t i = 0;
	uint32_t max_attr = 0;

	max_attr = sm->count;

	b = sb->b;

	b += 2;

	b_end = b + (max_attr * 12);

	while (b < b_end) {
		if (*b != 0) {
			if (i >= max_attr) {
				warnx("More attributes (%d) than fit in map", i);
				break;
			}

			sm->attr[i].id = b[0];
			sm->attr[i].bytes = 6;
			sm->attr[i].flags = 0;
			sm->attr[i].raw = b + 5;
			sm->attr[i].thresh = __smart_map_ata_thresh(b + 1);

			i++;
		}

		b += 12;
	}

	sm->count = i;
}

#ifndef ARRAYLEN
#define ARRAYLEN(p) sizeof(p)/sizeof(p[0])
#endif

#define NVME_VS(mjr,mnr,ter) (((mjr) << 16) | ((mnr) << 8) | (ter))
#define NVME_VS_1_0	NVME_VS(1,0,0)
#define NVME_VS_1_1	NVME_VS(1,1,0)
#define NVME_VS_1_2	NVME_VS(1,2,0)
#define NVME_VS_1_2_1	NVME_VS(1,2,1)
#define NVME_VS_1_3	NVME_VS(1,3,0)
struct {
	uint32_t off;		/* buffer offset */
	uint32_t bytes;		/* size in bytes */
	uint32_t ver;		/* first version available */
} __smart_nvme_values[] = {
	{ 0, 1, NVME_VS_1_0 },	// Critical Warning
	{ 1, 2, NVME_VS_1_0 },	// Temperature
	{ 3, 1, NVME_VS_1_0 },	// Available Spare
	{ 4, 1, NVME_VS_1_0 },	// Available Spare Threshold
	{ 5, 1, NVME_VS_1_0 },	// Percentage Used
	{ 32, 16, NVME_VS_1_0 },	// Data Units Read
	{ 48, 16, NVME_VS_1_0 },	// Data Units Written
	{ 64, 16, NVME_VS_1_0 },	// Host Read Commands
	{ 80, 16, NVME_VS_1_0 },	// Host Write Commands
	{ 96, 16, NVME_VS_1_0 },	// Controller Busy Time
	{ 112, 16, NVME_VS_1_0 },	// Power Cycles
	{ 128, 16, NVME_VS_1_0 },	// Power On Hours
	{ 144, 16, NVME_VS_1_0 },	// Unsafe Shutdowns
	{ 160, 16, NVME_VS_1_0 },	// Media Errors
	{ 176, 16, NVME_VS_1_0 },	// Number of Error Information Log Entries
};

/**
 * NVMe doesn't define attribute IDs like ATA does, but we can
 * approximate this behavior by treating the byte offset as the
 * attribute ID.
 */
static void
__smart_map_nvme(smart_buf_t *sb, smart_map_t *sm)
{
	uint8_t *b = NULL;
	uint32_t vs = NVME_VS_1_0;	// XXX assume device is 1.0
	uint32_t i, a;

	b = sb->b;

	for (i = 0, a = 0; i < ARRAYLEN(__smart_nvme_values); i++) {
		if (vs >= __smart_nvme_values[i].ver) {
			sm->attr[a].id = __smart_nvme_values[i].off;
			sm->attr[a].bytes = __smart_nvme_values[i].bytes;
			sm->attr[a].flags = 0;
			sm->attr[a].raw = b + __smart_nvme_values[i].off;
			sm->attr[a].thresh = NULL;

			a++;
		}
	}

	sm->count = a;
}

/**
 * Create a map of SMART values
 */
static void
__smart_attribute_map(smart_buf_t *sb, smart_map_t *sm)
{

	if (!sb || !sm) {
		return;
	}

	switch (sb->protocol) {
	case SMART_PROTO_ATA:
		__smart_map_ata(sb, sm);
		break;
	case SMART_PROTO_NVME:
		__smart_map_nvme(sb, sm);
		break;
	default:
		sm->count = 0;
	}
}

static smart_map_t *
__smart_map(smart_h h, smart_buf_t *sb)
{
	smart_map_t *sm = NULL;
	uint32_t max = 0;

	max = __smart_attribute_max(sb);

	sm = malloc(sizeof(smart_map_t) + (max * sizeof(smart_attr_t)));
	if (sm) {
		sm->sb = sb;

		/* count starts as the max but is adjusted to reflect the actual number */
		sm->count = max;

		__smart_attribute_map(sb, sm);
	}
	
	return sm;
}

