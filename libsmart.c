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

/* Default page lists */
smart_page_list_t pg_list_ata = {
	.pg_count = 1,
	.pages = {
		{ .id = 0xd0, .bytes = 512 }
	}
};

#define PAGE_ID_NVME_SMART_HEALTH	0x02

smart_page_list_t pg_list_nvme = {
	.pg_count = 1,
	.pages = {
		{ .id = PAGE_ID_NVME_SMART_HEALTH, .bytes = 512 }
	}
};

#define PAGE_ID_SCSI_SUPPORTED_PAGES	0x00
#define PAGE_ID_SCSI_WRITE_ERR		0x02		/* Write Error counter */
#define PAGE_ID_SCSI_READ_ERR		0x03		/* Read Error counter */
#define PAGE_ID_SCSI_VERIFY_ERR		0x05		/* Verify Error counter */
#define PAGE_ID_SCSI_NON_MEDIUM_ERR	0x06		/* Non-Medium Error */
#define PAGE_ID_SCSI_LAST_N_ERR		0x07		/* Last n Error events */
#define PAGE_ID_SCSI_TEMPERATURE	0x0d		/* Temperature */
#define PAGE_ID_SCSI_START_STOP_CYCLE	0x0e		/* Start-Stop Cycle counter */

smart_page_list_t pg_list_scsi = {
	.pg_count = 7,
	.pages = {
		{ .id = PAGE_ID_SCSI_WRITE_ERR, .bytes = 128 },
		{ .id = PAGE_ID_SCSI_READ_ERR, .bytes = 128 },
		{ .id = PAGE_ID_SCSI_VERIFY_ERR, .bytes = 128 },
		{ .id = PAGE_ID_SCSI_NON_MEDIUM_ERR, .bytes = 128 },
		{ .id = PAGE_ID_SCSI_LAST_N_ERR, .bytes = 128 },
		{ .id = PAGE_ID_SCSI_TEMPERATURE, .bytes = 64 },
		{ .id = PAGE_ID_SCSI_START_STOP_CYCLE, .bytes = 128 },
	}
};

static uint32_t __smart_attribute_max(smart_buf_t *sb);
static uint32_t __smart_buffer_size(smart_h h);
static smart_map_t *__smart_map(smart_h h, smart_buf_t *sb);
static smart_page_list_t *__smart_page_list(smart_h h);
static int32_t __smart_read_pages(smart_h h, smart_buf_t *sb);

static char *
smart_proto_str(smart_protocol_e p)
{

	switch (p) {
	case SMART_PROTO_AUTO:
		return "auto";
	case SMART_PROTO_ATA:
		return "ATA";
	case SMART_PROTO_SCSI:
		return "SCSI";
	case SMART_PROTO_NVME:
		return "NVME";
	default:
		return "Unknown";
	}
}

smart_h
smart_open(smart_protocol_e protocol, char *devname)
{
	smart_t *s;

	s = device_open(protocol, devname);

	if (s) {
		dprintf("protocol %s (specified %s%s)\n",
				smart_proto_str(s->protocol),
				smart_proto_str(protocol),
				s->info.tunneled ?  ", tunneled ATA" : "");
	}

	return s;
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
		dprintf("SMART is %ssupported\n", s->info.supported ? "" : "not ");
	}

	return supported;
}

smart_map_t *
smart_read(smart_h h)
{
	smart_t *s = h;
	smart_buf_t *sb = NULL;
	smart_map_t *sm = NULL;

	sb = calloc(1, sizeof(smart_buf_t));
	if (sb) {
		sb->protocol = s->protocol;

		/*
		 * Need the page list to calculate the buffer size. If one
		 * isn't specified, get the default based on the protocol.
		 */
		if (s->pg_list == NULL) {
			s->pg_list = __smart_page_list(s);
			if (!s->pg_list) {
				goto smart_read_out;
			}
		}

		sb->b = NULL;
		sb->bsize = __smart_buffer_size(s);

		if (sb->bsize != 0) {
			sb->b = malloc(sb->bsize);
		}

		if (sb->b == NULL) {
			goto smart_read_out;
		}

		if (__smart_read_pages(s, sb) < 0) {
			goto smart_read_out;
		}

		sb->attr_count = __smart_attribute_max(sb);

		sm = __smart_map(h, sb);
		if (!sm) {
			free(sb->b);
			free(sb);
			sb = NULL;
		}
	}

smart_read_out:
	if (!sm) {
		if (sb) {
			if (sb->b) {
				free(sb->b);
			}

			free(sb);
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

#define THRESH_HEX	" %#01.1x %#01.1x %#01.1x"
#define	THRESH_DEC	" %d %d %d"

#define RAW_HEX		"%#01.1x"
#define RAW_DEC		"%d"

/* Long integer version of the format macro */
#define RAW_LHEX	"%#01.1" PRIx64
#define RAW_LDEC	"%" PRId64

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
				*((uint8_t *)tm->attr[2].raw));
	}
}

void
smart_print(smart_h h, smart_map_t *sm, int32_t which, uint32_t flags)
{
	uint32_t i;
	const char *fmt, *lfmt;
	bool do_hex = false;
	uint32_t bytes = 0;

	if (!sm) {
		return;
	}

	if (flags & 0x1)
		do_hex = true;

	for (i = 0; i < sm->count; i++) {
		/* If we're printing a specific attribute, is this it? */
		if ((which != -1) && (which != sm->attr[i].id)) {
			continue;
		}

		/* Print the page / attribute ID if selecting all attributes */
		if (which == -1) {
			printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].page);
			printf(do_hex ? ID_HEX : ID_DEC, sm->attr[i].id);
		}

		bytes = sm->attr[i].bytes;

		/* Print the attribute based on its size */
		if (sm->attr[i].flags & SMART_ATTR_F_STR) {
			printf("%s", sm->attr[i].raw);
		} else if (bytes > 8) {
			if (do_hex)
				;
			else
				printf("%s", __smart_u128_str(&sm->attr[i]));

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

			printf(do_hex ? RAW_HEX : RAW_DEC, v16);

		} else if (bytes > 0) {
			uint8_t v8 = *((uint8_t *)sm->attr[i].raw);

			printf(do_hex ? RAW_HEX : RAW_DEC, v8);
		}

		__smart_print_thresh(sm->attr[i].thresh, flags);

		printf("\n");

		/* We're done if printing a specific attribute */
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
		max = 30;
	}

	return max;
}

static uint32_t
__smart_attr_max_nvme(smart_buf_t *sb)
{
	uint32_t max = 0;

	if (sb) {
		max = 512;
	}

	return max;
}

static uint32_t
__smart_attr_max_scsi(smart_buf_t *sb)
{
	uint32_t max = 0;

	if (sb) {
		max = 512;
	}

	return max;
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
		case SMART_PROTO_SCSI:
			count = __smart_attr_max_scsi(sb);
			break;
		default:
			;
		}
	}

	return count;
}

/**
 * Return the total buffer size needed by the protocol's page list
 */
static uint32_t
__smart_buffer_size(smart_h h)
{
	smart_t *s = h;
	uint32_t size = 0;

	if ((s != NULL) && (s->pg_list != NULL)) {
		smart_page_list_t *plist = s->pg_list;
		uint32_t p = 0;

		for (p = 0; p < plist->pg_count; p++) {
			size += plist->pages[p].bytes;
		}
	}

	return size;
}

static smart_map_t *
__smart_map_ata_thresh(uint8_t *b)
{
	smart_map_t *sm = NULL;

	sm = malloc(sizeof(smart_map_t) + (3 * sizeof(smart_attr_t)));
	if (sm) {
		uint32_t i;

		sm->count = 3;

		sm->attr[0].page = 0;
		sm->attr[0].id = 0;
		sm->attr[0].bytes = 2;
		sm->attr[0].flags = 0;
		sm->attr[0].raw = b;
		sm->attr[0].thresh = NULL;

		b++;

		for (i = 1; i < sm->count; i++) {
			sm->attr[i].page = 0;
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

			sm->attr[i].page = 0xd0;
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

	sm->count = 0;
	b = sb->b;

	for (i = 0, a = 0; i < ARRAYLEN(__smart_nvme_values); i++) {
		if (vs >= __smart_nvme_values[i].ver) {
			sm->attr[a].page = 0x2;
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

/*
 * Create a SMART map for SCSI error counter pages
 *
 * Several SCSI log pages have a similar format for the error counter log
 * pages
 */
static void
__smart_map_scsi_err_page(smart_map_t *sm, void *b, size_t bsize)
{
	struct scsi_err_page {
		uint8_t page_code;
		uint8_t subpage_code;
		uint16_t page_length;
		uint8_t param[];
	} __attribute__((packed)) *err = b;
	struct scsi_err_counter_param {
		uint16_t	code;
		uint8_t		format:2,
				tmc:2,
				etc:1,
				tsd:1,
				:1,
				du:1;
		uint8_t		length;
		uint8_t		counter[];
	} __attribute__((packed)) *param = NULL;
	uint32_t a, p, page_length;

	a = sm->count;

	p = 0;
	page_length = be16toh(err->page_length);

	while (p < page_length) {
		param = (struct scsi_err_counter_param *) (err->param + p);

		sm->attr[a].page = err->page_code;
		sm->attr[a].id = be16toh(param->code);
		sm->attr[a].bytes = param->length;
		sm->attr[a].flags = 0;
		sm->attr[a].raw = param->counter;
		sm->attr[a].thresh = NULL;

		p += 4 + param->length;

		a++;
	}
	
	sm->count = a;
}

static void
__smart_map_scsi_last_err(smart_map_t *sm, void *b, size_t bsize)
{
	struct scsi_last_n_error_event_page {
		uint8_t page_code:6,
			spf:1,
			ds:1;
		uint8_t	subpage_code;
		uint16_t page_length;
		uint8_t event[];
	} __attribute__((packed)) *lastn = b;
	struct scsi_last_n_error_event {
		uint16_t	code;
		uint8_t		format:2,
				tmc:2,
				etc:1,
				tsd:1,
				:1,
				du:1;
		uint8_t		length;
		uint8_t		data[];
	} __attribute__((packed)) *event = NULL;
	uint32_t a, p, page_length;

	a = sm->count;

	p = 0;
	page_length = be16toh(lastn->page_length);

	while (p < page_length) {
		event = (struct scsi_last_n_error_event *) (lastn->event + p);

		sm->attr[a].page = lastn->page_code;
		sm->attr[a].id = be16toh(event->code);
		sm->attr[a].bytes = event->length;
		sm->attr[a].flags = 0;
		sm->attr[a].raw = event->data;
		sm->attr[a].thresh = NULL;

		p += 4 + event->length;

		a++;
	}
	
	sm->count = a;
}

static void
__smart_map_scsi_temp(smart_map_t *sm, void *b, size_t bsize)
{
	struct scsi_temperature_log_page {
		uint8_t page_code;
		uint8_t subpage_code;
		uint16_t page_length;
		struct {
			uint16_t code;
			uint8_t control;
			uint8_t length;
			uint8_t	rsvd;
			uint8_t temperature;
		} param[];
	} __attribute__((packed)) *temp = b;
	uint32_t a, p, count;

	count = be16toh(temp->page_length);

	a = sm->count;

	for (p = 0; p < count; p++) {
		switch (be16toh(temp->param[p].code)) {
		case 0:
		case 1:
			sm->attr[a].page = temp->page_code;
			sm->attr[a].id = be16toh(temp->param[p].code);
			sm->attr[a].bytes = 1;
			sm->attr[a].flags = 0;
			sm->attr[a].raw = &(temp->param[p].temperature);
			sm->attr[a].thresh = NULL;
			a++;
			break;
		default:
			break;
		}
	}

	sm->count = a;
}

static void
__smart_map_scsi_start_stop(smart_map_t *sm, void *b, size_t bsize)
{
	struct scsi_start_stop_page {
		uint8_t page_code;
#define START_STOP_CODE_DATE_MFG	0x0001
#define START_STOP_CODE_DATE_ACCTN	0x0002
#define START_STOP_CODE_CYCLES_LIFE	0x0003
#define START_STOP_CODE_CYCLES_ACCUM	0x0004
#define START_STOP_CODE_LOAD_LIFE	0x0005
#define START_STOP_CODE_LOAD_ACCUM	0x0006
		uint8_t subpage_code;
		uint16_t page_length;
		uint8_t param[];
	} __attribute__((packed)) *sstop = b;
	struct scsi_start_stop_param {
		uint16_t code;
		uint8_t	format:2,
			tmc:2,
			etc:1,
			tsd:1,
			:1,
			du:1;
		uint8_t length;
		uint8_t data[];
	} __attribute__((packed)) *param;
	uint32_t a, p, page_length;

	a = sm->count;

	p = 0;
	page_length = be16toh(sstop->page_length);

	while (p < page_length) {
		param = (struct scsi_start_stop_param *) (sstop->param + p);

		sm->attr[a].page = sstop->page_code;
		sm->attr[a].id = be16toh(param->code);

		switch (sm->attr[a].id) {
		case START_STOP_CODE_DATE_MFG:
		case START_STOP_CODE_DATE_ACCTN:
			sm->attr[a].bytes = 6;
			sm->attr[a].flags = SMART_ATTR_F_STR;
			break;
		case START_STOP_CODE_CYCLES_LIFE:
		case START_STOP_CODE_CYCLES_ACCUM:
		case START_STOP_CODE_LOAD_LIFE:
		case START_STOP_CODE_LOAD_ACCUM:
			sm->attr[a].bytes = 4;
			sm->attr[a].flags = SMART_ATTR_F_BE;
		}

		sm->attr[a].raw = param->data;
		sm->attr[a].thresh = NULL;

		p += 4 + param->length;

		a++;
	}

	sm->count = a;
}

/*
 * Create a map based on the page list
 */
static void
__smart_map_scsi(smart_h h, smart_buf_t *sb, smart_map_t *sm)
{
	smart_t *s = h;
	smart_page_list_t *pg_list = NULL;
	uint8_t *b = NULL;
	uint32_t p;

	pg_list = s->pg_list;
	b = sb->b;

	sm->count = 0;

	for (p = 0; p < pg_list->pg_count; p++) {
		switch (pg_list->pages[p].id) {
		case PAGE_ID_SCSI_WRITE_ERR:
		case PAGE_ID_SCSI_READ_ERR:
		case PAGE_ID_SCSI_VERIFY_ERR:
		case PAGE_ID_SCSI_NON_MEDIUM_ERR:
			__smart_map_scsi_err_page(sm, b, pg_list->pages[p].bytes);
			break;
		case PAGE_ID_SCSI_LAST_N_ERR:
			__smart_map_scsi_last_err(sm, b, pg_list->pages[p].bytes);
			break;
		case PAGE_ID_SCSI_TEMPERATURE:
			__smart_map_scsi_temp(sm, b, pg_list->pages[p].bytes);
			break;
		case PAGE_ID_SCSI_START_STOP_CYCLE:
			__smart_map_scsi_start_stop(sm, b, pg_list->pages[p].bytes);
			break;
		}

		b += pg_list->pages[p].bytes;
	}
}

/**
 * Create a map of SMART values
 */
static void
__smart_attribute_map(smart_h h, smart_buf_t *sb, smart_map_t *sm)
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
	case SMART_PROTO_SCSI:
		__smart_map_scsi(h, sb, sm);
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

	max = sb->attr_count;
	if (max == 0) {
		warnx("Attribute count is zero?!?");
		return NULL;
	}

	sm = malloc(sizeof(smart_map_t) + (max * sizeof(smart_attr_t)));
	if (sm) {
		sm->sb = sb;

		/* count starts as the max but is adjusted to reflect the actual number */
		sm->count = max;

		__smart_attribute_map(h, sb, sm);
	}

	return sm;
}

typedef struct {
	uint8_t	page_code;
	uint8_t	subpage_code;
	uint16_t page_length;
	uint8_t supported_pages[];
} __attribute__((packed)) scsi_supported_log_pages;

static smart_page_list_t *
__smart_page_list_scsi(smart_t *s)
{
	smart_page_list_t *pg_list = NULL;
	scsi_supported_log_pages *b = NULL;
	uint32_t bsize = 68;	/* 4 byte header + 63 entries + 1 just cuz */
	int32_t rc;

	b = malloc(bsize);
	if (!b) {
		return NULL;
	}

	/* Supported Pages page ID is 0 */
	rc = device_read_log(s, PAGE_ID_SCSI_SUPPORTED_PAGES, (uint8_t *)b,
			bsize);
	if (rc < 0) {
		fprintf(stderr, "Read Supported Log Pages failed\n");
	} else {
		uint8_t *supported_page = b->supported_pages;
		uint32_t n_supported = be16toh(b->page_length);
		uint32_t s, p, pmax = pg_list_scsi.pg_count;

		/* Build a page list using only pages the device supports */
		pg_list = malloc(sizeof(pg_list_scsi));
		if (pg_list == NULL) {
			n_supported = 0;
		} else {
			pg_list->pg_count = 0;
		}

		/*
		 * Loop through all supported pages looking for those related
		 * to SMART. The below assumes the supported page list from the
		 * device and in pg_lsit_scsi are sorted in increasing order.
		 */
		for (s = 0, p = 0; (s < n_supported) && (p < pmax); s++) {
			while ((supported_page[s] > pg_list_scsi.pages[p].id) &&
					(p < pmax)) {
				p++;
			}

			if (supported_page[s] == pg_list_scsi.pages[p].id) {
				pg_list->pages[pg_list->pg_count] = pg_list_scsi.pages[p];
				pg_list->pg_count++;
				p++;
			}
		}
	}

	free(b);

	return pg_list;
}

static smart_page_list_t *
__smart_page_list(smart_h h)
{
	smart_t *s = h;
	smart_page_list_t *pg_list = NULL;

	if (!s) {
		return NULL;
	}

	switch (s->protocol) {
	case SMART_PROTO_ATA:
		pg_list = &pg_list_ata;
		break;
	case SMART_PROTO_NVME:
		pg_list = &pg_list_nvme;
		break;
	case SMART_PROTO_SCSI:
		pg_list = __smart_page_list_scsi(s);
		break;
	default:
		pg_list = NULL;
	}

	return pg_list;
}

static int32_t
__smart_read_pages(smart_h h, smart_buf_t *sb)
{
	smart_t *s = h;
	smart_page_list_t *plist = NULL;
	uint8_t *buf = NULL;
	int32_t rc = 0;
	uint32_t p = 0;

	plist = s->pg_list;

	buf = sb->b;

	for (p = 0; p < s->pg_list->pg_count; p++) {
		bzero(buf, plist->pages[p].bytes);
		rc = device_read_log(h, plist->pages[p].id, buf, plist->pages[p].bytes);
		if (rc) {
			dprintf("bad read (%d) from page %#x\n", rc, plist->pages[p].id);
			break; 
		}

		buf += plist->pages[p].bytes;
	}

	return rc;
}
