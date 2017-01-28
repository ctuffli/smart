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

#include "libsmart.h"
#include "libsmart_priv.h"

extern smart_h device_open(smart_protocol_e, char *);
extern void device_close(smart_h);
extern int32_t device_read(smart_h, void *, size_t);

static uint32_t __smart_attribute_count(smart_buf_t *sb);
static uint32_t __smart_buffer_size(smart_buf_t *sb);

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

smart_buf_t *
smart_read(smart_h h)
{
	smart_t *s = h;
	smart_buf_t *sb = NULL;

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
			device_read(h, sb->b, sb->bsize);

			sb->attr_count = __smart_attribute_count(sb);
		}
	}
	
	return sb;
}

void
smart_free(smart_buf_t *sb)
{
	if (sb == NULL)
		return;

	if (sb->b != NULL) {
		free(sb->b);
		sb->b = NULL;
	}

	free(sb);
}

/*
 * XXX TODO this is ATA specific
 */
#define ID_HEX		"%#01.1x "
#define ID_DEC		"%d "

#define THRESH_HEX	"%#01.1x %#01.1x %#01.1x %#01.1x "
#define	THRESH_DEC	"%d %d %d %d "

#define RAW_HEX		"%#01.1lx\n"
#define RAW_DEC		"%ld\n"

void
smart_print(smart_h h, smart_buf_t *sb, int32_t which, uint32_t flags)
{
	uint32_t i;
	uint8_t *b = NULL;
	const char *fmt, *lfmt;
	bool do_hex = false;
	bool do_thresh = false;

	if (flags & 0x1)
		do_hex = true;

	if (flags & 0x2)
		do_thresh = true;

	b = sb->b;

	b += 2;

	for (i = 0; i < sb->attr_count; i++) {
		if (*b != 0) {
			uint64_t raw = 0UL;

			if ((which == -1) || (*b == which)) {
				raw = (b[10] << 8) | b[9];
				raw <<= 16;
				raw |= (b[8] << 8) | b[7];
				raw <<= 16;
				raw |= (b[6] << 8) | b[5];

				if (which == -1)
					printf(do_hex ? ID_HEX : ID_DEC, b[0]);

				if (do_thresh)
					printf(do_hex ? THRESH_HEX : THRESH_DEC,
							b[1], b[2], b[3], b[4]);

				printf(do_hex ? RAW_HEX : RAW_DEC, raw);

				if (which != -1)
					break;
			}
		}

		b += 12;
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
__smart_attr_count_ata(smart_buf_t *sb)
{
	uint8_t *buf = sb->b;
	uint32_t i;
	uint32_t count = 0;

	for (i = 2; i < sb->bsize; i += 12) {
		if (buf[i] != 0) {
			count++;
		}
	}

	return count;
}

static uint32_t
__smart_attribute_count(smart_buf_t *sb)
{
	uint32_t count = 0;

	if (sb != NULL) {
		switch (sb->protocol) {
		case SMART_PROTO_ATA:
			count = __smart_attr_count_ata(sb);
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
		default:
			size = 0;
		}
	}

	return size;
}
