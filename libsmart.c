/*
 * Copyright (c) 2016 Chuck Tuffli <chuck@tuffli.net>
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

smart_buf_t *
smart_read(smart_h h)
{
	smart_buf_t *sb = NULL;

	sb = malloc(sizeof(smart_buf_t));
	if (sb) {
		sb->bsize = 512;
		sb->b = malloc(sb->bsize);
		if (sb->b == NULL) {
			free(sb);
			sb = NULL;
		} else {
			device_read(h, sb->b, sb->bsize);

			sb->vcount = 30;
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

	for (i = 0; i < sb->vcount; i++) {
		if (*b != 0) {
			uint64_t raw = 0UL;

			if ((which == -1) || (*b == which)) {
				raw =  (uint64_t)b[10] << 40 |
					 (uint64_t)b[9] << 32 |
					b[8] << 24 |
					b[7] << 16 |
					b[6] << 8 |
					b[5];

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

