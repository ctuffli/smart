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
#ifndef _LIBSMART_H
#define _LIBSMART_H

#include <inttypes.h>
#include <stdbool.h>

typedef void * smart_h;

typedef enum {
	SMART_PROTO_AUTO,
	SMART_PROTO_ATA,
	SMART_PROTO_SCSI,
	SMART_PROTO_NVME,
	SMART_PROTO_MAX
} smart_protocol_e;

typedef struct {
	smart_protocol_e protocol;
	void *b;		// buffer of raw data
	size_t bsize;		// buffer size
	uint32_t attr_count;	// number of SMART attributes
} smart_buf_t;

struct smart_map_s;

typedef struct smart_attr_s {
	uint32_t page;
	uint32_t id;
	uint32_t bytes;
	uint32_t flags;
#define SMART_ATTR_F_BE		0x00000001	/* Attribute is big-endian */
#define SMART_ATTR_F_STR	0x00000002	/* Attribute is a string */
	void *raw;
	struct smart_map_s *thresh;		/* Threshold values (if any) */
} smart_attr_t;

typedef struct smart_map_s {
	smart_buf_t *sb;
	uint32_t count;				/* Number of attributes */
	smart_attr_t attr[];			/* Array of attributes */
} smart_map_t;

smart_h smart_open(smart_protocol_e p, char *devname);
void smart_close(smart_h);
bool smart_supported(smart_h);
smart_map_t *smart_read(smart_h);
void smart_free(smart_map_t *);
void smart_print(smart_h, smart_map_t *, int32_t, uint32_t);
void smart_print_device_info(smart_h);

#endif
